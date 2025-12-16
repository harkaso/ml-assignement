from scapy.all import sniff, IP, TCP, UDP, ICMP
import numpy as np
import pandas as pd
from collections import defaultdict, deque
from datetime import datetime
import threading
import queue

class RealTimeFeatureExtractor:
    """Extract network features in real-time using Scapy"""
    
    def __init__(self, window_size=100):
        self.window_size = window_size
        self.packet_buffer = deque(maxlen=window_size)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'protocol_dist': defaultdict(int),
            'port_dist': defaultdict(int),
            'flag_dist': defaultdict(int),
            'timestamps': deque(maxlen=1000)
        })
        self.feature_queue = queue.Queue()
        
    def extract_packet_features(self, packet):
        """Extract features from a single packet"""
        features = {}
        
        try:
            if IP in packet:
                ip_layer = packet[IP]
                features['src_ip'] = ip_layer.src
                features['dst_ip'] = ip_layer.dst
                features['ttl'] = ip_layer.ttl
                features['protocol'] = ip_layer.proto
                features['packet_length'] = len(packet)
                
                # TCP features
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    features['src_port'] = tcp_layer.sport
                    features['dst_port'] = tcp_layer.dport
                    features['tcp_flags'] = tcp_layer.flags
                    features['window_size'] = tcp_layer.window
                    features['seq'] = tcp_layer.seq
                    features['ack'] = tcp_layer.ack
                    
                # UDP features
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    features['src_port'] = udp_layer.sport
                    features['dst_port'] = udp_layer.dport
                    features['udp_length'] = udp_layer.len
                    
                features['timestamp'] = datetime.now().timestamp()
                
        except Exception as e:
            print(f"Error extracting features: {e}")
            
        return features
    
    def update_flow_stats(self, packet):
        """Update flow statistics"""
        try:
            if IP in packet:
                ip_layer = packet[IP]
                flow_id = (ip_layer.src, ip_layer.dst)
                
                self.flow_stats[flow_id]['packet_count'] += 1
                self.flow_stats[flow_id]['byte_count'] += len(packet)
                self.flow_stats[flow_id]['protocol_dist'][ip_layer.proto] += 1
                self.flow_stats[flow_id]['timestamps'].append(datetime.now().timestamp())
                
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    self.flow_stats[flow_id]['port_dist'][tcp_layer.dport] += 1
                    self.flow_stats[flow_id]['flag_dist'][tcp_layer.flags] += 1
                    
        except Exception as e:
            print(f"Error updating flow stats: {e}")
    
    def compute_aggregate_features(self, flow_id):
        """Compute aggregate features for a flow"""
        stats = self.flow_stats[flow_id]
        agg_features = {}
        
        if stats['timestamps']:
            time_diffs = np.diff(list(stats['timestamps']))
            agg_features['inter_arrival_mean'] = np.mean(time_diffs) if len(time_diffs) > 0 else 0
            agg_features['inter_arrival_std'] = np.std(time_diffs) if len(time_diffs) > 0 else 0
        
        agg_features['packet_count'] = stats['packet_count']
        agg_features['byte_count'] = stats['byte_count']
        agg_features['bytes_per_packet'] = (stats['byte_count'] / stats['packet_count'] 
                                             if stats['packet_count'] > 0 else 0)
        
        # Protocol distribution
        total_protocols = sum(stats['protocol_dist'].values())
        agg_features['protocol_diversity'] = len(stats['protocol_dist'])
        
        # Port distribution
        total_ports = sum(stats['port_dist'].values())
        agg_features['port_diversity'] = len(stats['port_dist'])
        
        # Flag distribution (TCP)
        agg_features['tcp_flag_count'] = len(stats['flag_dist'])
        
        return agg_features
    
    def packet_callback(self, packet):
        """Callback for each packet captured"""
        self.packet_buffer.append(packet)
        self.update_flow_stats(packet)
        
        features = self.extract_packet_features(packet)
        if features:
            self.feature_queue.put(features)
    
    def start_sniffing(self, interface=None, packet_count=0, filter_expr=""):
        """Start packet sniffing"""
        print(f"Starting packet capture on interface: {interface}")
        print(f"Filter: {filter_expr if filter_expr else 'No filter'}")
        
        sniff(
            iface=interface,
            prn=self.packet_callback,
            store=False,
            count=packet_count if packet_count > 0 else 0,
            filter=filter_expr
        )
    
    def get_batch_features(self, batch_size=32):
        """Get batch of features"""
        batch = []
        try:
            for _ in range(batch_size):
                features = self.feature_queue.get(timeout=1)
                batch.append(features)
        except queue.Empty:
            pass
        return batch

# Exemple d'utilisation
if __name__ == "__main__":
    extractor = RealTimeFeatureExtractor(window_size=100)
    
    # Start sniffing in background
    sniff_thread = threading.Thread(
        target=extractor.start_sniffing,
        kwargs={'interface': None, 'filter_expr': 'tcp or udp'},
        daemon=True
    )
    sniff_thread.start()
    
    # Collect features
    try:
        for i in range(10):
            batch = extractor.get_batch_features(batch_size=5)
            if batch:
                df_batch = pd.DataFrame(batch)
                print(f"\nBatch {i+1}:")
                print(df_batch[['src_ip', 'dst_ip', 'packet_length']].head())
    except KeyboardInterrupt:
        print("Capture stopped")
