import torch
import numpy as np
from sklearn.preprocessing import StandardScaler
from scapy.all import sniff, IP, TCP, UDP
import pickle
import json
from datetime import datetime
from collections import deque
import warnings
warnings.filterwarnings('ignore')

class RealTimeIDS:
    """Real-Time Intrusion Detection System"""
    
    def __init__(self, model_path, scaler_path, label_encoder_path):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Load model
        self.model = torch.load(model_path, map_location=self.device)
        self.model.eval()
        
        # Load scaler
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        # Load label encoder
        with open(label_encoder_path, 'rb') as f:
            self.label_encoder = pickle.load(f)
        
        # Buffer for aggregating features
        self.feature_buffer = deque(maxlen=100)
        self.alerts = []
        self.prediction_threshold = 0.7
        
        print(f"IDS loaded successfully on {self.device}")
        print(f"Classes: {self.label_encoder.classes_}")
    
    def extract_features(self, packet, flow_stats):
        """Extract numerical features from packet"""
        features = {}
        
        try:
            if IP in packet:
                ip_layer = packet[IP]
                
                # Basic IP features
                features['ttl'] = ip_layer.ttl
                features['packet_length'] = len(packet)
                
                # Flow-based features
                flow_id = (ip_layer.src, ip_layer.dst)
                if flow_id in flow_stats:
                    stats = flow_stats[flow_id]
                    features['flow_packet_count'] = stats['packet_count']
                    features['flow_byte_count'] = stats['byte_count']
                    features['flow_duration'] = stats['duration']
                
                # Protocol-specific features
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    features['src_port'] = tcp_layer.sport
                    features['dst_port'] = tcp_layer.dport
                    features['tcp_flags'] = tcp_layer.flags
                    features['window_size'] = tcp_layer.window
                    
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    features['src_port'] = udp_layer.sport
                    features['dst_port'] = udp_layer.dport
                    features['udp_length'] = udp_layer.len
                
        except Exception as e:
            print(f"Feature extraction error: {e}")
        
        return features
    
    def predict_packet(self, features):
        """Predict if packet is normal or anomaly"""
        try:
            # Convert to numpy array
            feature_array = np.array(list(features.values())).reshape(1, -1)
            
            # Scale
            feature_scaled = self.scaler.transform(feature_array)
            
            # Convert to tensor
            feature_tensor = torch.FloatTensor(feature_scaled).to(self.device)
            
            # Predict
            with torch.no_grad():
                output = self.model(feature_tensor)
                probabilities = torch.softmax(output, dim=1)
                prediction = torch.argmax(probabilities, dim=1).item()
                confidence = probabilities[0, prediction].item()
            
            predicted_class = self.label_encoder.inverse_transform([prediction])[0]
            
            return {
                'class': predicted_class,
                'confidence': confidence,
                'is_attack': predicted_class != 'BENIGN',
                'probabilities': probabilities[0].cpu().numpy()
            }
            
        except Exception as e:
            print(f"Prediction error: {e}")
            return None
    
    def packet_callback(self, packet):
        """Callback for packet processing"""
        try:
            if IP in packet:
                # Extract features
                features = self.extract_features(packet, {})
                
                if features:
                    # Make prediction
                    prediction = self.predict_packet(features)
                    
                    if prediction:
                        # Log alert if attack detected
                        if prediction['is_attack'] and prediction['confidence'] > self.prediction_threshold:
                            alert = {
                                'timestamp': datetime.now().isoformat(),
                                'predicted_class': prediction['class'],
                                'confidence': prediction['confidence'],
                                'packet_info': {
                                    'src': packet[IP].src if IP in packet else None,
                                    'dst': packet[IP].dst if IP in packet else None,
                                    'length': len(packet)
                                }
                            }
                            self.alerts.append(alert)
                            
                            print(f"\n⚠️  ALERT: {prediction['class']} detected!")
                            print(f"   Confidence: {prediction['confidence']:.4f}")
                            print(f"   {alert['packet_info']}")
                        
                        self.feature_buffer.append(prediction)
                        
        except Exception as e:
            print(f"Packet callback error: {e}")
    
    def start_monitoring(self, interface=None, packet_count=0):
        """Start real-time monitoring"""
        print("\n===== Real-Time IDS Started =====")
        print(f"Monitoring on interface: {interface}")
        
        sniff(
            iface=interface,
            prn=self.packet_callback,
            store=False,
            count=packet_count if packet_count > 0 else 0
        )
    
    def get_statistics(self):
        """Get monitoring statistics"""
        if not self.alerts:
            return {
                'total_packets_monitored': len(self.feature_buffer),
                'attacks_detected': 0,
                'alert_rate': 0.0
            }
        
        return {
            'total_packets_monitored': len(self.feature_buffer),
            'attacks_detected': len(self.alerts),
            'alert_rate': len(self.alerts) / max(len(self.feature_buffer), 1),
            'recent_alerts': self.alerts[-10:]  # Last 10 alerts
        }

# Usage example
if __name__ == "__main__":
    # Initialize IDS
    ids = RealTimeIDS(
        model_path='best_ids_model.pt',
        scaler_path='scaler.pkl',
        label_encoder_path='label_encoder.pkl'
    )
    
    # Start monitoring
    try:
        ids.start_monitoring(packet_count=1000)
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped")
        
    # Print statistics
    stats = ids.get_statistics()
    print("\n===== Monitoring Statistics =====")
    print(json.dumps(stats, indent=2, default=str))
