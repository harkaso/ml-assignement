# ml-assignment — Initialisation du projet

## Prérequis

- Python 3.11+ (recommandé)
- Un IDE au choix : **VS Code** (extensions **Python** + **Jupyter**) ou **PyCharm**

> Note Scapy : sur Windows, l’analyse de fichiers CSV fonctionne sans driver, mais le sniff en temps réel nécessite **`Npcap`**.

## 1) Créer et activer l’environnement virtuel

Dans un terminal PowerShell à la racine du projet :

```powershell
cd ".\<path-to-project>\ml-assignement"
python -m venv .venv
.\.venv\Scripts\Activate
python -m pip install --upgrade pip
```

## 2) Installer les dépendances

```powershell
python -m pip install -r requirements.txt
```

## 3) Utiliser le projet dans VS Code

1. `Ctrl+Shift+P` → **Python: Select Interpreter** → choisir `.venv`
2. Ouvrir `Intrusion_Detection.ipynb`
3. En haut à droite du notebook → **Select Kernel** → choisir le kernel lié à `.venv`
4. Exécuter les cellules (ou **Run All**)

## 4) Utiliser le projet dans PyCharm

1. **Open** → ouvrir le dossier `ml-assignement`
2. **Settings** → **Project: Python Interpreter** → ⚙ → **Add...** → **Virtualenv** → Existing → sélectionner `.venv\\Scripts\\python.exe`
3. Installer les dépendances (au choix) :

   - Via le terminal PyCharm :

    ```powershell
    python -m pip install -r requirements.txt
    ```

   - Ou via l’UI : ouvrir `requirements.txt` → bouton **Install**

4. Ouvrir `Intrusion_Detection.ipynb` et exécuter les cellules.

> Si PyCharm ne propose pas l’exécution notebook : vérifie que le plugin **Jupyter** est activé (Settings → Plugins) ou utilise VS Code pour les notebooks.

Les données sont dans `datasets/`.

### Sniff en temps réel sur Windows (Scapy)

- Installer **Npcap** (mode WinPcap compatible recommandé)
- Redémarrer VS Code et le kernel Jupyter après installation
