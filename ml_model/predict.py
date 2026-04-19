import os
import joblib
from typing import Dict, Any, List, Tuple

class SequenceMalwarePredictor:
    """
    Machine Learning Predictor for Dynamic API Sequences.
    Loads the trained Random Forest and TF-IDF vectorizer.
    """
    def __init__(self, model_dir: str = None):
        if model_dir is None:
            model_dir = os.path.dirname(os.path.abspath(__file__))
            
        model_path = os.path.join(model_dir, "random_forest_model.pkl")
        vectorizer_path = os.path.join(model_dir, "api_vectorizer.pkl")
        
        print("Initializing SequenceMalwarePredictor Model...")
        try:
            self.model = joblib.load(model_path)
            self.vectorizer = joblib.load(vectorizer_path)
            
            # Map feature importances to feature names for XAI
            self.feature_names = self.vectorizer.get_feature_names_out()
            self.importances = self.model.feature_importances_
            print("Successfully loaded Random Forest model and Vectorizer.")
        except Exception as e:
            print(f"Warning: Could not load models. Did you run the Jupyter Notebook? Error: {e}")
            self.model = None

    def predict(self, extracted_features: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]], bool]:
        """
        Runs inference on the API sequences.
        Returns:
            - probability: float (0.0 to 1.0)
            - decision_flow: list of dictionaries for XAI (which APIs triggered it)
            - is_polymorphic: boolean indicating if dynamic evasion was strongly detected
        """
        sequences = extracted_features.get("api_sequences", [])
        
        if not sequences or self.model is None:
            return 0.05, [{"api": "No APIs recorded", "importance": 0.0, "reason": "No dynamic behavior extracted."}], False
            
        # Flatten all sequences into a single list of API calls
        flat_apis = []
        for seq in sequences:
            flat_apis.extend(seq.get("sequence", []))
            
        # Join into a single space-separated string for TF-IDF
        sequence_str = " ".join(flat_apis)
        
        # Vectorize
        X = self.vectorizer.transform([sequence_str])
        
        # Predict probability of Malware (Class 1)
        prob = float(self.model.predict_proba(X)[0][1])
            
        # Generate XAI: Find which features in this instance had the highest global importance
        # X is a sparse matrix. We get the non-zero feature indices for this sample.
        active_features = X.nonzero()[1]
        
        API_MEANINGS = {
            "WriteProcessMemory": "Injects compiled code into another process's memory space.",
            "VirtualAllocEx": "Allocates memory blocks in a remote process, typical of process hollowing.",
            "CreateRemoteThread": "Executes injected code threads inside another process.",
            "SetWindowsHookEx": "Installs a system-wide hook, often used for stealth keylogging.",
            "LdrLoadDll": "Loads a dynamic-link library (DLL) directly into process memory.",
            "RegSetValue": "Modifies the Windows Registry (common for establishing persistence).",
            "NtWriteFile": "Performs low-level disk writes, bypassing higher-level API monitoring.",
            "InternetOpen": "Establishes an outbound HTTP connection (Command & Control communication).",
            "URLDownloadToFile": "Pulls a malicious payload down from an external remote server.",
            "GetProcAddress": "Resolves function memory addresses dynamically to evade static analysis.",
            "IsDebuggerPresent": "Probes the environment to see if it's being analyzed locally (Anti-Analysis)."
        }

        decision_flow = []
        for idx in active_features:
            feat_name = self.feature_names[idx]
            imp = float(self.importances[idx])
            if imp > 0:
                reason_text = "Statistically significant API sequence anomaly detected."
                for api, desc in API_MEANINGS.items():
                    if api.lower() in feat_name.lower():
                        reason_text = desc
                        break
                        
                decision_flow.append({
                    "api": feat_name,
                    "importance": round(imp * 100, 2), # Scale up for readability
                    "reason": reason_text
                })
                
        # Sort explainability payload by most important
        decision_flow = sorted(decision_flow, key=lambda x: x["importance"], reverse=True)[:5]
        
        # If no important features triggered, add a generic low-risk reason
        if not decision_flow:
            decision_flow.append({"api": flat_apis[0] if flat_apis else "Unknown", "importance": 0.0, "reason": "Standard API call."})
        
        # Flag polymorphism if probability is very high (evasion features heavily matched)
        is_polymorphic = prob > 0.85
        
        return prob, decision_flow, is_polymorphic
