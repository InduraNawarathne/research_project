import json
import os
from typing import Dict, Any, List, Optional

class ReportFeatureExtractor:
    """
    Parses CAPEv2 report.json dictionaries to extract relevant features 
    for Machine Learning and Streamlit visualizations.
    Focuses primarily on Dynamic API call sequences to detect polymorphism.
    """
    
    @staticmethod
    def extract_api_sequences(report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extracts the chronological sequence of API calls for each process.
        Returns a list of dicts: [{'pid': int, 'process_name': str, 'calls': [str, str, ...]}]
        """
        sequences = []
        behavior = report.get("behavior", {})
        processes = behavior.get("processes", [])
        
        for proc in processes:
            pid = proc.get("process_id")
            name = proc.get("process_name")
            calls = proc.get("calls", [])
            
            api_sequence = [call.get("api") for call in calls if call.get("api")]
            
            if api_sequence:
                sequences.append({
                    "pid": pid,
                    "process_name": name,
                    "sequence": api_sequence
                })
                
        return sequences

    @staticmethod
    def extract_process_tree(report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extracts process tracking information (process hollowing, injection, children).
        Useful for the Process Tree visualization.
        """
        processes = []
        behavior = report.get("behavior", {})
        for proc in behavior.get("processes", []):
            processes.append({
                "pid": proc.get("process_id"),
                "ppid": proc.get("parent_id"),
                "name": proc.get("process_name"),
                "command_line": proc.get("command_line", ""),
                "time": proc.get("first_seen")
            })
        return processes

    @staticmethod
    def extract_network_indicators(report: Dict[str, Any]) -> Dict[str, List[Any]]:
        """
        Extracts interacted IPs, URLs, and Domains. 
        Useful for the interactive Map.
        """
        network = report.get("network", {})
        
        ips = []
        for tcp in network.get("tcp", []):
            if tcp.get("dst"):
                ips.append(tcp.get("dst"))
        for udp in network.get("udp", []):
            if udp.get("dst"):
                ips.append(udp.get("dst"))
                
        domains = [d.get("domain") for d in network.get("domains", []) if "domain" in d]
        http_reqs = [h.get("uri") for h in network.get("http", []) if "uri" in h]
        
        return {
            "ips": list(set(ips)),
            "domains": list(set(domains)),
            "urls": list(set(http_reqs))
        }

    @staticmethod
    def extract_malicious_score(report: Dict[str, Any]) -> float:
        """
        Gets CAPE's static/dynamic heuristically combined score.
        Useful for automatic labeling of data during collection.
        """
        return float(report.get("info", {}).get("score", 0.0))

    @staticmethod
    def extract_all_for_ml(report: Dict[str, Any], task_id: int) -> Dict[str, Any]:
        """
        Combines all extractions into a single ML-ready entry.
        """
        score = ReportFeatureExtractor.extract_malicious_score(report)
        return {
            "task_id": task_id,
            "hash": report.get("target", {}).get("file", {}).get("sha256", "unknown"),
            "score": score,
            "label": 1 if score >= 5.0 else 0, # Simple threshold labeling for dataset collection
            "api_sequences": ReportFeatureExtractor.extract_api_sequences(report),
            "network": ReportFeatureExtractor.extract_network_indicators(report),
            "process_tree": ReportFeatureExtractor.extract_process_tree(report)
        }
