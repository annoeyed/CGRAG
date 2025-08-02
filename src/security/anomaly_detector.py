# src/security/anomaly_detector.py
import pandas as pd
import numpy as np
from datetime import datetime
from typing import List, Dict, Tuple
from sentence_transformers import SentenceTransformer

class NetworkAnomalyDetector:
    def __init__(self, qdrant_manager):
        self.qdrant = qdrant_manager
        self.encoder = SentenceTransformer("all-MiniLM-L6-v2")
        
    def preprocess_network_log(self, log_entry: Dict) -> str:
        """Convert network log to text"""
        # Convert key network features to text
        features = [
            f"src_ip_{log_entry.get('src_ip', 'unknown')}",
            f"dst_ip_{log_entry.get('dst_ip', 'unknown')}",
            f"port_{log_entry.get('dst_port', 'unknown')}",
            f"protocol_{log_entry.get('protocol', 'unknown')}",
            f"bytes_{log_entry.get('bytes', 0)}",
            f"packets_{log_entry.get('packets', 0)}"
        ]
        return " ".join(features)
    
    def train_normal_behavior(self, normal_logs: List[Dict]):
        """Train normal network behavior patterns"""
        processed_data = []
        
        for i, log in enumerate(normal_logs):
            text_features = self.preprocess_network_log(log)
            embedding = self.encoder.encode(text_features).tolist()
            
            processed_data.append({
                "content": text_features,
                "embedding": embedding,
                "threat_level": "normal",
                "source": "baseline_traffic",
                "category": "network_pattern",
                "timestamp": log.get("timestamp", "")
            })
        
        # Save normal patterns to Qdrant
        self.qdrant.add_security_data("network_patterns", processed_data)
        print(f"{len(processed_data)} normal network patterns trained")
    
    def detect_anomaly(self, new_log: Dict, threshold: float = 0.7) -> Dict:
        """Detect anomalies in new logs"""
        # Convert new log to vector
        text_features = self.preprocess_network_log(new_log)
        embedding = self.encoder.encode(text_features).tolist()
        
        # Search for similar normal patterns
        results = self.qdrant.security_search(
            query_vector=embedding,
            collection_type="network_patterns",
            threat_level_filter="normal",
            limit=5
        )
        
        anomaly_result = {
            "timestamp": new_log.get("timestamp", datetime.now().isoformat()),
            "is_anomaly": False,
            "anomaly_score": 0.0,
            "confidence": 0.0,
            "details": text_features,
            "alert_level": "info"
        }
        
        if results:
            # Highest similarity score
            max_similarity = max([result.score for result in results])
            anomaly_score = 1.0 - max_similarity  # Lower similarity means higher anomaly
            
            anomaly_result["anomaly_score"] = anomaly_score
            anomaly_result["confidence"] = anomaly_score
            
            if anomaly_score >= threshold:
                anomaly_result["is_anomaly"] = True
                anomaly_result["alert_level"] = "high" if anomaly_score >= 0.9 else "medium"
                
                # Detailed analysis
                suspicious_features = self._analyze_suspicious_features(new_log)
                anomaly_result["suspicious_features"] = suspicious_features
        
        return anomaly_result
    
    def _analyze_suspicious_features(self, log: Dict) -> List[str]:
        """Analyze suspicious features"""
        suspicious = []
        
        # Check for common suspicious patterns
        if log.get("dst_port") in [22, 23, 3389, 5900]:  # SSH, Telnet, RDP, VNC
            suspicious.append("Remote access port used")
        
        if log.get("bytes", 0) > 10000000:  # Over 10MB
            suspicious.append("Large data transfer")
        
        if log.get("packets", 0) > 10000:
            suspicious.append("Excessive packet count")
        
        return suspicious
