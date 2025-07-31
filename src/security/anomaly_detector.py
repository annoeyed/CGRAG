# src/security/anomaly_detector.py
import pandas as pd
import numpy as np
from datetime import datetime
from typing import List, Dict, Tuple

class NetworkAnomalyDetector:
    def __init__(self, qdrant_manager):
        self.qdrant = qdrant_manager
        self.encoder = SentenceTransformer("all-MiniLM-L6-v2")
        
    def preprocess_network_log(self, log_entry: Dict) -> str:
        """네트워크 로그를 텍스트로 변환"""
        # 주요 네트워크 특성을 텍스트로 변환
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
        """정상 네트워크 행위 패턴 학습"""
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
        
        # 정상 패턴을 Qdrant에 저장
        self.qdrant.add_security_data("network_patterns", processed_data)
        print(f"{len(processed_data)}개 정상 네트워크 패턴 학습 완료")
    
    def detect_anomaly(self, new_log: Dict, threshold: float = 0.7) -> Dict:
        """새로운 로그에서 이상 징후 탐지"""
        # 새 로그를 벡터로 변환
        text_features = self.preprocess_network_log(new_log)
        embedding = self.encoder.encode(text_features).tolist()
        
        # 정상 패턴과 유사도 검색
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
            # 가장 높은 유사도 점수
            max_similarity = max([result.score for result in results])
            anomaly_score = 1.0 - max_similarity  # 유사도가 낮을수록 이상 징후
            
            anomaly_result["anomaly_score"] = anomaly_score
            anomaly_result["confidence"] = anomaly_score
            
            if anomaly_score >= threshold:
                anomaly_result["is_anomaly"] = True
                anomaly_result["alert_level"] = "high" if anomaly_score >= 0.9 else "medium"
                
                # 상세 분석
                suspicious_features = self._analyze_suspicious_features(new_log)
                anomaly_result["suspicious_features"] = suspicious_features
        
        return anomaly_result
    
    def _analyze_suspicious_features(self, log: Dict) -> List[str]:
        """의심스러운 특성 분석"""
        suspicious = []
        
        # 일반적인 의심스러운 패턴 검사
        if log.get("dst_port") in [22, 23, 3389, 5900]:  # SSH, Telnet, RDP, VNC
            suspicious.append("원격 접속 포트 사용")
        
        if log.get("bytes", 0) > 10000000:  # 10MB 이상
            suspicious.append("대용량 데이터 전송")
        
        if log.get("packets", 0) > 10000:
            suspicious.append("과도한 패킷 수")
        
        return suspicious
