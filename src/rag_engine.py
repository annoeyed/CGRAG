# src/rag_engine.py
from typing import Dict, List, Any
import json

class CyberSecurityRAG:
    def __init__(self, qdrant_manager):
        self.qdrant = qdrant_manager
        self.malware_detector = MalwareDetector(qdrant_manager)
        self.anomaly_detector = NetworkAnomalyDetector(qdrant_manager)
        
    def analyze_security_query(self, query: str, query_type: str = "general") -> Dict:
        """보안 쿼리 종합 분석"""
        # 쿼리를 벡터로 변환
        from sentence_transformers import SentenceTransformer
        encoder = SentenceTransformer("all-MiniLM-L6-v2")
        query_vector = encoder.encode(query).tolist()
        
        # 쿼리 타입에 따른 분석
        if query_type == "malware":
            return self._analyze_malware_query(query_vector, query)
        elif query_type == "network":
            return self._analyze_network_query(query_vector, query)
        else:
            return self._analyze_general_security_query(query_vector, query)
    
    def _analyze_malware_query(self, query_vector: List[float], query: str) -> Dict:
        """악성코드 관련 쿼리 분석"""
        results = self.qdrant.security_search(
            query_vector=query_vector,
            collection_type="malware_signatures",
            limit=5
        )
        
        analysis = {
            "query": query,
            "type": "malware_analysis",
            "findings": [],
            "recommendations": []
        }
        
        for result in results:
            finding = {
                "relevance": result.score,
                "threat_level": result.payload.get("threat_level", "unknown"),
                "description": result.payload.get("content", "")[:200] + "...",
                "source": result.payload.get("source", "unknown")
            }
            analysis["findings"].append(finding)
        
        # 추천사항 생성
        if results:
            analysis["recommendations"] = self._generate_malware_recommendations(results)
        
        return analysis
    
    def _analyze_general_security_query(self, query_vector: List[float], query: str) -> Dict:
        """일반 보안 쿼리 분석"""
        # 모든 컬렉션에서 검색
        all_results = []
        
        for collection_type in ["malware_signatures", "network_patterns", "threat_intel"]:
            try:
                results = self.qdrant.security_search(
                    query_vector=query_vector,
                    collection_type=collection_type,
                    limit=3
                )
                for result in results:
                    result.collection_type = collection_type
                    all_results.append(result)
            except:
                continue
        
        # 관련도 순으로 정렬
        all_results.sort(key=lambda x: x.score, reverse=True)
        
        analysis = {
            "query": query,
            "type": "comprehensive_analysis",
            "total_findings": len(all_results),
            "findings": []
        }
        
        for result in all_results[:10]:  # 상위 10개만
            finding = {
                "relevance": result.score,
                "category": result.collection_type,
                "threat_level": result.payload.get("threat_level", "unknown"),
                "summary": result.payload.get("content", "")[:150] + "..."
            }
            analysis["findings"].append(finding)
        
        return analysis
    
    def _generate_malware_recommendations(self, results) -> List[str]:
        """악성코드 분석 결과 기반 추천사항 생성"""
        recommendations = []
        
        high_threat_count = sum(1 for r in results if r.payload.get("threat_level") == "high")
        
        if high_threat_count > 0:
            recommendations.append("고위험 악성코드 탐지: 즉시 격리 조치 필요")
            recommendations.append("안티바이러스 정의 파일 업데이트 확인")
            recommendations.append("네트워크 접근 차단 및 시스템 스캔 실행")
        
        recommendations.append("주기적인 보안 패치 적용")
        recommendations.append("사용자 보안 교육 강화")
        
        return recommendations
