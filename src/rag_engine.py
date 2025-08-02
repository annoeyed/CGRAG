# src/rag_engine.py
from typing import Dict, List, Any
import json
from sentence_transformers import SentenceTransformer
from src.security.malware_detector import MalwareDetector
from src.security.anomaly_detector import NetworkAnomalyDetector

class CyberSecurityRAG:
    def __init__(self, qdrant_manager):
        self.qdrant = qdrant_manager
        self.malware_detector = MalwareDetector(qdrant_manager)
        self.anomaly_detector = NetworkAnomalyDetector(qdrant_manager)
        self.encoder = SentenceTransformer("all-MiniLM-L6-v2")
        
    def analyze_security_query(self, query: str, query_type: str = "general") -> Dict:
        """Comprehensive analysis of security queries"""
        # Convert query to vector
        query_vector = self.encoder.encode(query).tolist()
        
        # Analysis based on query type
        if query_type == "malware":
            return self._analyze_malware_query(query_vector, query)
        elif query_type == "network":
            return self._analyze_network_query(query_vector, query)
        else:
            return self._analyze_general_security_query(query_vector, query)
    
    def _analyze_malware_query(self, query_vector: List[float], query: str) -> Dict:
        """Analyze malware-related queries"""
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
        
        # Generate recommendations
        if results:
            analysis["recommendations"] = self._generate_malware_recommendations(results)
        
        return analysis

    def _analyze_network_query(self, query_vector: List[float], query: str) -> Dict:
        """Analyze network-related queries"""
        results = self.qdrant.security_search(
            query_vector=query_vector,
            collection_type="network_patterns",
            limit=5
        )

        analysis = {
            "query": query,
            "type": "network_analysis",
            "findings": [],
            "recommendations": ["Review firewall rules", "Monitor network traffic for anomalies"]
        }

        for result in results:
            finding = {
                "relevance": result.score,
                "threat_level": result.payload.get("threat_level", "normal"),
                "description": result.payload.get("content", "")[:200] + "...",
                "source": result.payload.get("source", "unknown")
            }
            analysis["findings"].append(finding)
        
        return analysis
    
    def _analyze_general_security_query(self, query_vector: List[float], query: str) -> Dict:
        """Analyze general security queries"""
        # Search all collections
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
        
        # Sort by relevance
        all_results.sort(key=lambda x: x.score, reverse=True)
        
        analysis = {
            "query": query,
            "type": "comprehensive_analysis",
            "total_findings": len(all_results),
            "findings": []
        }
        
        for result in all_results[:10]:  # Top 10 only
            finding = {
                "relevance": result.score,
                "category": result.collection_type,
                "threat_level": result.payload.get("threat_level", "unknown"),
                "summary": result.payload.get("content", "")[:150] + "..."
            }
            analysis["findings"].append(finding)
        
        return analysis
    
    def _generate_malware_recommendations(self, results) -> List[str]:
        """Generate recommendations based on malware analysis results"""
        recommendations = []
        
        high_threat_count = sum(1 for r in results if r.payload.get("threat_level") == "high")
        
        if high_threat_count > 0:
            recommendations.append("High-risk malware detected: immediate quarantine required")
            recommendations.append("Check for antivirus definition file updates")
            recommendations.append("Block network access and run system scan")
        
        recommendations.append("Apply security patches regularly")
        recommendations.append("Enhance user security training")
        
        return recommendations
