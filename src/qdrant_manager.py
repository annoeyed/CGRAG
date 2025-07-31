# src/qdrant_manager.py
from qdrant_client import QdrantClient, models
from qdrant_client.models import Distance, VectorParams
import numpy as np
from typing import List, Dict, Any

class SecurityQdrantManager:
    def __init__(self, host="localhost", port=6333):
        self.client = QdrantClient(host=host, port=port)
        self.collections = {
            "malware_signatures": "malware_signatures",
            "network_patterns": "network_patterns", 
            "threat_intel": "threat_intel"
        }
        
    def setup_collections(self):
        """보안 분석용 컬렉션 생성"""
        for collection_name in self.collections.values():
            try:
                self.client.create_collection(
                    collection_name=collection_name,
                    vectors_config=VectorParams(
                        size=384,  # sentence-transformers 기본 크기
                        distance=Distance.COSINE,
                        on_disk=True  # 메모리 절약
                    )
                )
                print(f"✅ 컬렉션 생성: {collection_name}")
            except Exception as e:
                print(f"컬렉션 {collection_name} 이미 존재 또는 오류: {e}")
    
    def add_security_data(self, collection_type: str, data: List[Dict]):
        """보안 데이터 벡터화하여 저장"""
        collection_name = self.collections[collection_type]
        
        points = []
        for i, item in enumerate(data):
            points.append(models.PointStruct(
                id=i,
                vector=item["embedding"],
                payload={
                    "content": item["content"],
                    "threat_level": item.get("threat_level", "medium"),
                    "source": item.get("source", "unknown"),
                    "timestamp": item.get("timestamp", ""),
                    "category": item.get("category", "general")
                }
            ))
        
        self.client.upsert(
            collection_name=collection_name,
            points=points
        )
        print(f"{len(points)}개 보안 데이터 저장 완료: {collection_name}")
    
    def security_search(self, query_vector: List[float], 
                       collection_type: str, 
                       threat_level_filter: str = None,
                       limit: int = 5):
        """위협 수준 필터링과 함께 보안 검색"""
        collection_name = self.collections[collection_type]
        
        # 위협 수준 필터 적용
        search_filter = None
        if threat_level_filter:
            search_filter = models.Filter(
                must=[
                    models.FieldCondition(
                        key="threat_level",
                        match=models.MatchValue(value=threat_level_filter)
                    )
                ]
            )
        
        results = self.client.search(
            collection_name=collection_name,
            query_vector=query_vector,
            query_filter=search_filter,
            limit=limit,
            with_payload=True
        )
        
        return results
