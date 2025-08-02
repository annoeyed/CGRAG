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
        """Create collections for security analysis"""
        for collection_name in self.collections.values():
            try:
                self.client.create_collection(
                    collection_name=collection_name,
                    vectors_config=VectorParams(
                        size=384,  # default size for sentence-transformers
                        distance=Distance.COSINE,
                        on_disk=True  # save memory
                    )
                )
                print(f"✅ Collection created: {collection_name}")
            except Exception as e:
                print(f"Collection {collection_name} already exists or error: {e}")
    
    def add_security_data(self, collection_type: str, data: List[Dict]):
        """Vectorize and save security data"""
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
        print(f"{len(points)} security data points saved: {collection_name}")
    
    def security_search(self, query_vector: List[float], 
                       collection_type: str, 
                       threat_level_filter: str = None,
                       limit: int = 5):
        """Perform security search with threat level filtering"""
        collection_name = self.collections[collection_type]
        
        # Apply threat level filter
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
