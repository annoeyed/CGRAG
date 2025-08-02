from qdrant_client import QdrantClient, models
from qdrant_client.models import Distance, VectorParams

client = QdrantClient("localhost", port=6333)

def make(name, dim=384):
    if client.collection_exists(name):
        return
    client.create_collection(
        collection_name=name,
        vectors_config=VectorParams(size=dim,
                                    distance=Distance.COSINE,
                                    on_disk=True)   # 디스크 저장
    )

for col in ("malware_signatures", "network_patterns", "threat_intel"):
    make(col)

print("all collections ready")
