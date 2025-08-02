from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient

# 모델과 클라이언트 초기화
enc = SentenceTransformer("all-MiniLM-L6-v2")
cli = QdrantClient("localhost", port=6333)

# 다양한 보안 질의들
queries = [
    "SQL injection vulnerability in login forms",
    "remote code execution in Apache servers",
    "privilege escalation in Linux kernels",
    "XSS attack in browser-based apps"
]

# 각 질의에 대해 검색 수행
for query in queries:
    print(f"\n Query: {query}")
    qvec = enc.encode(query).tolist()
    hits = cli.query_points(
    collection_name="threat_intel",
    vector=qvec,
    limit=5
    )
    for h in hits:
        print(f"→ {h.payload['cve_id']} - {h.payload.get('description')}")
