from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer

# 1. 임베딩 모델 불러오기
model = SentenceTransformer("all-MiniLM-L6-v2")  # dim=384

# 2. Qdrant 연결
client = QdrantClient(host="localhost", port=6333)

# 3. 검색 쿼리 임베딩 생성
query_text = "sample trojan downloader malware"
query_vector = model.encode(query_text).tolist()

# 4. 검색 실행
hits = client.search(
    collection_name="malware_signatures",
    query_vector=query_vector,
    limit=5
)

# 5. 결과 출력
for hit in hits:
    print(f"ID: {hit.id}, Score: {hit.score}, Payload: {hit.payload}")
