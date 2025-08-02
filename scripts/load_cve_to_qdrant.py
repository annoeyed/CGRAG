from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import PointStruct
from fetch_cve_from_nvd import fetch_recent_cves

model = SentenceTransformer("all-MiniLM-L6-v2")
client = QdrantClient("localhost", port=6333)

def embed_and_store(cve_list):
    vectors = []
    points = []
    for idx, cve in enumerate(cve_list):
        cve_id = cve["cve"]["id"]
        desc = cve["cve"]["descriptions"][0]["value"]
        embedding = model.encode(desc).tolist()
        point = PointStruct(
            id=idx,
            vector=embedding,
            payload={"cve_id": cve_id, "description": desc, "category": "cve"}
        )
        points.append(point)

    client.upsert(collection_name="threat_intel", points=points)
    print(f"{len(points)} CVEs indexed to Qdrant")

if __name__ == "__main__":
    cves = fetch_recent_cves(100)
    embed_and_store(cves)
