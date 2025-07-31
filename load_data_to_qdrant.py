from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import PointStruct
import json, pandas as pd, time

enc = SentenceTransformer("all-MiniLM-L6-v2")
qdr = QdrantClient("localhost", port=6333)

def vec(txt): return enc.encode(txt).tolist()

# 1) 악성코드
with open("data/sample_malware_hashes.json") as f:
    mal = json.load(f)
points = [PointStruct(id=i,
                      vector=vec(f"{d['name']} {d['description']}"),
                      payload=d | {"category":"malware",
                                   "timestamp":time.strftime('%F %T')})
          for i, d in enumerate(mal)]
qdr.upsert("malware_signatures", points)

# 2) CVE
with open("data/cve_database.json") as f:
    cves = json.load(f)
points = [PointStruct(id=i,
                      vector=vec(f"{c['cve_id']} {c['description']}"),
                      payload=c | {"category":"cve",
                                   "timestamp":time.strftime('%F %T')})
          for i, c in enumerate(cves)]
qdr.upsert("threat_intel", points)

# 3) 네트워크 로그
df = pd.read_csv("data/network_logs.csv")
batch = []
for idx, row in df.iterrows():
    text = f"src_{row.src_ip} dst_{row.dst_ip} port_{row.dst_port} proto_{row.protocol}"
    batch.append(PointStruct(id=idx,
                             vector=vec(text),
                             payload=row.to_dict() | {"category":"network",
                                                      "threat_level":"normal"}))
    if len(batch) == 500:
        qdr.upsert("network_patterns", batch)
        batch = []
if batch:
    qdr.upsert("network_patterns", batch)

print("data loaded")
