# generate_sample_data.py
import json
import csv
import random
from faker import Faker
import os

fake = Faker()
os.makedirs("data", exist_ok=True)

### 1. malware_signatures.json 생성 ###
malware_signatures = []
for i in range(200):
    malware = {
        "id": f"mal_{i}",
        "name": fake.word(),
        "hash": fake.sha1(),
        "description": fake.sentence(nb_words=6),
        "family": random.choice(["Trojan", "Worm", "Spyware", "Adware"]),
    }
    malware_signatures.append(malware)

with open("data/sample_malware_hashes.json", "w") as f:
    json.dump(malware_signatures, f, indent=2)

### 2. network_logs.csv 생성 ###
with open("data/network_logs.csv", "w", newline="") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=["timestamp", "src_ip", "dst_ip", "dst_port","protocol", "length"])
    writer.writeheader()
    for _ in range(1000):
        writer.writerow({
            "timestamp": fake.iso8601(),
            "src_ip": fake.ipv4(),
            "dst_ip": fake.ipv4(),
            "dst_port": random.randint(1024, 65535),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "length": random.randint(40, 1500)
        })

### 3. cve_database.json 생성 ###
cve_data = []
for i in range(100):
    entry = {
        "id": f"cve_{i}",
        "cve_id": f"CVE-2025-{str(i).zfill(4)}",
        "description": fake.sentence(nb_words=12), 
        "score": round(random.uniform(3.0, 9.8), 1),
        "product": fake.word()
    }
    cve_data.append(entry)

with open("data/cve_database.json", "w") as f:
    json.dump(cve_data, f, indent=2)

print("샘플 데이터 생성 완료!")
