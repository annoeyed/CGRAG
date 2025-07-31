import json
import random
from datetime import datetime, timedelta

cve_ids = [f"CVE-202{random.randint(0, 4)}-{random.randint(1000,9999)}" for _ in range(50)]
descriptions = [
    "Remote code execution vulnerability in Apache Log4j",
    "SQL injection flaw in login module",
    "Heap overflow in image parser",
    "Use-after-free vulnerability in browser engine",
    "Privilege escalation via symbolic link attack",
    "Cross-site scripting in web admin panel",
    "Denial of service via crafted packet",
    "Buffer overflow in file upload handler",
    "Directory traversal in download endpoint",
    "Authentication bypass in token system",
]
severities = ["low", "medium", "high", "critical"]
vendors = ["Apache", "Microsoft", "Google", "Cisco", "Oracle", "Adobe", "Samsung"]

data = []

for i, cve_id in enumerate(cve_ids):
    entry = {
        "cve_id": cve_id,
        "description": random.choice(descriptions),
        "severity": random.choice(severities),
        "published": (datetime.today() - timedelta(days=random.randint(0, 1500))).strftime("%Y-%m-%d"),
        "vendor": random.choice(vendors),
        "category": "software",
    }
    data.append(entry)

with open("data/cve_database.json", "w") as f:
    json.dump(data, f, indent=2)

print("CVE 데이터 50개 생성 완료 → data/cve_database.json")
