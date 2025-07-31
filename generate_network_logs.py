import pandas as pd
import random

src_ips = [f"192.168.1.{i}" for i in range(2, 254)]
dst_ips = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1", "172.16.0.1"]
protocols = ["TCP", "UDP", "ICMP"]
ports = list(range(20, 1024))

logs = []

for _ in range(1000):
    entry = {
        "src_ip": random.choice(src_ips),
        "dst_ip": random.choice(dst_ips),
        "dst_port": random.choice(ports),
        "protocol": random.choice(protocols),
    }
    logs.append(entry)

df = pd.DataFrame(logs)
df.to_csv("data/network_logs.csv", index=False)
print("정상 트래픽 1000개 생성 완료 → data/network_logs.csv")
