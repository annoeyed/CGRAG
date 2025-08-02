import os
import json
import csv
import random
from datetime import datetime, timedelta

def create_cgrag_data():
    """CGRAG 프로젝트에 필요한 모든 샘플 데이터 파일을 생성합니다."""
    
    # 데이터 디렉토리 생성
    if not os.path.exists('data'):
        os.makedirs('data')
        print("'data' 디렉토리가 생성되었습니다.")

    # 1. 악성코드 데이터 생성 (JSON)
    create_malware_data()

    # 2. 네트워크 로그 데이터 생성 (CSV)
    create_network_logs()

    # 3. CVE 취약점 데이터 생성 (JSON)
    create_cve_database()

    print("\n모든 데이터 파일 생성이 완료되었습니다!")

def create_malware_data():
    """실제 악성코드 샘플 기반의 데이터를 생성하여 JSON 파일로 저장합니다."""
    malware_data = [
        {
            "id": 1,
            "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "family": "WannaCry",
            "type": "Ransomware",
            "threat_level": "High",
            "signature": "Encrypts files and demands ransom. Spreads through SMB vulnerability CVE-2017-0144 (EternalBlue).",
            "related_cve": ["CVE-2017-0144"]
        },
        {
            "id": 2,
            "hash": "e88bc3a64006c561579b4de53202976378e9f598463566735e2373da2873de83",
            "family": "Zeus",
            "type": "Trojan",
            "threat_level": "High",
            "signature": "Banking trojan that steals financial information using man-in-the-browser techniques.",
            "related_cve": []
        },
        {
            "id": 3,
            "hash": "f2f1b3b4d5d6e7e8f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3",
            "family": "Emotet",
            "type": "Botnet, Trojan",
            "threat_level": "Critical",
            "signature": "Advanced, self-propagating modular trojan. Primarily a downloader for other malware.",
            "related_cve": []
        },
        {
            "id": 4,
            "hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
            "family": "Stuxnet",
            "type": "Worm",
            "threat_level": "Critical",
            "signature": "Highly sophisticated worm targeting industrial control systems (ICS). Exploited multiple zero-day vulnerabilities.",
            "related_cve": ["CVE-2010-2568"]
        },
        {
            "id": 5,
            "hash": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
            "family": "Conficker",
            "type": "Worm",
            "threat_level": "Medium",
            "signature": "Worm that targets Windows systems. Creates a botnet for spamming and phishing.",
            "related_cve": ["CVE-2008-4250"]
        },
        {
            "id": 6,
            "hash": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
            "family": "Gh0st RAT",
            "type": "Backdoor",
            "threat_level": "High",
            "signature": "Remote Access Trojan (RAT) used for cyber espionage. Allows full control over the infected machine.",
            "related_cve": []
        },
        {
            "id": 7,
            "hash": "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
            "family": "Mirai",
            "type": "Botnet",
            "threat_level": "High",
            "signature": "Malware that turns networked devices running Linux into remotely controlled bots for DDoS attacks.",
            "related_cve": []
        },
        {
            "id": 8,
            "hash": "d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7f8a9b0c1d2",
            "family": "Ryuk",
            "type": "Ransomware",
            "threat_level": "Critical",
            "signature": "Targeted ransomware known for high-value extortion. Often deployed after an Emotet infection.",
            "related_cve": []
        }
    ]
    file_path = 'data/sample_malware_hashes.json'
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(malware_data, f, indent=4, ensure_ascii=False)
    print(f"악성코드 데이터가 '{file_path}'에 저장되었습니다. (샘플 8개)")

def create_network_logs():
    """정상 네트워크 트래픽 패턴을 모방한 로그 1,000개를 생성하여 CSV 파일로 저장합니다."""
    file_path = 'data/network_logs.csv'
    headers = ['id', 'timestamp', 'source_ip', 'destination_ip', 'destination_port', 'protocol', 'bytes_sent', 'packets_sent', 'activity']

    activities = {
        'DNS Query': (0.401, 53, 'UDP'),
        'HTTPS Connection': (0.313, 443, 'TCP'),
        'HTTP Web Browsing': (0.144, 80, 'TCP'),
        'SSH Connection': (0.05, 22, 'TCP'),
        'FTP Transfer': (0.03, 21, 'TCP'),
        'SMTP Email': (0.062, 25, 'TCP'),
    }
    
    activity_list = random.choices(
        population=list(activities.keys()),
        weights=[v[0] for v in activities.values()],
        k=1000
    )

    with open(file_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        start_time = datetime.now() - timedelta(hours=1)
        for i in range(1000):
            activity = activity_list[i]
            port, protocol = activities[activity][1], activities[activity][2]
            
            row = [
                i + 1,
                (start_time + timedelta(seconds=random.randint(0, 3600))).isoformat(),
                f"192.168.1.{random.randint(10, 200)}",
                f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                port,
                protocol,
                random.randint(60, 1500) if activity != 'FTP Transfer' else random.randint(10000, 500000),
                random.randint(1, 20) if activity != 'FTP Transfer' else random.randint(50, 500),
                activity
            ]
            writer.writerow(row)
            
    print(f"네트워크 로그 데이터가 '{file_path}'에 저장되었습니다. (로그 1,000개)")

def create_cve_database():
    """주요 CVE 취약점 정보를 생성하여 JSON 파일로 저장합니다."""
    cve_data = [
        {
            "id": "CVE-2017-0144",
            "cvss_v3": 9.8,
            "severity": "Critical",
            "description": "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via a crafted packet, leveraged by WannaCry.",
            "affected_products": ["Windows 7", "Windows Server 2008"],
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
            "exploit_available": True
        },
        {
            "id": "CVE-2021-44228",
            "cvss_v3": 10.0,
            "severity": "Critical",
            "description": "Remote code execution vulnerability in Apache Log4j 2. An attacker who can control log messages can execute arbitrary code.",
            "affected_products": ["Apache Log4j2 <=2.14.1"],
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "exploit_available": True
        },
        {
            "id": "CVE-2010-2568",
            "cvss_v2": 9.3,
            "severity": "High",
            "description": "Microsoft Windows Shell vulnerability in the handling of LNK files, which allows remote code execution, used by Stuxnet.",
            "affected_products": ["Windows XP", "Windows 7"],
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2010-2568",
            "exploit_available": True
        },
        {
            "id": "CVE-2008-4250",
            "cvss_v2": 10.0,
            "severity": "Critical",
            "description": "The Server service in Microsoft Windows allows remote code execution via a crafted RPC request, exploited by Conficker.",
            "affected_products": ["Windows 2000", "Windows XP", "Windows Vista"],
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2008-4250",
            "exploit_available": True
        },
        {
            "id": "CVE-2019-0708",
            "cvss_v3": 9.8,
            "severity": "Critical",
            "description": "A remote code execution vulnerability exists in Remote Desktop Services (BlueKeep) when an unauthenticated attacker connects to the target system using RDP.",
            "affected_products": ["Windows 7", "Windows Server 2008"],
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
            "exploit_available": True
        },
        {
            "id": "CVE-2020-0601",
            "cvss_v3": 8.1,
            "severity": "High",
            "description": "A spoofing vulnerability exists in the way Windows CryptoAPI (Crypt32.dll) validates Elliptic Curve Cryptography (ECC) certificates (Curveball).",
            "affected_products": ["Windows 10", "Windows Server 2016/2019"],
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-0601",
            "exploit_available": True
        }
    ]
    file_path = 'data/cve_database.json'
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(cve_data, f, indent=4, ensure_ascii=False)
    print(f"CVE 데이터베이스가 '{file_path}'에 저장되었습니다. (취약점 6개)")

if __name__ == '__main__':
    create_cgrag_data()
