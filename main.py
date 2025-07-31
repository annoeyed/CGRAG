# main.py
from src.qdrant_manager import SecurityQdrantManager
from src.rag_engine import CyberSecurityRAG
import json
import time

def main():
    print("  CyberGuard RAG 시스템 시작")
    
    # Qdrant 연결 및 설정
    qdrant_manager = SecurityQdrantManager()
    qdrant_manager.setup_collections()
    
    # RAG 엔진 초기화
    rag_engine = CyberSecurityRAG(qdrant_manager)
    
    # 샘플 데이터 로드
    print("\n 샘플 보안 데이터 로드 중...")
    load_sample_data(rag_engine)
    
    # 인터랙티브 보안 분석
    print("\n 보안 분석 시작 (종료하려면 'quit' 입력)")
    while True:
        query = input("\n보안 쿼리를 입력하세요: ")
        if query.lower() == 'quit':
            break
            
        # 쿼리 타입 자동 감지
        query_type = detect_query_type(query)
        
        print(f"\n⚡ '{query_type}' 타입으로 분석 중...")
        result = rag_engine.analyze_security_query(query, query_type)
        
        # 결과 출력
        print_analysis_result(result)

def load_sample_data(rag_engine):
    """샘플 보안 데이터 로드"""
    # 샘플 악성코드 데이터
    sample_malware = [
        {
            "name": "WannaCry Ransomware",
            "description": "Windows 시스템을 대상으로 하는 랜섬웨어",
            "hash": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            "threat_level": "critical",
            "source": "security_lab"
        },
        {
            "name": "Zeus Banking Trojan",
            "description": "온라인 뱅킹 정보 탈취 트로이안",
            "hash": "7c9c45b9b53c1e3e8b5a4d2c8f9e7b6a3d5c1e9f8b7a6d4c2e1f9b8c7e6d5a4",
            "threat_level": "high",
            "source": "threat_intel"
        }
    ]
    
    # 악성코드 데이터베이스 로드
    with open("data/sample_malware_hashes.json", "w") as f:
        json.dump(sample_malware, f, indent=2)
    
    rag_engine.malware_detector.load_malware_database("data/sample_malware_hashes.json")
    
    # 샘플 정상 네트워크 로그
    normal_logs = [
        {"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "UDP", "bytes": 64, "packets": 1},
        {"src_ip": "192.168.1.100", "dst_ip": "google.com", "dst_port": 443, "protocol": "TCP", "bytes": 1500, "packets": 10},
        {"src_ip": "192.168.1.101", "dst_ip": "microsoft.com", "dst_port": 80, "protocol": "TCP", "bytes": 2048, "packets": 15}
    ]
    
    rag_engine.anomaly_detector.train_normal_behavior(normal_logs)

def detect_query_type(query: str) -> str:
    """쿼리 타입 자동 감지"""
    query_lower = query.lower()
    
    malware_keywords = ["악성코드", "바이러스", "malware", "virus", "trojan", "ransomware"]
    network_keywords = ["네트워크", "트래픽", "network", "traffic", "connection", "ip"]
    
    if any(keyword in query_lower for keyword in malware_keywords):
        return "malware"
    elif any(keyword in query_lower for keyword in network_keywords):
        return "network"
    else:
        return "general"

def print_analysis_result(result: dict):
    """분석 결과 출력"""
    print(f"\n 분석 결과 ({result['type']})")
    print(f"쿼리: {result['query']}")
    
    if result['findings']:
        print(f"\n 발견된 항목 ({len(result['findings'])}개):")
        for i, finding in enumerate(result['findings'][:5], 1):
            print(f"  {i}. 관련도: {finding['relevance']:.2%}")
            print(f"     위험도: {finding.get('threat_level', 'unknown')}")
            print(f"     내용: {finding.get('description', finding.get('summary', ''))}")
            print()
    
    if 'recommendations' in result and result['recommendations']:
        print("추천사항:")
        for rec in result['recommendations']:
            print(f"  • {rec}")

if __name__ == "__main__":
    main()
