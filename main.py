# main.py
from src.qdrant_manager import SecurityQdrantManager
from src.rag_engine import CyberSecurityRAG
import json
import time

def main():
    print("  Starting CyberGuard RAG system")
    
    # Connect and set up Qdrant
    qdrant_manager = SecurityQdrantManager()
    qdrant_manager.setup_collections()
    
    # Initialize RAG engine
    rag_engine = CyberSecurityRAG(qdrant_manager)
    
    # Load sample data
    print("\n Loading sample security data...")
    load_sample_data(rag_engine)
    
    # Interactive security analysis
    print("\nStarting security analysis (type 'quit' to exit)")
    while True:
        query = input("\nEnter your security query: ")
        if query.lower() == 'quit':
            break
            
        # Auto-detect query type
        query_type = detect_query_type(query)
        
        print(f"\n⚡ Analyzing as '{query_type}' type...")
        result = rag_engine.analyze_security_query(query, query_type)
        
        # Print analysis result
        print_analysis_result(result)

def load_sample_data(rag_engine):
    """Load sample security data"""
    # Sample malware data
    sample_malware = [
        {
            "name": "WannaCry Ransomware",
            "description": "A ransomware targeting Windows systems",
            "hash": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            "threat_level": "critical",
            "source": "security_lab"
        },
        {
            "name": "Zeus Banking Trojan",
            "description": "A trojan that steals online banking information",
            "hash": "7c9c45b9b53c1e3e8b5a4d2c8f9e7b6a3d5c1e9f8b7a6d4c2e1f9b8c7e6d5a4",
            "threat_level": "high",
            "source": "threat_intel"
        }
    ]
    
    # Load malware database
    with open("data/sample_malware_hashes.json", "w") as f:
        json.dump(sample_malware, f, indent=2)
    
    rag_engine.malware_detector.load_malware_database("data/sample_malware_hashes.json")
    
    # Sample normal network logs
    normal_logs = [
        {"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "UDP", "bytes": 64, "packets": 1},
        {"src_ip": "192.168.1.100", "dst_ip": "google.com", "dst_port": 443, "protocol": "TCP", "bytes": 1500, "packets": 10},
        {"src_ip": "192.168.1.101", "dst_ip": "microsoft.com", "dst_port": 80, "protocol": "TCP", "bytes": 2048, "packets": 15}
    ]
    
    rag_engine.anomaly_detector.train_normal_behavior(normal_logs)

def detect_query_type(query: str) -> str:
    """Auto-detect query type"""
    query_lower = query.lower()
    
    malware_keywords = ["malware", "virus", "trojan", "ransomware"]
    network_keywords = ["network", "traffic", "connection", "ip"]
    
    if any(keyword in query_lower for keyword in malware_keywords):
        return "malware"
    elif any(keyword in query_lower for keyword in network_keywords):
        return "network"
    else:
        return "general"

def print_analysis_result(result: dict):
    """Print analysis result"""
    print(f"\n Analysis Result ({result['type']})")
    print(f"Query: {result['query']}")
    
    if result['findings']:
        print(f"\n Found items ({len(result['findings'])}):")
        for i, finding in enumerate(result['findings'][:5], 1):
            print(f"  {i}. Relevance: {finding['relevance']:.2%}")
            print(f"     Threat Level: {finding.get('threat_level', 'unknown')}")
            print(f"     Content: {finding.get('description', finding.get('summary', ''))}")
            print()
    
    if 'recommendations' in result and result['recommendations']:
        print("Recommendations:")
        for rec in result['recommendations']:
            print(f"  • {rec}")

if __name__ == "__main__":
    main()
