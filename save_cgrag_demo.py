import json

# 전체 노트북 구성
notebook = {
    "cells": [],
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3"
        },
        "language_info": {
            "name": "python",
            "version": "3.9.12",
            "mimetype": "text/x-python",
            "codemirror_mode": {
                "name": "ipython",
                "version": 3
            },
            "pygments_lexer": "ipython3",
            "nbconvert_exporter": "python",
            "file_extension": ".py"
        }
    },
    "nbformat": 4,
    "nbformat_minor": 4
}

# 셀 목록을 준비
markdown_cells = [
    "# CGRAG 데모: Qdrant를 활용한 보안 위협 탐지\n\n이 노트북은 CGRAG 시스템의 주요 기능인 악성코드 탐지, 네트워크 이상 탐지, 그리고 위협 인텔리전스 검색의 실제 작동 흐름을 보여줍니다.\n\n---\n\n## 1. 소개\n\n**CGRAG**는 Qdrant 벡터 데이터베이스와 RAG 파이프라인을 활용하여 다음과 같은 보안 기능을 제공하는 AI 기반 시스템입니다:\n- 악성코드 유사도 탐지\n- 네트워크 이상 행위 탐지\n- 사이버 위협 인텔리전스 검색\n\n**사용 데이터:**\n- `sample_malware_hashes.json`: 악성코드 메타데이터 (이름, 설명, 해시 등)\n- `cve_database.json`: CVE 및 글로벌 취약점 메타데이터\n- `network_logs.csv`: 정상 (베이스라인) 네트워크 트래픽 로그",
    "## 2. 환경 설정 및 Qdrant 서버 연결\n\n### 필수 패키지 설치",
    "### 모듈 임포트 및 Qdrant 연결",
    "### 설정 파일 로드 및 Qdrant 클라이언트 초기화",
    "### 필요한 컬렉션이 존재하는지 확인",
    "--- \n## 3. 핵심 기능 데모\n\n이제 CGRAG의 핵심 보안 기능들을 시연합니다.",
    "### 3.1. 악성코드 유사도 검색\n\n새로운 악성코드 해시가 주어졌을 때, 데이터베이스에 저장된 기존 악성코드와 얼마나 유사한지 검색합니다.",
    "### 3.2. 네트워크 이상 탐지\n\n새로운 네트워크 로그가 정상 패턴과 얼마나 다른지(이상 점수)를 계산하여 비정상적인 활동을 탐지합니다.",
    "### 3.3. 위협 인텔리전스 검색\n\n키워드를 사용해 CVE 데이터베이스에서 관련 위협 정보를 검색합니다."
]

code_cells = [
    "!pip install qdrant-client sentence-transformers pandas pyyaml",
    "import sys\nimport os\nimport yaml\nimport pandas as pd\nfrom qdrant_client import QdrantClient\nfrom sentence_transformers import SentenceTransformer\n\nif '..' not in sys.path:\n    sys.path.append('..')\n\nfrom src.qdrant_manager import QdrantManager\nfrom src.rag_engine import RAGEngine",
    "with open(\"../config/config.yaml\", 'r') as f:\n    config = yaml.safe_load(f)\n\nqdrant_host = config['qdrant']['host']\nqdrant_port = config['qdrant']['port']\nembedding_model = config['embeddings']['model']\n\nqdrant_manager = QdrantManager(host=qdrant_host, port=qdrant_port)\nrag_engine = RAGEngine(qdrant_manager, model_name=embedding_model)\n\nprint(f\"Qdrant에 연결되었습니다. ({qdrant_host}:{qdrant_port})\")",
    "collections = [\"malware_signatures\", \"network_patterns\", \"threat_intel\"]\nfor c in collections:\n    exists = qdrant_manager.client.collection_exists(collection_name=c)\n    print(f\"컬렉션 '{c}': {'존재함' if exists else '존재하지 않음'}\")",
    "query_hash = \"a3a4e6b6f8f1e4a7b8c9d0e1f2a3b4c5\"\nsimilar_malware = rag_engine.query_malware(query_hash, top_k=3)\n\nprint(f\"'{query_hash}'와(과) 유사한 악성코드 검색 결과:\")\nfor malware in similar_malware:\n    print(f\"- ID: {malware.id}, 점수: {malware.score:.4f}, 이름: {malware.payload.get('name')}\")",
    "new_log_entry = \"timestamp,src_ip,dst_ip,dst_port,protocol\\n2023-10-27 11:00:00,192.168.1.100,10.0.0.255,666,UDP\"\n\nanomaly_score = rag_engine.detect_anomaly(new_log_entry)\n\nprint(f\"새로운 로그 항목: \\n{new_log_entry}\\n\")\nprint(f\"계산된 이상 탐지 점수: {anomaly_score:.4f}\")\nif anomaly_score > config['security']['anomaly_threshold']:\n    print(\"결과: 비정상적인 활동으로 의심됩니다.\")\nelse:\n    print(\"결과: 정상적인 활동으로 보입니다.\")",
    "threat_query = \"Log4j remote code execution\"\nthreat_info = rag_engine.query_threat_intel(threat_query, top_k=2)\n\nprint(f\"'{threat_query}'에 대한 위협 인텔리전스 검색 결과:\")\nfor threat in threat_info:\n    print(f\"- ID: {threat.id}, 점수: {threat.score:.4f}\")\n    print(f\"  설명: {threat.payload.get('description')}\\n\")"
]

# 마크다운 셀 추가
for md in markdown_cells:
    notebook["cells"].append({
        "cell_type": "markdown",
        "metadata": {},
        "source": [md]
    })

# 코드 셀 추가
for code in code_cells:
    notebook["cells"].append({
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [line + "\n" for line in code.splitlines()]
    })

# 저장
output_path = "./cgrag_demo.ipynb"
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(notebook, f, ensure_ascii=False, indent=2)

output_path
