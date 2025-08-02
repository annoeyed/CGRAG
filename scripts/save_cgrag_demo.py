import json

# 이 스크립트는 CGRAG 시스템의 핵심 기능을 시연하는 Jupyter 노트북(.ipynb) 파일을 프로그래밍 방식으로 생성합니다.

def create_code_cell(source):
    """코드 셀 구조를 생성합니다."""
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": source.strip().split('\n')
    }

def create_markdown_cell(source):
    """마크다운 셀 구조를 생성합니다."""
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": source.strip().split('\n')
    }

# --- 셀 내용 정의 ---

# 각 요소는 (셀 유형, 내용) 튜플입니다.
cell_definitions = [
    ("markdown", """
# CGRAG 데모: Qdrant를 활용한 보안 위협 탐지

이 노트북은 CGRAG 시스템의 주요 기능인 악성코드 탐지, 네트워크 이상 탐지, 그리고 위협 인텔리전스 검색의 실제 작동 흐름을 보여줍니다.

---

## 1. 소개

**CGRAG**는 Qdrant 벡터 데이터베이스와 RAG 파이프라인을 활용하여 다음과 같은 보안 기능을 제공하는 AI 기반 시스템입니다:
- 악성코드 유사도 탐지
- 네트워크 이상 행위 탐지
- 사이버 위협 인텔리전스 검색

**사용 데이터:**
- `sample_malware_hashes.json`: 악성코드 메타데이터 (이름, 설명, 해시 등)
- `cve_database.json`: CVE 및 글로벌 취약점 메타데이터
- `network_logs.csv`: 정상 (베이스라인) 네트워크 트래픽 로그
    """),
    ("markdown", """
## 2. 환경 설정 및 Qdrant 서버 연결

### 필수 패키지 설치
    """),
    ("code", """
!pip install qdrant-client sentence-transformers pandas pyyaml
    """),
    ("markdown", """
### 모듈 임포트 및 Qdrant 연결
    """),
    ("code", """
import sys
import os
import yaml
import pandas as pd
from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer

# 파이썬 경로에 프로젝트 루트 추가
if '..' not in sys.path:
    sys.path.append('..')

from src.qdrant_manager import QdrantManager
from src.rag_engine import RAGEngine
    """),
    ("markdown", """
### 설정 파일 로드 및 Qdrant 클라이언트 초기화
    """),
    ("code", """
with open("../config/config.yaml", 'r') as f:
    config = yaml.safe_load(f)

qdrant_host = config['qdrant']['host']
qdrant_port = config['qdrant']['port']
embedding_model = config['embeddings']['model']

qdrant_manager = QdrantManager(host=qdrant_host, port=qdrant_port)
rag_engine = RAGEngine(qdrant_manager, model_name=embedding_model)

print(f"Qdrant에 연결되었습니다. ({qdrant_host}:{qdrant_port})")
    """),
    ("markdown", """
### 필요한 컬렉션이 존재하는지 확인
    """),
    ("code", """
collections = ["malware_signatures", "network_patterns", "threat_intel"]
for c in collections:
    exists = qdrant_manager.client.collection_exists(collection_name=c)
    print(f"컬렉션 '{c}': {'존재함' if exists else '존재하지 않음'}")
    """),
    ("markdown", """
--- 
## 3. 핵심 기능 데모

이제 CGRAG의 핵심 보안 기능들을 시연합니다.
    """),
    ("markdown", """
### 3.1. 악성코드 유사도 검색

새로운 악성코드 해시가 주어졌을 때, 데이터베이스에 저장된 기존 악성코드와 얼마나 유사한지 검색합니다.
    """),
    ("code", """
query_hash = "a3a4e6b6f8f1e4a7b8c9d0e1f2a3b4c5"
similar_malware = rag_engine.query_malware(query_hash, top_k=3)

print(f"'{query_hash}'와(과) 유사한 악성코드 검색 결과:")
for malware in similar_malware:
    print(f"- ID: {malware.id}, 점수: {malware.score:.4f}, 이름: {malware.payload.get('name')}")
    """),
    ("markdown", """
### 3.2. 네트워크 이상 탐지

새로운 네트워크 로그가 정상 패턴과 얼마나 다른지(이상 점수)를 계산하여 비정상적인 활동을 탐지합니다.
    """),
    ("code", """
new_log_entry = "timestamp,src_ip,dst_ip,dst_port,protocol\\n2023-10-27 11:00:00,192.168.1.100,10.0.0.255,666,UDP"

anomaly_score = rag_engine.detect_anomaly(new_log_entry)

print(f"새로운 로그 항목: \\n{new_log_entry}\\n")
print(f"계산된 이상 탐지 점수: {anomaly_score:.4f}")
if anomaly_score > config['security']['anomaly_threshold']:
    print("결과: 비정상적인 활동으로 의심됩니다.")
else:
    print("결과: 정상적인 활동으로 보입니다.")
    """),
    ("markdown", """
### 3.3. 위협 인텔리전스 검색

키워드를 사용해 CVE 데이터베이스에서 관련 위협 정보를 검색합니다.
    """),
    ("code", """
threat_query = "Log4j remote code execution"
threat_info = rag_engine.query_threat_intel(threat_query, top_k=2)

print(f"'{threat_query}'에 대한 위협 인텔리전스 검색 결과:")
for threat in threat_info:
    print(f"- ID: {threat.id}, 점수: {threat.score:.4f}")
    print(f"  설명: {threat.payload.get('description')}\\n")
    """)
]

# --- 노트북 조립 ---

cells = []
for cell_type, source in cell_definitions:
    if cell_type == "code":
        cells.append(create_code_cell(source))
    else:
        cells.append(create_markdown_cell(source))

notebook = {
    "cells": cells,
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

# --- 노트북 저장 ---

output_path = "cgrag_demo.ipynb"
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(notebook, f, ensure_ascii=False, indent=2)

print(f"Notebook saved to {output_path}")
