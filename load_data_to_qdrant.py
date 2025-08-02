import json
import pandas as pd
from qdrant_client import QdrantClient, models
from sentence_transformers import SentenceTransformer
from tqdm import tqdm
import numpy as np
import time

# --- 설정 ---
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
MODEL_NAME = 'all-MiniLM-L6-v2' # 384 차원 벡터
BATCH_SIZE = 500

# 컬렉션 이름 정의
MALWARE_COLLECTION = "malware_signatures"
THREAT_INTEL_COLLECTION = "threat_intel"
NETWORK_COLLECTION = "network_patterns"

def connect_to_qdrant():
    """Qdrant 클라이언트를 생성하고 연결을 테스트합니다."""
    try:
        client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
        client.get_collections() # 연결 테스트
        print(f"Qdrant 서버에 성공적으로 연결되었습니다. ({QDRANT_HOST}:{QDRANT_PORT})")
        return client
    except Exception as e:
        print(f"Qdrant 서버 연결 실패.")
        print(f"오류: {e}")
        print("Hint: Docker 컨테이너가 실행 중인지 확인하세요.")
        return None

def get_embedding_model():
    """Sentence Transformer 모델을 로드합니다."""
    try:
        print(f"임베딩 모델 '{MODEL_NAME}'을 로드하는 중입니다...")
        model = SentenceTransformer(MODEL_NAME)
        print(f"임베딩 모델 로드 완료.")
        return model
    except Exception as e:
        print(f"임베딩 모델 로드 실패.")
        print(f"오류: {e}")
        return None

def create_collection(client, collection_name, vector_size):
    """지정된 이름과 벡터 크기로 Qdrant 컬렉션을 생성합니다."""
    try:
        client.recreate_collection(
            collection_name=collection_name,
            vectors_config=models.VectorParams(
                size=vector_size,
                distance=models.Distance.COSINE # 코사인 유사도 사용
            ),
            on_disk=True # 메모리 절약을 위해 디스크 기반 저장소 사용
        )
        print(f"  - 컬렉션 '{collection_name}'이(가) 생성되었습니다.")
    except Exception as e:
        print(f"  - 컬렉션 '{collection_name}' 생성 중 오류 발생: {e}")


# --- 데이터 로드 및 처리 함수 ---

def load_malware_data(client, model):
    """악성코드 데이터를 Qdrant에 업로드합니다."""
    collection_name = MALWARE_COLLECTION
    print(f"\n--- 1. 악성코드 데이터 처리 시작 ---")
    
    try:
        with open('data/sample_malware_hashes.json', 'r', encoding='utf-8') as f:
            malware_list = json.load(f)
    except FileNotFoundError:
        print("'data/sample_malware_hashes.json' 파일을 찾을 수 없습니다.")
        return

    create_collection(client, collection_name, model.get_sentence_embedding_dimension())

    texts_to_embed = [
        f"Family: {item['family']}. Type: {item['type']}. Signature: {item['signature']}"
        for item in malware_list
    ]
    
    print(f"  - 텍스트 임베딩 생성 중... (데이터 {len(texts_to_embed)}개)")
    vectors = model.encode(texts_to_embed, show_progress_bar=True)
    
    points = [
        models.PointStruct(
            id=item['id'],
            vector=vector.tolist(),
            payload={
                "hash": item['hash'],
                "family": item['family'],
                "type": "Ransomware",
                "threat_level": item['threat_level'],
                "signature": item['signature'],
                "related_cve": item.get('related_cve', [])
            }
        ) for item, vector in zip(malware_list, vectors)
    ]

    client.upsert(collection_name=collection_name, points=points, wait=True)
    print(f"  - 성공: 총 {len(points)}개의 악성코드 데이터 포인트를 '{collection_name}'에 저장했습니다.")
    return True


def load_cve_data(client, model):
    """CVE 데이터를 Qdrant에 업로드합니다."""
    collection_name = THREAT_INTEL_COLLECTION
    print(f"\n--- 2. CVE 취약점 데이터 처리 시작 ---")

    try:
        with open('data/cve_database.json', 'r', encoding='utf-8') as f:
            cve_list = json.load(f)
    except FileNotFoundError:
        print("'data/cve_database.json' 파일을 찾을 수 없습니다.")
        return

    create_collection(client, collection_name, model.get_sentence_embedding_dimension())
    
    texts_to_embed = [
        f"CVE ID: {item['id']}. Description: {item['description']}. Affected: {', '.join(item['affected_products'])}"
        for item in cve_list
    ]
    
    print(f"  - 텍스트 임베딩 생성 중... (데이터 {len(texts_to_embed)}개)")
    vectors = model.encode(texts_to_embed, show_progress_bar=True)
    
    points = [
        models.PointStruct(
            id=idx + 1,
            vector=vector.tolist(),
            payload=item
        ) for idx, (item, vector) in enumerate(zip(cve_list, vectors))
    ]

    client.upsert(collection_name=collection_name, points=points, wait=True)
    print(f"  - 성공: 총 {len(points)}개의 CVE 데이터 포인트를 '{collection_name}'에 저장했습니다.")
    return True

def load_network_data(client, model):
    """네트워크 로그 데이터를 Qdrant에 업로드합니다."""
    collection_name = NETWORK_COLLECTION
    print(f"\n--- 3. 네트워크 로그 데이터 처리 시작 ---")

    try:
        df = pd.read_csv('data/network_logs.csv')
    except FileNotFoundError:
        print("'data/network_logs.csv' 파일을 찾을 수 없습니다.")
        return
        
    create_collection(client, collection_name, model.get_sentence_embedding_dimension())
    
    # 대표 패턴 생성 (중복 제거 및 요약)
    df_patterns = df.groupby(['destination_port', 'protocol', 'activity']).size().reset_index(name='counts')
    
    texts_to_embed = [
        f"Normal network traffic pattern. Activity: {row['activity']}, Protocol: {row['protocol']}, Port: {row['destination_port']}"
        for _, row in df_patterns.iterrows()
    ]

    print(f"  - 텍스트 임베딩 생성 중... (고유 패턴 {len(texts_to_embed)}개)")
    vectors = model.encode(texts_to_embed, show_progress_bar=True)

    points = []
    for idx, (vector, (_, row)) in enumerate(zip(vectors, df_patterns.iterrows())):
        points.append(
            models.PointStruct(
                id=idx + 1,
                vector=vector.tolist(),
                payload={
                    "activity": row['activity'],
                    "protocol": row['protocol'],
                    "destination_port": int(row['destination_port']),
                    "description": f"A baseline pattern representing normal {row['activity']} activity over {row['protocol']} on port {row['destination_port']}."
                }
            )
        )
        
    client.upsert(collection_name=collection_name, points=points, wait=True)
    print(f"  - 성공: 총 {len(points)}개의 네트워크 패턴 데이터 포인트를 '{collection_name}'에 저장했습니다.")
    return True


# --- 검증 함수 ---
def run_verification_tests(client, model):
    """데이터 저장 후 간단한 검색 테스트를 수행하여 검증합니다."""
    print("\n\n--- 데이터 저장 검증 시작 ---")
    
    # 1. 악성코드 검색 테스트
    query_text_malware = "file encryption ransom"
    query_vector_malware = model.encode(query_text_malware).tolist()
    search_result_malware = client.search(
        collection_name=MALWARE_COLLECTION,
        query_vector=query_vector_malware,
        limit=1
    )
    
    # 2. CVE 검색 테스트
    query_text_cve = "log4j remote code execution"
    query_vector_cve = model.encode(query_text_cve).tolist()
    search_result_cve = client.search(
        collection_name=THREAT_INTEL_COLLECTION,
        query_vector=query_vector_cve,
        limit=1
    )

    print("\n--- Qdrant 검색 테스트 결과 ---")
    if search_result_malware:
        malware_top_hit = search_result_malware[0]
        print(f"악성코드 유사성 쿼리: '{query_text_malware}'")
        print(f"  - 검색 결과 (Top 1): Family: {malware_top_hit.payload['family']} ({malware_top_hit.payload['hash'][:12]}...)")
        print(f"  - 유사도 점수: {malware_top_hit.score:.4f}")
    else:
        print("악성코드 검색 결과가 없습니다.")

    if search_result_cve:
        cve_top_hit = search_result_cve[0]
        print(f"위협 인텔리전스 쿼리: '{query_text_cve}'")
        print(f"  - 검색 결과 (Top 1): ID: {cve_top_hit.payload['id']}")
        print(f"  - 유사도 점수: {cve_top_hit.score:.4f}")
    else:
        print("CVE 검색 결과가 없습니다.")
    print("---------------------------------")


# --- 메인 실행 함수 ---
def main():
    start_time = time.time()
    print("CGRAG 데이터 로더 시작")
    
    client = connect_to_qdrant()
    if not client:
        return

    model = get_embedding_model()
    if not model:
        return

    # 데이터 로드
    malware_ok = load_malware_data(client, model)
    cve_ok = load_cve_data(client, model)
    network_ok = load_network_data(client, model)

    # 모든 데이터 로드가 성공했는지 확인
    if all([malware_ok, cve_ok, network_ok]):
        print("\n모든 데이터가 Qdrant에 성공적으로 저장되었습니다.")
        
        # 검증 테스트 실행
        run_verification_tests(client, model)
    else:
        print("\n일부 데이터 저장에 실패했습니다. 로그를 확인해주세요.")
        
    end_time = time.time()
    print(f"\n총 실행 시간: {end_time - start_time:.2f}초")

if __name__ == '__main__':
    main()
