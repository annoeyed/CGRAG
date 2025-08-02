import json
import pandas as pd
from qdrant_client import QdrantClient, models
from sentence_transformers import SentenceTransformer
from tqdm import tqdm
import numpy as np
import time

# --- Settings ---
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
MODEL_NAME = 'all-MiniLM-L6-v2' # 384-dimensional vectors
BATCH_SIZE = 500

# Collection names definition
MALWARE_COLLECTION = "malware_signatures"
THREAT_INTEL_COLLECTION = "threat_intel"
NETWORK_COLLECTION = "network_patterns"

def connect_to_qdrant():
    """Creates a Qdrant client and tests the connection."""
    try:
        client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
        client.get_collections() # Test connection
        print(f"Successfully connected to Qdrant server. ({QDRANT_HOST}:{QDRANT_PORT})")
        return client
    except Exception as e:
        print(f"Failed to connect to Qdrant server.")
        print(f"Error: {e}")
        print("Hint: Check if the Docker container is running.")
        return None

def get_embedding_model():
    """Loads the Sentence Transformer model."""
    try:
        print(f"Loading embedding model '{MODEL_NAME}'...")
        model = SentenceTransformer(MODEL_NAME)
        print(f"Embedding model loaded successfully.")
        return model
    except Exception as e:
        print(f"Failed to load embedding model.")
        print(f"Error: {e}")
        return None

def create_collection(client, collection_name, vector_size):
    """Creates a Qdrant collection with the specified name and vector size."""
    try:
        client.recreate_collection(
            collection_name=collection_name,
            vectors_config=models.VectorParams(
                size=vector_size,
                distance=models.Distance.COSINE # Use cosine similarity
            )
        )
        print(f"  - Collection '{collection_name}' has been created.")
    except Exception as e:
        # It's okay if the collection already exists.
        # This error can be ignored if it's about `on_disk` or existence.
        if "already exists" in str(e) or "Unknown arguments" in str(e):
             print(f"  - Collection '{collection_name}' already exists or minor issue occurred. Proceeding.")
        else:
            print(f"  - Error creating collection '{collection_name}': {e}")


# --- Data Loading and Processing Functions ---

def load_malware_data(client, model):
    """Uploads malware data to Qdrant."""
    collection_name = MALWARE_COLLECTION
    print(f"\n--- 1. Starting Malware Data Processing ---")
    
    try:
        with open('data/sample_malware_hashes.json', 'r', encoding='utf-8') as f:
            malware_list = json.load(f)
    except FileNotFoundError:
        print("'data/sample_malware_hashes.json' file not found.")
        return

    create_collection(client, collection_name, model.get_sentence_embedding_dimension())

    texts_to_embed = [
        f"Family: {item['family']}. Type: {item['type']}. Signature: {item['signature']}"
        for item in malware_list
    ]
    
    print(f"  - Creating text embeddings... ({len(texts_to_embed)} data points)")
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
    print(f"  - Success: A total of {len(points)} malware data points have been saved to '{collection_name}'.")
    return True


def load_cve_data(client, model):
    """Uploads CVE data to Qdrant."""
    collection_name = THREAT_INTEL_COLLECTION
    print(f"\n--- 2. Starting CVE Vulnerability Data Processing ---")

    try:
        with open('data/cve_database.json', 'r', encoding='utf-8') as f:
            cve_list = json.load(f)
    except FileNotFoundError:
        print("'data/cve_database.json' file not found.")
        return

    create_collection(client, collection_name, model.get_sentence_embedding_dimension())
    
    texts_to_embed = [
        f"CVE ID: {item.get('id', '')}. Description: {item.get('description', '')}. Affected: {', '.join(item.get('affected_products', []))}"
        for item in cve_list
    ]
    
    print(f"  - Creating text embeddings... ({len(texts_to_embed)} data points)")
    vectors = model.encode(texts_to_embed, show_progress_bar=True)
    
    points = [
        models.PointStruct(
            id=idx + 1,
            vector=vector.tolist(),
            payload=item
        ) for idx, (item, vector) in enumerate(zip(cve_list, vectors))
    ]

    client.upsert(collection_name=collection_name, points=points, wait=True)
    print(f"  - Success: A total of {len(points)} CVE data points have been saved to '{collection_name}'.")
    return True

def load_network_data(client, model):
    """Uploads network log data to Qdrant."""
    collection_name = NETWORK_COLLECTION
    print(f"\n--- 3. Starting Network Log Data Processing ---")

    try:
        df = pd.read_csv('data/network_logs.csv')
    except FileNotFoundError:
        print("'data/network_logs.csv' file not found.")
        return
        
    create_collection(client, collection_name, model.get_sentence_embedding_dimension())
    
    # Create representative patterns (remove duplicates and summarize)
    df_patterns = df.groupby(['destination_port', 'protocol', 'activity']).size().reset_index(name='counts')
    
    texts_to_embed = [
        f"Normal network traffic pattern. Activity: {row['activity']}, Protocol: {row['protocol']}, Port: {row['destination_port']}"
        for _, row in df_patterns.iterrows()
    ]

    print(f"  - Creating text embeddings... ({len(texts_to_embed)} unique patterns)")
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
    print(f"  - Success: A total of {len(points)} network pattern data points have been saved to '{collection_name}'.")
    return True


# --- Verification Function ---
def run_verification_tests(client, model):
    """Performs simple search tests after data storage to verify."""
    print("\n\n--- Starting Data Storage Verification ---")
    
    # 1. Malware search test
    query_text_malware = "file encryption ransom"
    query_vector_malware = model.encode(query_text_malware).tolist()
    search_result_malware = client.search(
        collection_name=MALWARE_COLLECTION,
        query_vector=query_vector_malware,
        limit=1,
        
    )
    
    # 2. CVE search test
    query_text_cve = "log4j remote code execution"
    query_vector_cve = model.encode(query_text_cve).tolist()
    search_result_cve = client.search(
        collection_name=THREAT_INTEL_COLLECTION,
        query_vector=query_vector_cve,
        limit=1
    )

    print("\n--- Qdrant Search Test Results ---")
    if search_result_malware:
        malware_top_hit = search_result_malware[0]
        print(f"Malware similarity query: '{query_text_malware}'")
        print(f"  - Search result (Top 1): Family: {malware_top_hit.payload.get('family', 'N/A')} ({malware_top_hit.payload.get('hash', 'N/A')[:12]}...)")
        print(f"  - Similarity score: {malware_top_hit.score:.4f}")
    else:
        print("No malware search results.")

    if search_result_cve:
        cve_top_hit = search_result_cve[0]
        print(f"Threat intelligence query: '{query_text_cve}'")
        print(f"  - Search result (Top 1): ID: {cve_top_hit.payload.get('id', 'N/A')}")
        print(f"  - Similarity score: {cve_top_hit.score:.4f}")
    else:
        print("No CVE search results.")
    print("---------------------------------")


# --- Main Execution Function ---
def main():
    start_time = time.time()
    print("Starting CGRAG Data Loader")
    
    client = connect_to_qdrant()
    if not client:
        return
    
    model = get_embedding_model()
    if not model:
        return

    # Load data
    malware_ok = load_malware_data(client, model)
    cve_ok = load_cve_data(client, model)
    network_ok = load_network_data(client, model)

    # Check if all data loading was successful
    if all([malware_ok, cve_ok, network_ok]):
        print("\nAll data has been successfully saved to Qdrant.")
        
        # Run verification tests
        run_verification_tests(client, model)
    else:
        print("\nSome data failed to save. Please check the logs.")
        
    end_time = time.time()
    print(f"\nTotal execution time: {end_time - start_time:.2f} seconds")

if __name__ == '__main__':
    main()
