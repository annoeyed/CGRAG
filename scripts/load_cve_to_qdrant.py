import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from src.qdrant_manager import SecurityQdrantManager
from sentence_transformers import SentenceTransformer
from tqdm import tqdm
import torch

def load_cve_data_to_qdrant(cve_file_path="data/cve_database.json"):
    """
    Loads CVE data from a JSON file, generates embeddings, and upserts into Qdrant.
    """
    # Initialize Qdrant manager and sentence transformer
    qdrant_manager = SecurityQdrantManager()
    encoder = SentenceTransformer("all-MiniLM-L6-v2", device="cuda" if torch.cuda.is_available() else "cpu")

    # Load CVE data from file
    with open(cve_file_path, "r") as f:
        cve_data = json.load(f)

    # Prepare data for Qdrant
    points_to_upsert = []
    
    # Using a list to batch descriptions for embedding
    descriptions = [item['description'] for item in cve_data]
    
    print(f"Generating embeddings for {len(descriptions)} CVE descriptions...")
    embeddings = encoder.encode(descriptions, show_progress_bar=True)

    print("Preparing data points for Qdrant...")
    for i, item in enumerate(tqdm(cve_data, desc="Processing CVEs")):
        payload = {
            "content": item["description"],
            "cve_id": item["cve_id"],
            "threat_level": item.get("severity", "unknown").lower(),
            "published_date": item.get("published", ""),
            "vendor": item.get("vendor", "unknown"),
            "category": "cve"
        }
        
        point = {
            "id": i,
            "vector": embeddings[i].tolist(),
            "payload": payload
        }
        points_to_upsert.append(point)

    # Upsert data into the 'threat_intel' collection
    if points_to_upsert:
        print(f"\nUpserting {len(points_to_upsert)} data points to 'threat_intel' collection...")
        qdrant_manager.client.upsert(
            collection_name=qdrant_manager.collections["threat_intel"],
            points=points_to_upsert,
            wait=True
        )
        print("CVE data successfully loaded into Qdrant.")
    else:
        print("No new CVE data to load.")

if __name__ == "__main__":
    load_cve_data_to_qdrant()
