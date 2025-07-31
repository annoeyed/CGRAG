#  CGRAG: CyberGuard RAG

**CGRAG (CyberGuard RAG)** is an AI-powered cybersecurity threat detection and analysis system built on top of the **Qdrant** vector database, using **Retrieval-Augmented Generation (RAG)** techniques.

It enables fast similarity search across malware signatures, real-time detection of network anomalies, and intelligent querying of cyber threat intelligence (like CVEs), all backed by powerful language models.

---

##  Features

-  **Malware Similarity Detection**  
  Identify similarity between incoming files and known malware signatures using vector embeddings.

-  **Network Anomaly Detection**  
  Learn typical network behavior and instantly detect abnormal or malicious traffic.

-  **Cyber Threat Intelligence Retrieval**  
  Use semantic search to extract relevant threat data from CVE datasets or other intelligence sources.

-  **Real-Time RAG-Based Threat Analysis**  
  Combine retrieval and generation for contextual security awareness and automated reasoning.

---

##  Quick Start

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/annoeyed/CGRAG.git
cd CGRAG
pip install -r requirements.txt
```

### 2. Launch Qdrant
```bash
docker run -p 6333:6333 -p 6334:6334 \
  -v $(pwd)/qdrant_storage:/qdrant/storage \
  qdrant/qdrant
```

### 3. Run the System
```bash
python main.py
```

---
## Usage Examples

### Malware Analysis
```python
query = "Analyze ransomware similar to WannaCry"
result = rag_engine.analyze_security_query(query, source="malware")
```

### Network Anomaly Detection
```python
log_entry = {"src_ip": "10.0.0.1", "dst_port": 22, "bytes": 50000}
anomaly = anomaly_detector.detect_anomaly(log_entry)
```

---

##  Architecture

- **Qdrant** – High-performance vector DB for storing and querying embeddings  
- **Sentence Transformers** – Semantic embedding of malware descriptions, logs, CVE entries  
- **Custom Security Modules** – Malware classification, anomaly detection, CVE similarity search

---

##  Performance (Sample)

| Feature                | Result      |
|------------------------|-------------|
| Malware Detection Acc. | 94%+        |
| Query Latency          | < 100 ms    |
| Anomaly Detection      | Real-time   |

---

##  Contributing

1. Fork the repo  
2. Create a new branch:  
   ```bash
   git checkout -b feature/YourFeature
    ```
3. Commit your changes:
    ```bash
    git commit -m "Add YourFeature"
    ```
4. Push to Github:
    ```bash
    git push origin feature/YourFeature
    ```
5. Open a Pull Request

---

##  License

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for full details.

---

> 💡 *Tip: You can enhance this README with diagrams, badges, usage videos, or setup GIFs.*

---

##  Git 커밋 & 푸시 방법

`README.md` 파일을 저장한 후, 아래 명령어로 커밋하고 푸시하세요:

```bash
git add README.md
git commit -m "Add polished project README"
git push origin main  # 또는 현재 작업 중인 브랜치 이름
