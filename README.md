# CGRAG: CyberGuard RAG

**CGRAG (CyberGuard RAG)** is an AI-powered cybersecurity threat detection and analysis system built on top of the **Qdrant** vector database, using **Retrieval-Augmented Generation (RAG)** techniques.

It enables fast similarity search across malware signatures, real-time detection of network anomalies, and intelligent querying of cyber threat intelligence (like CVEs), all backed by powerful language models.

---

## Features

- **Malware Similarity Detection**
  Identify similarity between incoming files and known malware signatures using vector embeddings.

- **Network Anomaly Detection**
  Learn typical network behavior and instantly detect abnormal or malicious traffic.

- **Cyber Threat Intelligence Retrieval**
  Use semantic search to extract relevant threat data from CVE datasets or other intelligence sources.

- **Real-Time RAG-Based Threat Analysis**
  Combine retrieval and generation for contextual security awareness and automated reasoning.

---

## Quick Start

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/annoeyed/CGRAG.git
cd CGRAG
pip install -r requirements.txt
```

### 2. Launch Qdrant
```bash
docker-compose up -d
```

### 3. Prepare Data
First, create the necessary collections in Qdrant.
```bash
python create_collections.py
```
Next, fetch the initial datasets.
```bash
python fetch_cve_from_nvd.py
python fetch_network_logs.py
```
Finally, load the data into Qdrant.
```bash
python load_data_to_qdrant.py
```


### 4. Run the System
```bash
python main.py
```

---
## Usage Examples

You can test the system by running the `test_query.py` script. It allows you to pass a query directly from the command line.

### Malware Analysis
```bash
python test_query.py "Analyze ransomware similar to WannaCry"
```

### CVE Information Retrieval
```bash
python test_query.py "Find vulnerabilities related to Apache Log4j"
```

---

## Architecture

- **Qdrant** – High-performance vector DB for storing and querying embeddings
- **Sentence Transformers** – Semantic embedding of malware descriptions, logs, CVE entries
- **Custom Security Modules** – Malware classification, anomaly detection, CVE similarity search

---

## Performance (Sample)

| Feature                | Result      |
|------------------------|-------------|
| Malware Detection Acc. | 94%+        |
| Query Latency          | < 100 ms    |
| Anomaly Detection      | Real-time   |

---

## Contributing

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

## License

This project is licensed under the **MIT License**.
See the `LICENSE` file for full details.
