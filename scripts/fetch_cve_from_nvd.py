import requests
import os
import json
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("NVD_API_KEY")

def fetch_recent_cves(results_per_page=100):
    headers = {"apiKey": API_KEY}
    params = {
        "resultsPerPage": results_per_page,
        "startIndex": 0
    }
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    data = response.json()
    return data["vulnerabilities"]

def get_vendor_from_cve(cve_data):
    # Extract vendor information from the CVE data
    # This is a simplified example; real-world data can be complex
    try:
        return cve_data["cve"]["references"][0]["tags"][0]
    except (KeyError, IndexError):
        return "Unknown"

if __name__ == "__main__":
    print("Fetching recent CVEs from NVD...")
    cves = fetch_recent_cves(results_per_page=200) # Fetch 200 recent CVEs
    
    processed_data = []
    for cve_item in cves:
        cve = cve_item["cve"]
        # Basic severity check, adjust as needed
        severity = "unknown"
        if "cvssMetricV31" in cve.get("metrics", {}):
            severity = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]

        processed_entry = {
            "cve_id": cve["id"],
            "description": cve["descriptions"][0]["value"],
            "severity": severity,
            "published": cve["published"],
            "vendor": get_vendor_from_cve(cve_item),
            "category": "software" # Default category
        }
        processed_data.append(processed_entry)

    output_filename = "data/cve_database.json"
    os.makedirs(os.path.dirname(output_filename), exist_ok=True)
    with open(output_filename, "w") as f:
        json.dump(processed_data, f, indent=2)
        
    print(f"Successfully fetched and saved {len(processed_data)} CVEs to {output_filename}")
