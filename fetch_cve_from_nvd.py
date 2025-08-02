import requests
import os
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

if __name__ == "__main__":
    cves = fetch_recent_cves()
    for cve in cves[:5]:
        print(cve["cve"]["id"], "-", cve["cve"]["descriptions"][0]["value"])
