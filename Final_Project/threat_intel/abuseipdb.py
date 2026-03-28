import requests
import os
from dotenv import load_dotenv
load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def get_abuse_data(ip):
    if not API_KEY:
        print("[!] ABUSEIPDB_API_KEY not set in .env")
        return {"abuse_score": 0}

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)

        if response.status_code != 200:
            print(f"[!] AbuseIPDB error: {response.status_code}")
            return {"abuse_score": 0}

        data = response.json()

        return {
            "abuse_score": data["data"]["abuseConfidenceScore"]
        }

    except Exception as e:
        print(f"[!] AbuseIPDB exception: {e}")
        return {"abuse_score": 0}
