import requests
import os
from dotenv import load_dotenv
load_dotenv()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def get_ip_report(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": API_KEY
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            print(f"[!] API Error: {response.status_code}")
            return None

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        result = {
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }

        return result

    except Exception as e:
        print(f"[!] Error: {e}")
        return None