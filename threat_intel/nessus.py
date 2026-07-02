import requests
import json
import os
import time
from dotenv import load_dotenv

load_dotenv()

NESSUS_URL = os.getenv("NESSUS_URL", "https://localhost:8834")
NESSUS_ACCESS_KEY = os.getenv("NESSUS_ACCESS_KEY", "")
NESSUS_SECRET_KEY = os.getenv("NESSUS_SECRET_KEY", "")

class NessusClient:
    """
    Boilerplate client for interacting with the Tenable Nessus Professional REST API.
    Provides methods to launch scans and export vulnerability reports.
    Requires Access and Secret keys to be set in the environment or .env file.
    """
    
    def __init__(self):
        self.headers = {
            "X-ApiKeys": f"accessKey={NESSUS_ACCESS_KEY}; secretKey={NESSUS_SECRET_KEY}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        # Suppress SSL warnings if Nessus uses a self-signed cert
        requests.packages.urllib3.disable_warnings()

    def get_scan_list(self) -> dict:
        """Retrieves a list of all configured scans."""
        try:
            url = f"{NESSUS_URL}/scans"
            response = requests.get(url, headers=self.headers, verify=False, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}", "details": response.text}
        except Exception as e:
            return {"error": "Connection Failed", "details": str(e)}

    def launch_scan(self, scan_id: int) -> dict:
        """Launches a specific scan by ID and returns the scan UUID."""
        try:
            url = f"{NESSUS_URL}/scans/{scan_id}/launch"
            response = requests.post(url, headers=self.headers, verify=False, timeout=10)
            if response.status_code == 200:
                return {"status": "success", "scan_uuid": response.json().get("scan_uuid")}
            else:
                return {"error": f"Failed to launch. HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def export_report(self, scan_id: int) -> dict:
        """
        Exports the latest scan results in Nessus format.
        Note: This is an asynchronous process in the real API (Export -> Status -> Download).
        This boilerplate demonstrates the initial export trigger.
        """
        try:
            url = f"{NESSUS_URL}/scans/{scan_id}/export"
            payload = {"format": "nessus"}
            response = requests.post(url, headers=self.headers, json=payload, verify=False, timeout=10)
            if response.status_code == 200:
                return {"status": "export_started", "file_id": response.json().get("file")}
            else:
                return {"error": f"Export failed. HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

if __name__ == "__main__":
    # Example usage
    client = NessusClient()
    print("[*] Nessus Boilerplate Initialized.")
    if NESSUS_ACCESS_KEY:
        print(client.get_scan_list())
    else:
        print("[!] Missing NESSUS_ACCESS_KEY in environment.")
