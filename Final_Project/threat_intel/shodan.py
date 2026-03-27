"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  FILE     : threat_intel/shodan.py                                          ║
║  PURPOSE  : Fetch host intelligence from Shodan API                         ║
║  USED BY  : threat_intel/aggregator.py                                      ║
║  REQUIRES : SHODAN_API_KEY in .env                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

HOW IT WORKS:
  1. Calls Shodan REST API for a given IP address
  2. Returns open ports, banners, org info, and country
  3. Falls back gracefully if key is missing or IP not indexed
"""

import requests
import os
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
SHODAN_BASE_URL = "https://api.shodan.io/shodan/host"


def get_shodan_data(ip: str) -> dict:
    """
    Fetch host information from Shodan for a given IP.

    Args:
        ip (str): Target IP address to look up

    Returns:
        dict: {
            "ports":       list of open ports Shodan has indexed,
            "banners":     list of service banner strings,
            "org":         organization name (ISP/hosting),
            "country":     country name,
            "hostnames":   list of associated hostnames,
            "vulns":       list of CVE IDs Shodan detected (if any),
            "tags":        Shodan tags e.g. ["self-signed", "vpn"],
            "source":      "shodan"
        }
        Returns a safe empty dict on any failure so the pipeline never crashes.
    """

    # ── No API key configured ──────────────────────────────────────────────
    if not SHODAN_API_KEY:
        print("[!] SHODAN_API_KEY not set in .env — skipping Shodan lookup")
        return _empty_result()

    url = f"{SHODAN_BASE_URL}/{ip}?key={SHODAN_API_KEY}"

    try:
        response = requests.get(url, timeout=10)

        # ── IP not in Shodan index ─────────────────────────────────────────
        if response.status_code == 404:
            print(f"[~] Shodan: no data for {ip}")
            return _empty_result()

        # ── API error ─────────────────────────────────────────────────────
        if response.status_code != 200:
            print(f"[!] Shodan API error: {response.status_code}")
            return _empty_result()

        data = response.json()

        # ── Extract banners (service info strings) ─────────────────────────
        banners = []
        for item in data.get("data", []):
            banner = item.get("data", "").strip()
            if banner:
                banners.append(banner[:200])     # cap length for storage

        return {
            "ports":     data.get("ports", []),
            "banners":   banners,
            "org":       data.get("org", "Unknown"),
            "country":   data.get("country_name", "Unknown"),
            "hostnames": data.get("hostnames", []),
            "vulns":     list(data.get("vulns", {}).keys()),   # CVE IDs
            "tags":      data.get("tags", []),
            "source":    "shodan"
        }

    except requests.exceptions.Timeout:
        print(f"[!] Shodan timeout for {ip}")
        return _empty_result()

    except Exception as e:
        print(f"[!] Shodan error for {ip}: {e}")
        return _empty_result()


def _empty_result() -> dict:
    """Returns a safe default when Shodan data is unavailable."""
    return {
        "ports":     [],
        "banners":   [],
        "org":       "Unknown",
        "country":   "Unknown",
        "hostnames": [],
        "vulns":     [],
        "tags":      [],
        "source":    "shodan"
    }