from scanner.nmap_scanner import scan_target
from threat_intel.virustotal import get_ip_report
from risk.risk_score import calculate_risk

if __name__ == "__main__":
    target = input("Enter IP or domain: ")

    scan_results = scan_target(target)

    print("\n=== Final Security Analysis ===\n")

    for host in scan_results:
        ip = host["ip"]

        vt_data = get_ip_report(ip)

        print(f"IP: {ip}")
        print(f"State: {host['state']}")
        print(f"Total Open Ports: {host['total_open_ports']}")

        print("\nOpen Ports:")
        for port in host["open_ports"]:
            print(f"  - {port['port']} ({port['service']})")

        if vt_data:
            malicious = vt_data["malicious"]
            suspicious = vt_data["suspicious"]

            print("\n--- Threat Intelligence ---")
            print(f"Malicious: {malicious}")
            print(f"Suspicious: {suspicious}")
            print(f"Harmless: {vt_data['harmless']}")

            # 🔥 Risk calculation
            score, level = calculate_risk(
                host["total_open_ports"],
                malicious,
                suspicious
            )

            print("\n--- Risk Assessment ---")
            print(f"Risk Score: {score}")
            print(f"Risk Level: {level}")

        else:
            print("\n[!] No threat data available")

        print("\n============================\n")