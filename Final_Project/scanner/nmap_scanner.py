import nmap

def scan_target(target_ip):
    scanner = nmap.PortScanner()

    print(f"\n[+] Scanning target: {target_ip}...\n")

    try:
        scanner.scan(hosts=target_ip, arguments='-sV -T4')

        final_results = []

        for host in scanner.all_hosts():
            host_data = {
                "ip": host,
                "state": scanner[host].state(),
                "open_ports": [],
                "total_open_ports": 0
            }

            # 🔍 Collect open ports FIRST
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()

                for port in ports:
                    port_data = scanner[host][proto][port]

                    if port_data['state'] == 'open':
                        host_data["open_ports"].append({
                            "port": port,
                            "service": port_data['name']
                        })

            # ✅ THEN calculate total
            host_data["total_open_ports"] = len(host_data["open_ports"])

            final_results.append(host_data)

        return final_results

    except Exception as e:
        print(f"[!] Error: {e}")
        return None