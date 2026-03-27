def prioritize_ports(open_ports):
    critical_ports = [22, 21, 3389, 445]

    prioritized = []

    for p in open_ports:
        if p["port"] in critical_ports:
            priority = "HIGH"
        else:
            priority = "LOW"

        prioritized.append({
            "port": p["port"],
            "service": p["service"],
            "priority": priority
        })

    return prioritized