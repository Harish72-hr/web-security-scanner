import nmap


def scan_ports(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-F')

        ports = []

        for host in nm.all_hosts():
            for protocol in nm[host].all_protocols():
                for port in nm[host][protocol]:

                    service = nm[host][protocol][port]['name']

                    ports.append({
                        "port": port,
                        "service": service
                    })

        return ports

    except Exception as e:
        return [{"port": "Error", "service": str(e)}]