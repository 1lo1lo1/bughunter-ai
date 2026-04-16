import asyncio
import socket

class PortScanner:
    def __init__(self):
        # პორტების რუკა უფრო კონკრეტული სახელებისთვის
        self.port_map = {
            21: "Exposed FTP Service",
            22: "Open SSH Management Port",
            3306: "Exposed MySQL Database",
            6379: "Unprotected Redis Cache",
            8080: "Exposed Web Proxy/Jenkins",
            8443: "Exposed SSL Management Alt"
        }

    async def check_port(self, ip, port):
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1.5)
            writer.close()
            await writer.wait_closed()
            return True, port
        except:
            return False, port

    async def scan(self, domain):
        findings = []
        try:
            ip = socket.gethostbyname(domain)
            tasks = [self.check_port(ip, port) for port in self.port_map.keys()]
            results = await asyncio.gather(*tasks)
            for is_open, port in results:
                if is_open:
                    port_name = self.port_map.get(port, f"Open Port {port}")
                    findings.append({
                        "type": port_name,
                        "val": f"IP: {ip} | Port: {port}",
                        "severity": "critical" if port in [3306, 6379] else "high",
                        "poc": f"http://{ip}:{port}" # ეს აღარ გამოიწვევს ERR_FILE_NOT_FOUND
                    })
        except:
            pass
        return findings
