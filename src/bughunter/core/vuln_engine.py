import aiohttp
import asyncio

class VulnEngine:
    def __init__(self):
        # განვსაზღვროთ სხვადასხვა ტიპის ბაგების პეილოიდები და რას უნდა ველოდოთ პასუხში
        self.payloads = {
            "LFI": {
                "paths": ["/etc/passwd", "/windows/win.ini"],
                "match": ["root:x:0:0:", "[extensions]"]
            },
            "SSTI": {
                "paths": ["/{{7*7}}", "/${7*7}"],
                "match": ["49"]
            },
            "SQLi": {
                "paths": ["' OR 1=1 --", "') OR ('1'='1"],
                "match": ["SQL syntax", "mysql_fetch", "PostgreSQL query failed"]
            }
        }

    async def check_vuln(self, session, base_url):
        findings = []
        for vuln_type, data in self.payloads.items():
            for path in data["paths"]:
                url = f"{base_url}{path}"
                try:
                    async with session.get(url, timeout=4) as resp:
                        text = await resp.text()
                        for match_str in data["match"]:
                            if match_str in text:
                                findings.append({
                                    "type": f"Critical: {vuln_type} Detected",
                                    "val": f"Exploit URL: {url}",
                                    "severity": "critical",
                                    "poc": url
                                })
                except:
                    pass
        return findings

    async def check_headers(self, session, url):
        # ვამოწმებთ აკლია თუ არა უსაფრთხოების ჰედერები
        findings = []
        try:
            async with session.head(url, timeout=4) as resp:
                headers = resp.headers
                missing = []
                if "Content-Security-Policy" not in headers: missing.append("CSP")
                if "X-Frame-Options" not in headers: missing.append("X-Frame-Options (Clickjacking)")
                
                if missing:
                    findings.append({
                        "type": "Missing Security Headers",
                        "val": f"Missing: {', '.join(missing)}",
                        "severity": "low",
                        "poc": url
                    })
        except:
            pass
        return findings
