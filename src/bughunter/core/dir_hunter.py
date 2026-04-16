import aiohttp
import asyncio

class DirHunter:
    def __init__(self):
        self.sensitive_files = [
            ".git/config", ".env", "phpinfo.php", "config.php.bak", 
            ".aws/credentials", "robots.txt", ".htaccess", "server-status"
        ]

    async def scan(self, base_url):
        findings = []
        async with aiohttp.ClientSession() as session:
            for file in self.sensitive_files:
                url = f"{base_url.rstrip('/')}/{file}"
                try:
                    async with session.get(url, timeout=5, allow_redirects=False) as resp:
                        # მხოლოდ 200 OK და არა გადამისამართება
                        if resp.status == 200:
                            content = await resp.text()
                            # ვალიდაცია: ფაილი არ უნდა იყოს ძალიან პატარა და არ უნდა შეიცავდეს HTML-ს (გარდა phpinfo-სი)
                            if len(content) > 20 and ("<html" not in content.lower() or "phpinfo" in file):
                                findings.append({
                                    "type": "Sensitive File Found",
                                    "val": url,
                                    "severity": "high",
                                    "poc": url
                                })
                except:
                    pass
        return findings
