import asyncio
from .core.engine import AsyncScanner
from .core.dir_hunter import DirHunter
from .core.vuln_engine import VulnEngine
from .core.port_scanner import PortScanner
import aiohttp

class BugHunterCore:
    def __init__(self):
        self.dir_hunter = DirHunter()
        self.vuln_engine = VulnEngine()
        self.port_scanner = PortScanner()

    async def scan_target(self, url: str):
        findings = []
        
        async with aiohttp.ClientSession() as session:
            # 1. ფაილების ძებნა
            findings.extend(await self.dir_hunter.scan(url))
            
            # 2. სერიოზული ბაგების ძებნა (LFI, SQLi, SSTI)
            findings.extend(await self.vuln_engine.check_vuln(session, url))
            
            # 3. ჰედერების შემოწმება
            findings.extend(await self.vuln_engine.check_headers(session, url))

        # 4. პორტების სკანირება
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        findings.extend(await self.port_scanner.scan(domain))

        return findings
