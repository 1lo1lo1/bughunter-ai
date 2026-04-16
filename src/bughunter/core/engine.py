import asyncio
import aiohttp
from typing import List, Dict

class AsyncScanner:
    def __init__(self, concurrency: int = 50):
        self.concurrency = concurrency

    async def fetch(self, session: aiohttp.ClientSession, url: str):
        try:
            async with session.get(url, timeout=10, ssl=False) as response:
                return {
                    "url": url, 
                    "status": response.status, 
                    "content": await response.text(),
                    "headers": dict(response.headers)
                }
        except Exception as e:
            return {"url": url, "error": str(e)}

    async def run(self, urls: List[str]):
        connector = aiohttp.TCPConnector(limit_per_host=self.concurrency)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.fetch(session, url) for url in urls]
            return await asyncio.gather(*tasks)
