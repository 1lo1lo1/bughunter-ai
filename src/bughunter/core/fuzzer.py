import aiohttp

class ActiveFuzzer:
    def __init__(self):
        self.payloads = {
            "redirect": "https://bing.com", # თუ ბინგზე გადაგვიყვანა, ბაგია
            "xss": "<script>alert(1)</script>"
        }

    async def verify_redirect(self, base_url, param):
        test_url = f"{base_url}?{param}={self.payloads['redirect']}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(test_url, allow_redirects=False, timeout=5) as resp:
                    if resp.status in [301, 302] and "bing.com" in resp.headers.get('Location', ''):
                        return True, test_url
        except:
            pass
        return False, None
