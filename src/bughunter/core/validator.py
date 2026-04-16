import aiohttp

async def validate_xss(url: str, parameter: str):
    """ამოწმებს რეალურად სრულდება თუ არა XSS პეილოიდი"""
    poc_payload = "<script>confirm(1)</script>"
    test_url = f"{url}?{parameter}={poc_payload}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(test_url, timeout=5) as resp:
                body = await resp.text()
                if poc_payload in body:
                    return True, test_url
    except:
        pass
    return False, None

async def validate_cors(url: str):
    """ამოწმებს CORS Misconfiguration-ს (Credential Reflection)"""
    headers = {"Origin": "https://evil-hacker.com"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=5) as resp:
                origin = resp.headers.get("Access-Control-Allow-Origin")
                creds = resp.headers.get("Access-Control-Allow-Credentials")
                if origin == "https://evil-hacker.com" and creds == "true":
                    return True
    except:
        pass
    return False
