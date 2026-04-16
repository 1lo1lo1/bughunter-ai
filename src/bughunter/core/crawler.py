import re
from urllib.parse import urljoin, urlparse

class SmartCrawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc

    def extract_links(self, html_content):
        """ამოიღებს ყველა JS ფაილის ლინკს"""
        # ეძებს <script src="...">
        js_links = re.findall(r'src=["\'](.*?\.js.*?)["\']', html_content)
        full_links = [urljoin(self.base_url, link) for link in js_links]
        return list(set(full_links))

    def extract_endpoints(self, text_content):
        """ამოიღებს პოტენციურ API ენდპოინტებს JS კოდიდან"""
        # ეძებს რაღაცას რაც ჰგავს გზას: /api/v1/user ან /config/db
        endpoints = re.findall(r'["\'](/[a-zA-Z0-9\._\-/]+)["\']', text_content)
        # ვფილტრავთ მხოლოდ იმას, რაც გზას ჰგავს და არა უბრალო ტექსტს
        valid_endpoints = [e for e in endpoints if '/' in e and len(e) > 2]
        return list(set(valid_endpoints))
