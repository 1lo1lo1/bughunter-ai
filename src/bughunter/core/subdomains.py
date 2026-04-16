import requests
import re

class SubdomainFinder:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()

    def from_crtsh(self):
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            res = requests.get(url, timeout=15)
            if res.status_code == 200:
                for item in res.json():
                    name = item['name_value']
                    for sub in name.split('\n'):
                        if sub.endswith(self.domain) and '*' not in sub:
                            self.subdomains.add(sub.strip().lower())
        except: pass

    def from_jldc(self):
        try:
            url = f"https://jldc.me/anubis/subdomains/{self.domain}"
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                for sub in res.json():
                    self.subdomains.add(sub.strip().lower())
        except: pass

    def from_alienvault(self):
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                for item in res.json().get('passive_dns', []):
                    sub = item.get('hostname')
                    if sub and sub.endswith(self.domain):
                        self.subdomains.add(sub.strip().lower())
        except: pass

    def find_all(self):
        print(f"🔍 Hunting subdomains for {self.domain} using 3 sources...")
        self.from_jldc()
        self.from_alienvault()
        # crt.sh-ს ბოლოს ვუშვებთ რადგან ნელია
        if len(self.subdomains) < 5:
            self.from_crtsh()
            
        final_list = list(self.subdomains)
        print(f"✅ Success! Found {len(final_list)} unique subdomains.")
        return final_list
