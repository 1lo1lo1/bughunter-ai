"""
Subdomain Discovery Module for BugHunter AI
OSINT-based subdomain enumeration using multiple sources
Uses requests instead of aiohttp for simplicity
"""
import requests
import json
import re
from typing import Set, List, Optional
from dataclasses import dataclass
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class SubdomainResult:
    """Subdomain discovery result"""
    domain: str
    source: str  # crt.sh, jldc, rapiddns, etc.
    discovered_at: datetime
    is_live: Optional[bool] = None
    ip_address: Optional[str] = None


class SubdomainDiscovery:
    """Subdomain discovery using OSINT sources"""
    
    def __init__(self, target: str, timeout: int = 30):
        self.target = target.lower().strip()
        self.timeout = timeout
        self.subdomains: Set[str] = set()
        self.results: List[SubdomainResult] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def discover_all(self) -> List[SubdomainResult]:
        """Run all discovery methods concurrently"""
        
        # Run all sources in parallel using ThreadPoolExecutor
        sources = [
            (self._crt_sh, "crt.sh"),
            (self._jldc, "jldc.me"),
            (self._rapiddns, "rapiddns.io"),
            (self._anubis, "anubis"),
        ]
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(func): name for func, name in sources}
            
            for future in as_completed(futures):
                name = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"[{name}] Error: {e}")
        
        # Convert to results
        for subdomain in sorted(self.subdomains):
            self.results.append(SubdomainResult(
                domain=subdomain,
                source="osint_aggregate",
                discovered_at=datetime.now()
            ))
        
        return self.results
    
    def _crt_sh(self):
        """Query crt.sh Certificate Transparency logs"""
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # Split multiple domains and clean
                    for domain in name_value.split('\n'):
                        domain = domain.strip().lower()
                        if domain and domain.endswith(self.target):
                            # Remove wildcards
                            domain = domain.replace('*.', '')
                            if domain and domain != self.target:
                                self.subdomains.add(domain)
        except Exception as e:
            print(f"[crt.sh] Error: {e}")
    
    def _jldc(self):
        """Query JLDC.me Anubis API"""
        try:
            url = f"https://jldc.me/anubis/subdomains/{self.target}"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    for subdomain in data:
                        subdomain = subdomain.strip().lower()
                        if subdomain and subdomain.endswith(self.target):
                            self.subdomains.add(subdomain)
        except Exception as e:
            print(f"[jldc] Error: {e}")
    
    def _rapiddns(self):
        """Query RapidDNS.io"""
        try:
            url = f"https://rapiddns.io/subdomain/{self.target}?full=1"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                html = response.text
                # Extract subdomains using regex
                pattern = re.compile(r'([a-z0-9_-]+\.' + re.escape(self.target) + r')')
                matches = pattern.findall(html)
                for match in matches:
                    subdomain = match.lower().strip()
                    if subdomain and subdomain != self.target:
                        self.subdomains.add(subdomain)
        except Exception as e:
            print(f"[rapiddns] Error: {e}")
    
    def _anubis(self):
        """Query Anubis API via jldc"""
        # Already covered by _jldc, but kept for extensibility
        pass
    
    def save_to_file(self, filename: str):
        """Save discovered subdomains to file"""
        with open(filename, 'w') as f:
            for result in sorted(self.results, key=lambda x: x.domain):
                f.write(f"{result.domain}\n")
        
    def get_summary(self) -> dict:
        """Get discovery summary"""
        return {
            'target': self.target,
            'total_found': len(self.subdomains),
            'sources_checked': ['crt.sh', 'jldc.me', 'rapiddns.io'],
            'discovered_at': datetime.now().isoformat()
        }


def discover_subdomains(target: str, output_file: Optional[str] = None) -> dict:
    """Main function for subdomain discovery"""
    from rich.console import Console
    console = Console()
    
    console.print(f"[bold blue]🔍 Discovering subdomains for:[/bold blue] {target}")
    
    discovery = SubdomainDiscovery(target)
    results = discovery.discover_all()
    
    summary = discovery.get_summary()
    
    if output_file:
        discovery.save_to_file(output_file)
        console.print(f"[green]✅ Saved to:[/green] {output_file}")
    
    # Display results
    if results:
        console.print(f"\n[bold green]🎯 Found {len(results)} subdomains:[/bold green]")
        for result in results[:20]:  # Show first 20
            console.print(f"  • {result.domain}")
        if len(results) > 20:
            console.print(f"  ... and {len(results) - 20} more")
    else:
        console.print("[yellow]⚠️ No subdomains found[/yellow]")
    
    return summary
