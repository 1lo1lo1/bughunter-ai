# 🛡️ BugHunter AI v3.5.0 — ilo Edition

AI-powered security auditing tool designed for Bug Bounty hunters and Security Researchers. Now with professional HTML reporting and advanced vulnerability detection.

## ✨ Key Features (v3.5.0 Update)
- 🌐 **Advanced Vuln Engine**: Automated detection for **SSTI**, **LFI**, and **Error-based SQLi**.
- 🔌 **Port Hunter**: Intelligent scanner for exposed databases (MySQL, Redis), SSH, FTP, and Jenkins.
- 📊 **Pro HTML Audit Reports**: Beautiful, categorized reports featuring **ilo** branding, PoC links, and exploit suggestions.
- 🎯 **Smart FP Filter**: Content-length and logic-based validation to eliminate False Positives.
- 🔎 **Subdomain Discovery**: High-speed OSINT discovery (crt.sh, JLDC, RapidDNS).
- 🤖 **AI Integration**: Local AI analysis using Ollama (Llama 3, Mistral).

## 🚀 Installation & Quick Start

```bash
# Clone the repository
git clone [https://github.com/1lo1lo1/bughunter-ai.git](https://github.com/1lo1lo1/bughunter-ai.git)
cd bughunter-ai

# Install in editable mode
pip install -e .
🛠️ Common CommandsCommandDescriptionExamplemass-huntFull audit: Subdomains + Ports + Vulnsbughunter mass-hunt target.comdiscoverFast subdomain OSINT discoverybughunter discover target.comscan-urlDeep scan specific URL for XSS/SSTI/CORSbughunter scan-url https://target.com
Command,Description,Example
mass-hunt,Full audit: Subdomains + Ports + Vulns,bughunter mass-hunt target.com
discover,Fast subdomain OSINT discovery,bughunter discover target.com
scan-url,Deep scan specific URL for XSS/SSTI/CORS,bughunter scan-url https://target.com
📄 License
MIT License — Created by ilo.
