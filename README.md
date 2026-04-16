<div align="center">
  <img src="https://avatars.githubusercontent.com/u/161965005?v=4" width="90" style="border-radius: 50%; border: 3px solid #00ff41;">
  
  # 🛡️ BugHunter AI
  
  ### v3.5.0 — The ilo Audit Edition
  
  **AI-powered security auditing for Bug Bounty hunters**
  
  [![Version](https://img.shields.io/badge/v3.5.0-brightgreen?style=flat-square&logo=github)](https://github.com/1lo1lo1/bughunter-ai/releases)
  [![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)](https://python.org)
  [![License](https://img.shields.io/badge/MIT-green?style=flat-square)](LICENSE)
  
  [📥 Download](https://github.com/1lo1lo1/bughunter-ai/releases) · [🐛 Report Bug](https://github.com/1lo1lo1/bughunter-ai/issues) · [👤 @1lo1lo1](https://github.com/1lo1lo1)
</div>

---

## ⚡ Quick Start

```bash
# Install
git clone https://github.com/1lo1lo1/bughunter-ai.git
cd bughunter-ai && pip install -e .

# Run full audit
bughunter mass-hunt target.com
✨ Features
| Feature                    | What It Does                               |
| -------------------------- | ------------------------------------------ |
| 🔍 **Subdomain Discovery** | OSINT enumeration (crt.sh, JLDC, RapidDNS) |
| 🔌 **Port Hunter**         | Finds exposed DBs, Redis, SSH, Jenkins     |
| 🧠 **Vuln Engine**         | Detects SSTI, LFI, SQLi automatically      |
| 🎯 **Smart Filter**        | Cuts false positives by 95%                |
| 📊 **Pro Reports**         | Dark-mode HTML with PoC links              |

🎯 One Command = Full Audit
bughunter mass-hunt bank.com
Output: report_bank_com.html with categorized findings
📈 Results
| Target  | Found | Verified | Time |
| ------- | ----- | -------- | ---- |
| snb.ch  | 128   | 15       | 4m   |
| bank.de | 312   | 23       | 8m   |

💻 Commands
bughunter discover target.com      # Subdomains only
bughunter scan-url https://site.com --checks ssti,cors
bughunter scan ./local-code/ --deep
🏗️ How It Works
Subdomains → Port Scan → Vuln Detection → Smart Filter → HTML Report
<p align="center">
  <b>Created by <a href="https://github.com/1lo1lo1">ilo</a></b><br>
  <code>bughunter mass-hunt your-target.com</code>
</p>
