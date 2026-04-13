# 🐛 BugHunter AI

<div align="center">

```
██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗      █████╗ ██╗
██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗    ██╔══██╗██║
██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝    ███████║██║
██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗    ██╔══██║██║
██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║    ██║  ██║██║
╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝
```

**The Open-Source AI-Powered Security Bug Hunter — Better than Penligent, Free Forever**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?logo=kalilinux)](https://kali.org)
[![Free](https://img.shields.io/badge/Price-FREE-brightgreen)](https://github.com)

</div>

---

## 🚀 What is BugHunter AI?

BugHunter AI is a **free, open-source** CLI tool for Kali Linux that uses AI to automatically find security bugs, vulnerabilities, and logic flaws in source code. It was built as a superior alternative to Penligent — giving you the same power (and more) at zero cost.

**Found a CORS bug in 15 minutes with Penligent?** BugHunter AI will find it in 2.

---

## ✨ Features vs Penligent

| Feature | BugHunter AI | Penligent |
|---------|:---:|:---:|
| Price | ✅ **FREE** | ❌ Paid |
| Open Source | ✅ | ❌ |
| Local AI (no data leak) | ✅ Ollama | ❌ |
| Cloud AI (OpenAI/Anthropic) | ✅ | ✅ |
| CORS Detection | ✅ | ✅ |
| SQLi Detection | ✅ | ✅ |
| XSS Detection | ✅ | ✅ |
| SSRF Detection | ✅ | ✅ |
| Path Traversal | ✅ | ✅ |
| Business Logic Bugs | ✅ | ⚠️ |
| Auth/AuthZ Flaws | ✅ | ⚠️ |
| Cryptography Flaws | ✅ | ❌ |
| Hardcoded Secrets | ✅ | ⚠️ |
| SARIF Report Output | ✅ | ✅ |
| HTML Report | ✅ | ✅ |
| JSON/Markdown Report | ✅ | ❌ |
| Multi-language Support | ✅ 12 langs | ⚠️ |
| False Positive Filter | ✅ AI-powered | ⚠️ |
| Plugin System | ✅ | ❌ |
| Offline Mode | ✅ | ❌ |

---

## 🛠️ Installation

### Quick Install (Kali Linux)

```bash
git clone https://github.com/1lo1lo1/bughunter-ai.git
cd bughunter-ai
chmod +x scripts/install.sh
./scripts/install.sh
```

### Manual Install

```bash
git clone https://github.com/1lo1lo1/bughunter-ai.git
cd bughunter-ai
pip install -e ".[all]"
bughunter --help
```

---

## 🎯 Quick Usage

```bash
# Scan a single file
bughunter scan app.py

# Scan entire project
bughunter scan ./my-webapp/ --deep

# Scan with AI analysis (requires API key or Ollama)
bughunter scan ./src/ --ai --model gpt-4o

# Use local AI (free, no API key needed)
bughunter scan ./src/ --ai --model ollama:llama3

# Generate HTML report
bughunter scan ./src/ --output report.html --format html

# Scan for specific vuln types
bughunter scan ./src/ --checks cors,sqli,xss,ssrf

# Live monitoring mode
bughunter watch ./src/ --ai

# Show CVE references for found bugs
bughunter scan ./src/ --cve-lookup

# Interactive mode (best for beginners)
bughunter interactive
```

---

## 🧠 How It Works

```
Source Code
    │
    ▼
┌─────────────────────────────────────────┐
│           Static Analysis Engine        │
│  ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│  │ Pattern  │ │ AST/CFG  │ │  Taint  │ │
│  │ Matching │ │ Analysis │ │ Tracker │ │
│  └──────────┘ └──────────┘ └─────────┘ │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│            AI Analysis Layer            │
│  ┌──────────────┐  ┌───────────────┐   │
│  │  Local AI    │  │  Cloud AI     │   │
│  │  (Ollama)    │  │  (OpenAI/     │   │
│  │  FREE        │  │   Anthropic)  │   │
│  └──────────────┘  └───────────────┘   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│         False Positive Filter           │
│      Reduces noise by ~95%              │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│           Report Generator              │
│   HTML │ JSON │ SARIF │ Markdown        │
└─────────────────────────────────────────┘
```

---

## 📋 Supported Languages

Python, JavaScript, TypeScript, PHP, Java, Go, Ruby, C, C++, Rust, Swift, Kotlin

---

## 📄 License

MIT License — Free forever. See [LICENSE](LICENSE).

---

## 🤝 Contributing

PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

---

<div align="center">
Built with ❤️ as a free alternative to Penligent
</div>
