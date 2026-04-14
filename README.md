# 🐛 BugHunter AI

AI-powered security bug hunting tool for bug bounty hunters and security researchers.

[![Version](https://img.shields.io/badge/version-2.3.1-blue)](https://github.com/1lo1lo1/bughunter-ai)
[![Python](https://img.shields.io/badge/python-3.8+-green)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)

## ✨ Features

- 🔍 **Static Analysis (SAST)** — Scan local code for vulnerabilities
- 🌐 **Live URL Scanner** — Auto-download and scan any website
- 🔎 **Subdomain Discovery** — Find subdomains via OSINT (crt.sh, JLDC, RapidDNS)
- 🤖 **AI-Powered Analysis** — Local AI with Ollama integration
- 🎯 **False Positive Filter** — Smart filtering reduces noise
- 📊 **Multiple Output Formats** — HTML, JSON, Markdown

## 🚀 Quick Start

```bash
# Install
git clone https://github.com/1lo1lo1/bughunter-ai.git
cd bughunter-ai
pip install -e .

# Scan local files
bughunter scan ./my-project/ --deep --ai

# Scan live website
bughunter scan-url https://target.com --checks cors,secrets,xss --depth 2

# Discover subdomains
bughunter discover target.com --output subdomains.txt

# AI-powered analysis
bughunter scan-url https://target.com --ai --model ollama:llama3
