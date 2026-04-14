# Changelog

## [2.2.0] - 2026-04-14

### ✨ New Features
- **Live URL Scanner** (`scan-url` command) — Auto-download & scan any website
- **Progress indicators** — Rich progress bars for downloads and scans
- **HTML/JSON/Markdown reports** — Multiple output formats

### 🐛 Bug Fixes
- **Fix analyzer.py syntax error** — Line 185 vuln_id indentation
- **Fix cli.py missing imports** — Add tempfile, subprocess, urlparse
- **Fix scan-url command** — Proper integration with core scanner

### 🛠️ Improvements
- **Better error handling** — Try/except blocks for network operations
- **Fallback mode** — Single-page download if mirror fails
- **Download timeout** — 300s limit with progress feedback

### 🔧 Technical
- Updated ScanConfig parameters (target, use_ai, checks)
- Fixed Vulnerability dataclass initialization
- Added wget integration with depth control (1-5)

## [2.1.0] - 2026-04-14 [YANKED]

⚠️ This release had critical bugs and was replaced by 2.2.0

## [2.0.0] - 2026-04-14 [YANKED]

⚠️ This release had syntax errors and was replaced by 2.2.0

## [1.0.0] - 2026-04-13

### 🎉 Initial Release
- Static analysis engine (SAST)
- Pattern matching: CORS, SQLi, XSS, SSRF
- Secrets detection (25+ types)
- AI-powered analysis (OpenAI/Ollama)
- Multiple output formats: HTML, JSON, SARIF, Markdown
- False positive filter
- Interactive mode
