# Contributing to BugHunter AI

Thank you for helping make security tooling free and accessible! 🐛

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/bughunter-ai.git
cd bughunter-ai
pip install -e ".[dev]"
```

## Adding New Vulnerability Patterns

Edit `src/bughunter/analyzers/patterns.py` and add to the `PATTERNS` list:

```python
{
    "id": "MYCHECK-001",
    "type": "my_vuln_type",
    "category": VulnCategory.INJECTION,
    "severity": Severity.HIGH,
    "title": "My Vulnerability Title",
    "pattern": r'your_regex_here',
    "description": "What this vulnerability is",
    "impact": "What damage it can cause",
    "recommendation": "How to fix it",
    "cwe": "CWE-XXX",
    "owasp": "A0X:2021 ...",
    "languages": ["python", "javascript"],
},
```

## Adding New Secret Patterns

Edit `src/bughunter/analyzers/secrets.py` and add to `SECRET_PATTERNS`:

```python
("SECRETS-MYSERVICE", r'your_regex', "Service Name Token", Severity.HIGH),
```

## Submitting Pull Requests

1. Fork the repo
2. Create a branch: `git checkout -b feat/my-new-check`
3. Make your changes
4. Test: `pytest tests/`
5. Open a PR with a clear description

## Code Style

- Black formatting: `black src/`
- Lint: `ruff check src/`

## Reporting Issues

Open an issue on GitHub with:
- Description of the false positive / missed vulnerability
- Code sample (anonymized)
- Expected behavior
