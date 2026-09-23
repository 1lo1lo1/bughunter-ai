# 🛡️ BugHunter AI

**An experimental Python toolkit for authorized security research.**

The current CLI combines passive subdomain discovery, active web checks, common-port inspection, and HTML reporting. Its output is a starting point for investigation, not proof of a vulnerability.

[Releases](https://github.com/1lo1lo1/bughunter-ai/releases) · [Report an issue](https://github.com/1lo1lo1/bughunter-ai/issues) · [MIT License](LICENSE)

## Current capabilities

| Component | What the current CLI does |
| --- | --- |
| Discovery | Queries JLDC and AlienVault; falls back to crt.sh when fewer than five hosts are found |
| Web checks | Runs directory/exposure checks, basic LFI/SSTI/SQL-error probes, and security-header checks |
| Ports | Checks a predefined set of service ports |
| Reporting | Prints single-URL results; generates a grouped HTML report for the mass-hunt workflow |

The repository also contains static-analysis components and optional AI adapters. **The current `hunt` and `mass-hunt` commands do not invoke those AI adapters.**

## Installation

Requires **Python 3.10 or newer**. The following setup uses Linux, macOS, or WSL:

```bash
git clone https://github.com/1lo1lo1/bughunter-ai.git
cd bughunter-ai
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
# Current packaging workaround: the live CLI imports these undeclared dependencies.
python -m pip install aiohttp requests
bughunter --help
```

The extra installation step is needed until the package dependency declarations are corrected.

## Usage

Use only assets you own or have explicit permission to test. The commands below make active requests and check ports. Replace the reserved example domains with an authorized target.

### Inspect the available commands

```bash
bughunter --help
bughunter hunt --help
bughunter mass-hunt --help
```

### Check a single URL

```bash
bughunter hunt https://app.example.com
```

Results are printed to the terminal.

### Discover and check subdomains

```bash
bughunter mass-hunt example.com
```

This discovers hostnames, checks **up to 50** of them over HTTPS, and writes `report_example_com.html` in the current directory when hosts are found. Host selection is not deterministic because discovery results come from a set.

The current CLI does not expose the older `discover`, `scan-url`, or `scan` commands.

## Interpreting results

- Pattern matches are **candidate findings** that require independent validation.
- A missing security header or open port does not, by itself, demonstrate exploitable impact.
- The report's current “Verified Findings” label does not mean that verification occurred.
- No measured false-positive reduction or independently verified benchmark is claimed.

## Known limitations

- There is no dedicated scope allowlist/exclusion control in the current CLI. Use mass-hunt only when all discovered hosts and the active checks are explicitly covered by authorization.
- Broad exception handling can hide failed checks; an empty result is not assurance that a target is secure.
- The 50-host limit and concurrency behavior are fixed in code.
- The static-analysis API and existing test suite need repair before they can serve as a reliable release gate.
- AI-assisted analysis is not connected to the live CLI workflow.
- Report rendering needs hardening before reports containing untrusted data should be shared.

## Development and contributions

```bash
python -m pip install -e ".[dev]"
python -m compileall -q src
python -m pytest -q
```

The existing test suite has known failures; these commands are provided for diagnosis, not as a claim that the current release passes.

Useful contributions include dependency fixes, scope enforcement, reliable error reporting, offline regression tests, and report-rendering improvements. Include a reproducible local example and sanitized output with bug reports.

## License

[MIT](LICENSE).

---

Built by [Ilo](https://github.com/1lo1lo1) · [TryHackMe](https://tryhackme.com/p/1lo) · [LinkedIn](https://linkedin.com/in/1lo)
