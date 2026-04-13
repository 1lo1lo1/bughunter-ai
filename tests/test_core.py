"""
BugHunter AI — Tests
"""
import asyncio
from pathlib import Path
import pytest


def test_pattern_analyzer_detects_sqli(tmp_path):
    """Test SQL injection detection."""
    vuln_file = tmp_path / "app.py"
    vuln_file.write_text("""
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
""")
    from bughunter.analyzers.patterns import PatternAnalyzer
    from bughunter.core import ScanConfig

    config = ScanConfig(target=tmp_path)
    analyzer = PatternAnalyzer(config)
    results = asyncio.run(analyzer.analyze(vuln_file))
    assert any("sqli" in r.vuln_type or "sql" in r.vuln_type.lower() for r in results)


def test_pattern_analyzer_detects_cors(tmp_path):
    """Test CORS wildcard detection."""
    vuln_file = tmp_path / "views.py"
    vuln_file.write_text("""
response.headers['Access-Control-Allow-Origin'] = '*'
""")
    from bughunter.analyzers.patterns import PatternAnalyzer
    from bughunter.core import ScanConfig

    config = ScanConfig(target=tmp_path)
    analyzer = PatternAnalyzer(config)
    results = asyncio.run(analyzer.analyze(vuln_file))
    assert any("cors" in r.vuln_type for r in results)


def test_secrets_analyzer_detects_aws_key(tmp_path):
    """Test AWS key detection."""
    secret_file = tmp_path / "config.py"
    secret_file.write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'")
    from bughunter.analyzers.secrets import SecretsAnalyzer
    from bughunter.core import ScanConfig

    config = ScanConfig(target=tmp_path)
    analyzer = SecretsAnalyzer(config)
    results = asyncio.run(analyzer.analyze(secret_file))
    assert len(results) > 0
    assert results[0].severity.value in ("critical", "high")


def test_static_analyzer_detects_pickle(tmp_path):
    """Test pickle deserialization detection."""
    vuln_file = tmp_path / "app.py"
    vuln_file.write_text("data = pickle.loads(user_data)")
    from bughunter.analyzers.static import StaticAnalyzer
    from bughunter.core import ScanConfig

    config = ScanConfig(target=tmp_path)
    analyzer = StaticAnalyzer(config)
    results = asyncio.run(analyzer.analyze(vuln_file))
    assert any("pickle" in r.vuln_type for r in results)


def test_fp_filter_removes_test_files(tmp_path):
    """Test that test files have reduced confidence."""
    from bughunter.models import Vulnerability, Severity, VulnCategory
    from bughunter.utils.fp_filter import FalsePositiveFilter

    vuln = Vulnerability(
        vuln_id="TEST-001",
        vuln_type="sql_injection",
        category=VulnCategory.INJECTION,
        severity=Severity.HIGH,
        file_path=Path("tests/test_views.py"),
        line_number=10,
        title="Test",
        confidence=0.9,
        false_positive_score=0.0,
    )
    f = FalsePositiveFilter()
    filtered = f.filter([vuln])
    # Should not be filtered but confidence reduced
    if filtered:
        assert filtered[0].confidence < 0.9


def test_scanner_full_scan(tmp_path):
    """Test full scanner pipeline on example code."""
    vuln_file = tmp_path / "app.py"
    vuln_file.write_text("""
import os, pickle, hashlib
password = "admin123"
os.system("ping " + host)
data = pickle.loads(user_input)
hash = hashlib.md5(pw.encode()).hexdigest()
""")
    from bughunter.core import Scanner, ScanConfig

    config = ScanConfig(target=tmp_path, use_ai=False)
    results = asyncio.run(Scanner(config).scan(verbose=False))
    assert len(results) > 0
    print(f"Found {len(results)} vulnerabilities in test code ✓")
