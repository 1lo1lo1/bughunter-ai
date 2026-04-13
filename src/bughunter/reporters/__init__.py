"""
BugHunter AI — Report Generator
Generates HTML, JSON, SARIF, and Markdown reports
"""
from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List

from bughunter.models import Vulnerability


class ReportFormat(str, Enum):
    TABLE = "table"
    HTML = "html"
    JSON = "json"
    SARIF = "sarif"
    MARKDOWN = "markdown"


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BugHunter AI Security Report</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --accent: #58a6ff; --critical: #f85149;
    --high: #e3b341; --medium: #3fb950; --low: #58a6ff; --info: #8b949e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: var(--bg); color: var(--text); padding: 24px; }}
  h1 {{ font-size: 2rem; color: var(--accent); margin-bottom: 8px; }}
  .subtitle {{ color: #8b949e; margin-bottom: 32px; }}
  .stats {{ display: flex; gap: 16px; margin-bottom: 32px; flex-wrap: wrap; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border);
               border-radius: 12px; padding: 20px 28px; min-width: 140px; text-align: center; }}
  .stat-card .num {{ font-size: 2rem; font-weight: bold; }}
  .stat-card .label {{ font-size: 0.85rem; color: #8b949e; margin-top: 4px; }}
  .critical .num {{ color: var(--critical); }}
  .high .num {{ color: var(--high); }}
  .medium .num {{ color: var(--medium); }}
  .low .num {{ color: var(--low); }}
  .vuln {{ background: var(--surface); border: 1px solid var(--border);
           border-radius: 12px; margin-bottom: 16px; overflow: hidden; }}
  .vuln-header {{ padding: 16px 20px; display: flex; align-items: center; gap: 12px;
                  cursor: pointer; justify-content: space-between; }}
  .vuln-header:hover {{ background: rgba(88,166,255,0.05); }}
  .badge {{ padding: 4px 10px; border-radius: 20px; font-size: 0.75rem;
            font-weight: bold; text-transform: uppercase; }}
  .badge.critical {{ background: rgba(248,81,73,0.2); color: var(--critical); }}
  .badge.high {{ background: rgba(227,179,65,0.2); color: var(--high); }}
  .badge.medium {{ background: rgba(63,185,80,0.2); color: var(--medium); }}
  .badge.low {{ background: rgba(88,166,255,0.2); color: var(--low); }}
  .badge.info {{ background: rgba(139,148,158,0.2); color: var(--info); }}
  .vuln-title {{ font-weight: 600; font-size: 1rem; }}
  .vuln-file {{ font-size: 0.8rem; color: #8b949e; font-family: monospace; }}
  .vuln-body {{ padding: 20px; border-top: 1px solid var(--border); }}
  .section {{ margin-bottom: 16px; }}
  .section-label {{ font-size: 0.75rem; text-transform: uppercase; color: #8b949e;
                    letter-spacing: 0.8px; margin-bottom: 6px; }}
  pre {{ background: #0d1117; border: 1px solid var(--border); border-radius: 8px;
        padding: 14px; font-size: 0.82rem; overflow-x: auto; line-height: 1.5; }}
  .tags {{ display: flex; gap: 8px; flex-wrap: wrap; }}
  .tag {{ background: rgba(88,166,255,0.1); border: 1px solid rgba(88,166,255,0.3);
          color: var(--accent); padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; }}
  .ai-badge {{ background: rgba(88,166,255,0.15); color: var(--accent);
               padding: 2px 8px; border-radius: 8px; font-size: 0.7rem; }}
  details summary {{ list-style: none; }}
  details summary::-webkit-details-marker {{ display: none; }}
  .chevron {{ transition: transform 0.2s; }}
  details[open] .chevron {{ transform: rotate(90deg); }}
  footer {{ margin-top: 48px; text-align: center; color: #8b949e; font-size: 0.82rem; }}
</style>
</head>
<body>
<h1>🐛 BugHunter AI Security Report</h1>
<p class="subtitle">Generated {timestamp} · {file_count} files scanned · {duration}</p>

<div class="stats">
  <div class="stat-card critical"><div class="num">{critical}</div><div class="label">Critical</div></div>
  <div class="stat-card high"><div class="num">{high}</div><div class="label">High</div></div>
  <div class="stat-card medium"><div class="num">{medium}</div><div class="label">Medium</div></div>
  <div class="stat-card low"><div class="num">{low}</div><div class="label">Low</div></div>
  <div class="stat-card"><div class="num">{total}</div><div class="label">Total</div></div>
</div>

{vulns_html}

<footer>BugHunter AI — Free &amp; Open Source · <a href="https://github.com/YOUR_USERNAME/bughunter-ai" style="color: var(--accent);">GitHub</a></footer>
</body>
</html>
"""

VULN_HTML = """
<details class="vuln">
  <summary class="vuln-header">
    <div style="display:flex;align-items:center;gap:12px;">
      <span class="badge {severity}">{severity_upper}</span>
      <div>
        <div class="vuln-title">{title}</div>
        <div class="vuln-file">{file_path}:{line}</div>
      </div>
      {ai_badge}
    </div>
    <span class="chevron">›</span>
  </summary>
  <div class="vuln-body">
    {description_section}
    {impact_section}
    {recommendation_section}
    {snippet_section}
    {tags_section}
    {fix_section}
  </div>
</details>
"""


class ReportGenerator:

    def generate(self, vulns: List[Vulnerability], output: Path,
                 fmt: ReportFormat, config=None) -> Path:
        if fmt == ReportFormat.HTML:
            return self._html(vulns, output, config)
        elif fmt == ReportFormat.JSON:
            return self._json(vulns, output)
        elif fmt == ReportFormat.SARIF:
            return self._sarif(vulns, output)
        elif fmt == ReportFormat.MARKDOWN:
            return self._markdown(vulns, output)
        return output

    def _html(self, vulns, output, config) -> Path:
        sev_count = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
        for v in vulns:
            sev_count[v.severity.value] += 1

        vulns_html = ""
        for v in vulns:
            ai_badge = '<span class="ai-badge">🤖 AI</span>' if v.ai_confirmed else ""
            desc = f'<div class="section"><div class="section-label">Description</div><p>{v.description}</p></div>' if v.description else ""
            impact = f'<div class="section"><div class="section-label">Impact</div><p>{v.impact}</p></div>' if v.impact else ""
            rec = f'<div class="section"><div class="section-label">Recommendation</div><p>{v.recommendation}</p></div>' if v.recommendation else ""
            snippet = ""
            if v.snippet:
                snippet = f'<div class="section"><div class="section-label">Code</div><pre>{_escape(v.snippet.content)}</pre></div>'

            tags = []
            if v.cwe_id: tags.append(v.cwe_id)
            if v.owasp_category: tags.append(v.owasp_category.split(" ")[0])
            tags.append(f"confidence: {v.confidence:.0%}")
            tags_html = '<div class="section"><div class="tags">' + "".join(f'<span class="tag">{t}</span>' for t in tags) + "</div></div>"

            fix_html = ""
            if v.fix and v.fix.code_after:
                fix_html = f'<div class="section"><div class="section-label">Fix</div><pre>{_escape(v.fix.code_after)}</pre></div>'

            vulns_html += VULN_HTML.format(
                severity=v.severity.value,
                severity_upper=v.severity.value.upper(),
                title=_escape(v.title),
                file_path=_escape(v.short_path),
                line=v.line_number,
                ai_badge=ai_badge,
                description_section=desc,
                impact_section=impact,
                recommendation_section=rec,
                snippet_section=snippet,
                tags_section=tags_html,
                fix_section=fix_html,
            )

        html = HTML_TEMPLATE.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M"),
            file_count="N/A",
            duration="",
            critical=sev_count["critical"],
            high=sev_count["high"],
            medium=sev_count["medium"],
            low=sev_count["low"],
            total=len(vulns),
            vulns_html=vulns_html if vulns_html else "<p style='color:#8b949e;text-align:center;padding:48px'>✅ No vulnerabilities found!</p>",
        )
        output.write_text(html)
        return output

    def _json(self, vulns, output) -> Path:
        data = {
            "generated": datetime.now().isoformat(),
            "total": len(vulns),
            "by_severity": {s: sum(1 for v in vulns if v.severity.value == s)
                          for s in ["critical", "high", "medium", "low", "info"]},
            "vulnerabilities": [v.to_dict() for v in vulns],
        }
        output.write_text(json.dumps(data, indent=2, default=str))
        return output

    def _sarif(self, vulns, output) -> Path:
        rules = {}
        results = []

        for v in vulns:
            rule_id = v.vuln_type
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": v.title,
                    "shortDescription": {"text": v.title},
                    "fullDescription": {"text": v.description},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{v.cwe_id.replace('CWE-', '') if v.cwe_id else '0'}.html",
                    "properties": {"severity": v.severity.value, "tags": [v.category.value]},
                }
            results.append({
                "ruleId": rule_id,
                "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}.get(v.severity.value, "none"),
                "message": {"text": v.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(v.file_path)},
                        "region": {"startLine": v.line_number},
                    }
                }],
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "BugHunter AI", "version": "1.0.0", "rules": list(rules.values())}},
                "results": results,
            }],
        }
        output.write_text(json.dumps(sarif, indent=2))
        return output

    def _markdown(self, vulns, output) -> Path:
        lines = ["# 🐛 BugHunter AI Security Report", "",
                 f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                 f"**Total Issues:** {len(vulns)}", ""]

        sev_counts = {}
        for v in vulns:
            sev_counts[v.severity.value] = sev_counts.get(v.severity.value, 0) + 1

        lines += ["## Summary", ""]
        lines += ["| Severity | Count |", "|----------|-------|"]
        for sev in ["critical", "high", "medium", "low", "info"]:
            emoji = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}[sev]
            lines.append(f"| {emoji} {sev.capitalize()} | {sev_counts.get(sev, 0)} |")

        lines += ["", "## Vulnerabilities", ""]
        for v in vulns:
            emoji = v.severity_emoji
            lines += [
                f"### {emoji} {v.title}",
                f"- **File:** `{v.file_path}:{v.line_number}`",
                f"- **Severity:** {v.severity.value.upper()}",
                f"- **Category:** {v.category.value}",
                f"- **CWE:** {v.cwe_id or 'N/A'}",
                f"- **Confidence:** {v.confidence:.0%}",
                "",
                f"**Description:** {v.description}", "",
                f"**Impact:** {v.impact}", "",
                f"**Recommendation:** {v.recommendation}", "",
            ]
            if v.snippet:
                lines += ["**Code:**", "```", v.snippet.content, "```", ""]

        output.write_text("\n".join(lines))
        return output


def _escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
