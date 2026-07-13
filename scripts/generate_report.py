import glob
import html
import json
import os
from collections import Counter
from urllib.parse import quote, unquote, urlparse


def safe_text(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def make_github_file_url(path, line=None):
    if not path:
        return "#"

    normalized = unquote(str(path)).replace("\\", "/").strip()

    if normalized.startswith("file://"):
        normalized = urlparse(normalized).path

    normalized = normalized.split("?", 1)[0].split("#", 1)[0]
    normalized = normalized.lstrip("./")

    repo_folder = "OWASP_Insecure_Application/"
    if repo_folder in normalized:
        normalized = normalized.split(repo_folder, 1)[1]

    normalized = normalized.lstrip("/")
    if not normalized:
        return "#"

    github_server_url = os.getenv(
        "GITHUB_SERVER_URL", "https://github.com"
    ).rstrip("/")
    scanned_repository = os.getenv(
        "SCAN_REPOSITORY", "baigsf/OWASP_Insecure_Application"
    ).strip("/")
    scanned_ref = os.getenv("SCAN_REPO_SHA", "main").strip() or "main"

    encoded_ref = quote(scanned_ref, safe="")
    encoded_path = quote(normalized, safe="/")
    url = (
        f"{github_server_url}/{scanned_repository}/blob/"
        f"{encoded_ref}/{encoded_path}"
    )

    try:
        line_number = int(line)
    except (TypeError, ValueError):
        line_number = 0

    if line_number > 0:
        url += f"#L{line_number}"

    return url


def normalize(severity):
    severity = str(severity).upper()
    if severity in {"ERROR", "HIGH"}:
        return "HIGH"
    if severity in {"WARNING", "MEDIUM"}:
        return "MEDIUM"
    if severity in {"INFO", "LOW", "NOTE"}:
        return "LOW"
    return "UNKNOWN"


def codeql_severity_from_result(result, rule_meta):
    rule_id = result.get("ruleId", "")
    properties = rule_meta.get(rule_id, {}).get("properties", {})
    security_severity = properties.get("security-severity")

    if security_severity is not None:
        try:
            score = float(security_severity)
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"
        except (TypeError, ValueError):
            pass

    problem_severity = properties.get("problem.severity")
    if problem_severity:
        return normalize(problem_severity)

    return normalize(result.get("level", "warning"))


def extract_codeql_cwe(rule):
    for tag in rule.get("properties", {}).get("tags", []):
        tag = str(tag).lower()
        if tag.startswith("external/cwe/"):
            cwe = tag.split("/")[-1].replace("cwe-", "").upper()
            return f"CWE-{cwe}"
    return "N/A"


os.makedirs("output", exist_ok=True)
findings = []

# Semgrep
try:
    with open("output/results.json", encoding="utf-8") as file:
        semgrep_data = json.load(file)

    for result in semgrep_data.get("results", []):
        rule_id = result.get("check_id", "semgrep_rule")
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        file_path = result.get("path", "")
        line_number = result.get("start", {}).get("line", "")

        findings.append({
            "source": "Semgrep",
            "rule_id": rule_id,
            "file": file_path,
            "line": line_number,
            "severity": extra.get("severity", "UNKNOWN"),
            "description": extra.get("message", ""),
            "cwe": metadata.get("cwe", "N/A"),
            "owasp": metadata.get("owasp", "N/A"),
            "rule_url": f"https://semgrep.dev/r?q={quote(rule_id)}",
            "github_file_url": make_github_file_url(file_path, line_number),
        })
except FileNotFoundError:
    print("No Semgrep JSON file found at output/results.json")
except Exception as error:
    print(f"Failed to load Semgrep results: {error}")

# CodeQL
codeql_sarif_files = glob.glob(
    "output/codeql-results/**/*.sarif", recursive=True
)
codeql_sarif_files.extend(
    glob.glob("output/codeql-results/**/*.sarif.json", recursive=True)
)
codeql_sarif_files = list(dict.fromkeys(codeql_sarif_files))

if not codeql_sarif_files:
    print("No CodeQL SARIF files found in output/codeql-results")
else:
    print("CodeQL SARIF files found:")
    for sarif_file in codeql_sarif_files:
        print(f" - {sarif_file}")

for sarif_file in codeql_sarif_files:
    try:
        with open(sarif_file, encoding="utf-8") as file:
            codeql_data = json.load(file)

        for run in codeql_data.get("runs", []):
            rule_meta = {}
            rules = run.get("tool", {}).get("driver", {}).get("rules", [])

            for rule in rules:
                rule_id = rule.get("id", "")
                rule_meta[rule_id] = {
                    "help_uri": rule.get("helpUri", "#"),
                    "short_description": rule.get(
                        "shortDescription", {}
                    ).get("text", ""),
                    "cwe": extract_codeql_cwe(rule),
                    "properties": rule.get("properties", {}),
                }

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "codeql_rule")
                message = result.get("message", {}).get("text", "")
                if not message:
                    message = rule_meta.get(rule_id, {}).get(
                        "short_description", ""
                    )

                file_path = ""
                line_number = ""
                locations = result.get("locations", [])
                if locations:
                    physical = locations[0].get("physicalLocation", {})
                    file_path = physical.get("artifactLocation", {}).get(
                        "uri", ""
                    )
                    line_number = physical.get("region", {}).get(
                        "startLine", ""
                    )

                findings.append({
                    "source": "CodeQL",
                    "rule_id": f"CodeQL: {rule_id}",
                    "file": file_path,
                    "line": line_number,
                    "severity": codeql_severity_from_result(
                        result, rule_meta
                    ),
                    "description": message,
                    "cwe": rule_meta.get(rule_id, {}).get("cwe", "N/A"),
                    "owasp": "CodeQL",
                    "rule_url": rule_meta.get(rule_id, {}).get(
                        "help_uri", "#"
                    ),
                    "github_file_url": make_github_file_url(
                        file_path, line_number
                    ),
                })
    except Exception as error:
        print(f"Failed to parse CodeQL SARIF file {sarif_file}: {error}")

# Gitleaks
try:
    with open("output/gitleaks-results.json", encoding="utf-8") as file:
        gitleaks_data = json.load(file)

    if isinstance(gitleaks_data, list):
        gitleaks_results = gitleaks_data
    elif isinstance(gitleaks_data, dict):
        gitleaks_results = gitleaks_data.get(
            "findings", gitleaks_data.get("results", [])
        )
    else:
        gitleaks_results = []

    for result in gitleaks_results:
        rule_id = result.get("RuleID", "gitleaks_rule")
        file_path = result.get("File", "")
        line_number = result.get("StartLine", "")
        description_parts = [
            result.get("Description", "Potential hardcoded secret detected")
        ]

        end_line = result.get("EndLine", "")
        commit = result.get("Commit", "")
        fingerprint = result.get("Fingerprint", "")

        if end_line and str(end_line) != str(line_number):
            description_parts.append(f"Detection ends on line {end_line}.")
        if commit:
            description_parts.append(f"Commit: {commit}.")
        if fingerprint:
            description_parts.append(f"Fingerprint: {fingerprint}.")

        findings.append({
            "source": "Gitleaks",
            "rule_id": f"Gitleaks: {rule_id}",
            "file": file_path,
            "line": line_number,
            "severity": "HIGH",
            "description": " ".join(
                str(part) for part in description_parts if part
            ),
            "cwe": "CWE-798",
            "owasp": "Secret Detection",
            "rule_url": "https://github.com/gitleaks/gitleaks",
            "github_file_url": make_github_file_url(
                file_path, line_number
            ),
        })
except FileNotFoundError:
    print("No Gitleaks JSON file found at output/gitleaks-results.json")
except json.JSONDecodeError as error:
    print(f"Failed to decode Gitleaks JSON results: {error}")
except Exception as error:
    print(f"Failed to load Gitleaks results: {error}")

# Normalize and summarize
for finding in findings:
    finding["severity"] = normalize(finding["severity"])

priority = {"HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
findings.sort(key=lambda finding: priority.get(finding["severity"], 4))

counts = Counter(finding["severity"] for finding in findings)
high_count = counts.get("HIGH", 0)
medium_count = counts.get("MEDIUM", 0)
low_count = counts.get("LOW", 0)
unknown_count = counts.get("UNKNOWN", 0)

source_counts = Counter(finding["source"] for finding in findings)
semgrep_count = source_counts.get("Semgrep", 0)
codeql_count = source_counts.get("CodeQL", 0)
gitleaks_count = source_counts.get("Gitleaks", 0)
max_count = max(high_count, medium_count, low_count, unknown_count, 1)

html_output = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SAST Dashboard</title>
  <style>
    :root {{ --bg:#f5f7fb; --text:#1f2937; --card:#fff; --border:#dbe2ea; --shadow:rgba(0,0,0,.08); --muted:#6b7280; --link:#2563eb; --high:#dc2626; --medium:#f59e0b; --low:#16a34a; --unknown:#6b7280; --input-bg:#fff; --header-bg:#fff; }}
    body.dark {{ --bg:#0f172a; --text:#e5e7eb; --card:#111827; --border:#334155; --shadow:rgba(0,0,0,.35); --muted:#94a3b8; --link:#60a5fa; --high:#f87171; --medium:#fbbf24; --low:#4ade80; --unknown:#cbd5e1; --input-bg:#1f2937; --header-bg:#111827; }}
    * {{ box-sizing:border-box; }}
    body {{ font-family:Arial,sans-serif; margin:0; background:var(--bg); color:var(--text); transition:.25s; }}
    .container {{ max-width:1200px; margin:auto; padding:28px; }}
    .topbar {{ display:flex; justify-content:space-between; align-items:center; gap:16px; flex-wrap:wrap; margin-bottom:24px; background:var(--header-bg); padding:20px; border:1px solid var(--border); border-radius:16px; box-shadow:0 4px 14px var(--shadow); }}
    h1 {{ margin:0; font-size:2rem; }}
    .subtitle,.footer-note {{ color:var(--muted); margin-top:6px; }}
    .toggle-btn {{ background:var(--card); color:var(--text); border:1px solid var(--border); padding:10px 14px; border-radius:10px; cursor:pointer; font-weight:bold; }}
    .summary-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:24px; }}
    .summary-card,.panel,.card {{ background:var(--card); border:1px solid var(--border); box-shadow:0 4px 14px var(--shadow); }}
    .summary-card {{ border-radius:14px; padding:18px; }}
    .summary-label {{ color:var(--muted); font-size:.95rem; margin-bottom:8px; }}
    .summary-value {{ font-size:1.8rem; font-weight:bold; }}
    .high-text {{ color:var(--high); }} .medium-text {{ color:var(--medium); }} .low-text {{ color:var(--low); }} .unknown-text {{ color:var(--unknown); }}
    .panel {{ border-radius:16px; padding:20px; margin-bottom:24px; }}
    .panel h2 {{ margin-top:0; }}
    .bar-row {{ margin-bottom:18px; }}
    .bar-header {{ display:flex; justify-content:space-between; margin-bottom:6px; font-weight:bold; }}
    .bar-track {{ width:100%; height:18px; background:rgba(148,163,184,.18); border-radius:999px; overflow:hidden; }}
    .bar-fill {{ height:100%; border-radius:999px; }}
    .bar-high {{ background:var(--high); }} .bar-medium {{ background:var(--medium); }} .bar-low {{ background:var(--low); }} .bar-unknown {{ background:var(--unknown); }}
    .search-input {{ width:100%; padding:12px 14px; border-radius:10px; border:1px solid var(--border); background:var(--input-bg); color:var(--text); }}
    .card {{ border-radius:14px; padding:18px; margin:14px 0; }}
    .finding-title {{ margin-top:0; margin-bottom:10px; }}
    .meta {{ margin:8px 0; line-height:1.5; }}
    .github-link,.rule-link {{ color:var(--link); text-decoration:none; word-break:break-word; }}
    .github-link:hover,.rule-link:hover {{ text-decoration:underline; }}
    .pill,.source-pill {{ display:inline-block; padding:4px 10px; border-radius:999px; font-size:.84rem; font-weight:bold; margin-left:8px; border:1px solid var(--border); }}
    .source-pill {{ background:rgba(37,99,235,.12); color:var(--link); }}
  </style>
</head>
<body>
<div class="container">
  <div class="topbar">
    <div><h1>SAST Security Dashboard</h1><div class="subtitle">Combined Semgrep, CodeQL, and Gitleaks findings</div></div>
    <button class="toggle-btn" onclick="toggleTheme()">Toggle Dark Mode</button>
  </div>
  <div class="summary-grid">
    <div class="summary-card"><div class="summary-label">High</div><div class="summary-value high-text">{high_count}</div></div>
    <div class="summary-card"><div class="summary-label">Medium</div><div class="summary-value medium-text">{medium_count}</div></div>
    <div class="summary-card"><div class="summary-label">Low</div><div class="summary-value low-text">{low_count}</div></div>
    <div class="summary-card"><div class="summary-label">Unknown</div><div class="summary-value unknown-text">{unknown_count}</div></div>
    <div class="summary-card"><div class="summary-label">Semgrep Findings</div><div class="summary-value">{semgrep_count}</div></div>
    <div class="summary-card"><div class="summary-label">CodeQL Findings</div><div class="summary-value">{codeql_count}</div></div>
    <div class="summary-card"><div class="summary-label">Gitleaks Findings</div><div class="summary-value">{gitleaks_count}</div></div>
  </div>
  <div class="panel">
    <h2>Vulnerability Severity Graph</h2>
    <div class="bar-row"><div class="bar-header"><span class="high-text">High</span><span>{high_count}</span></div><div class="bar-track"><div class="bar-fill bar-high" style="width:{high_count / max_count * 100:.2f}%"></div></div></div>
    <div class="bar-row"><div class="bar-header"><span class="medium-text">Medium</span><span>{medium_count}</span></div><div class="bar-track"><div class="bar-fill bar-medium" style="width:{medium_count / max_count * 100:.2f}%"></div></div></div>
    <div class="bar-row"><div class="bar-header"><span class="low-text">Low</span><span>{low_count}</span></div><div class="bar-track"><div class="bar-fill bar-low" style="width:{low_count / max_count * 100:.2f}%"></div></div></div>
    <div class="bar-row"><div class="bar-header"><span class="unknown-text">Unknown</span><span>{unknown_count}</span></div><div class="bar-track"><div class="bar-fill bar-unknown" style="width:{unknown_count / max_count * 100:.2f}%"></div></div></div>
    <div class="footer-note">The bar lengths are scaled relative to the largest severity count.</div>
  </div>
  <div class="panel"><h2>Search Findings</h2><input type="text" id="search" class="search-input" placeholder="Search findings by source, rule, file, CWE, OWASP, or description..."></div>
"""

for finding in findings:
    severity_class = f"{finding['severity'].lower()}-text"
    html_output += f"""
  <div class="card">
    <h2 class="finding-title {severity_class}">[{safe_text(finding['severity'])}] {safe_text(finding['rule_id'])}<span class="source-pill">{safe_text(finding['source'])}</span></h2>
    <p class="meta"><b>Impacted File:</b> <a class="github-link" href="{safe_text(finding['github_file_url'])}" target="_blank" rel="noopener noreferrer">{safe_text(finding['file'])}:{safe_text(finding['line'])}</a></p>
    <p class="meta"><b>Description:</b> {safe_text(finding['description'])}</p>
    <p class="meta"><b>CWE:</b> {safe_text(finding['cwe'])}<span class="pill">{safe_text(finding['severity'])}</span></p>
    <p class="meta"><b>OWASP / Source Category:</b> {safe_text(finding['owasp'])}</p>
    <p class="meta"><b>Remediation:</b><br><a class="rule-link" href="{safe_text(finding['rule_url'])}" target="_blank" rel="noopener noreferrer">View Fix Guidance</a></p>
  </div>
"""

html_output += """
</div>
<script>
function applySavedTheme(){if(localStorage.getItem("theme")==="dark"){document.body.classList.add("dark");}}
function toggleTheme(){document.body.classList.toggle("dark");localStorage.setItem("theme",document.body.classList.contains("dark")?"dark":"light");}
applySavedTheme();
document.getElementById("search").addEventListener("input",function(event){const term=event.target.value.toLowerCase();document.querySelectorAll(".card").forEach(function(card){card.style.display=card.innerText.toLowerCase().includes(term)?"":"none";});});
</script>
</body>
</html>
"""

with open("output/security-report.html", "w", encoding="utf-8") as file:
    file.write(html_output)

print("Dashboard generated: output/security-report.html")
