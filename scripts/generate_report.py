import json
import html
import os
import glob
from collections import Counter


def make_github_file_url(path, line=None):
    if not path:
        return "#"

    normalized = str(path).replace("\\", "/")

    if normalized.startswith("./"):
        normalized = normalized[2:]

    # Build GitHub link for the current repository and commit
    github_server_url = os.getenv("GITHUB_SERVER_URL", "https://github.com")
    github_repository = os.getenv("GITHUB_REPOSITORY", "")
    github_sha = os.getenv("GITHUB_SHA", "main")

    if not github_repository:
        return "#"

    url = f"{github_server_url}/{github_repository}/blob/{github_sha}/{normalized}"

    if line:
        url += f"#L{line}"

    return url


def normalize(sev):
    sev = str(sev).upper()
    if sev in ["ERROR", "HIGH"]:
        return "HIGH"
    elif sev in ["WARNING", "MEDIUM"]:
        return "MEDIUM"
    elif sev in ["INFO", "LOW", "NOTE"]:
        return "LOW"
    return "UNKNOWN"


def codeql_severity_from_result(result, rule_meta):
    rule_id = result.get("ruleId", "")
    props = rule_meta.get(rule_id, {}).get("properties", {})

    security_severity = props.get("security-severity")

    if security_severity is not None:
        try:
            score = float(security_severity)
            if score >= 7.0:
                return "HIGH"
            elif score >= 4.0:
                return "MEDIUM"
            else:
                return "LOW"
        except ValueError:
            pass

    problem_severity = props.get("problem.severity")
    if problem_severity:
        return normalize(problem_severity)

    level = result.get("level", "warning")
    return normalize(level)


def extract_codeql_cwe(rule):
    tags = rule.get("properties", {}).get("tags", [])

    for tag in tags:
        tag = str(tag).lower()

        if tag.startswith("external/cwe/"):
            cwe_part = tag.split("/")[-1]
            cwe_part = cwe_part.replace("cwe-", "").upper()
            return f"CWE-{cwe_part}"

    return "N/A"


# -------------------------------
# Load Semgrep results
# -------------------------------
with open("output/results.json", encoding="utf-8") as f:
    data = json.load(f)

results = data.get("results", [])
findings = []

# Extract Semgrep fields
for r in results:
    rule_id = r.get("check_id")
    meta = r.get("extra", {}).get("metadata", {})
    file_path = r.get("path")
    line_number = r.get("start", {}).get("line")

    rule_url = f"https://semgrep.dev/r?q={rule_id}"
    github_file_url = make_github_file_url(file_path, line_number)

    findings.append({
        "source": "Semgrep",
        "rule_id": rule_id,
        "file": file_path,
        "line": line_number,
        "severity": r.get("extra", {}).get("severity", "UNKNOWN"),
        "description": r.get("extra", {}).get("message", ""),
        "cwe": meta.get("cwe", "N/A"),
        "owasp": meta.get("owasp", "N/A"),
        "rule_url": rule_url,
        "github_file_url": github_file_url
    })


# -------------------------------
# Load CodeQL SARIF results
# -------------------------------
codeql_sarif_files = []

codeql_sarif_files.extend(
    glob.glob("output/codeql-results/**/*.sarif", recursive=True)
)

codeql_sarif_files.extend(
    glob.glob("output/codeql-results/**/*.sarif.json", recursive=True)
)

if not codeql_sarif_files:
    print("No CodeQL SARIF files found in output/codeql-results")
else:
    print("CodeQL SARIF files found:")
    for sarif_file in codeql_sarif_files:
        print(f" - {sarif_file}")

for sarif_file in codeql_sarif_files:
    try:
        with open(sarif_file, encoding="utf-8") as f:
            codeql_data = json.load(f)

        for run in codeql_data.get("runs", []):
            rule_meta = {}

            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rule_id = rule.get("id", "")

                rule_meta[rule_id] = {
                    "name": rule.get("name", ""),
                    "help_uri": rule.get("helpUri", "#"),
                    "short_description": rule.get("shortDescription", {}).get("text", ""),
                    "full_description": rule.get("fullDescription", {}).get("text", ""),
                    "cwe": extract_codeql_cwe(rule),
                    "properties": rule.get("properties", {})
                }

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "codeql_rule")

                message = result.get("message", {}).get("text", "")

                if not message:
                    message = rule_meta.get(rule_id, {}).get("short_description", "")

                file_path = ""
                line_number = ""

                locations = result.get("locations", [])

                if locations:
                    physical = locations[0].get("physicalLocation", {})
                    file_path = physical.get("artifactLocation", {}).get("uri", "")
                    line_number = physical.get("region", {}).get("startLine", "")

                severity = codeql_severity_from_result(result, rule_meta)
                rule_url = rule_meta.get(rule_id, {}).get("help_uri", "#")
                cwe = rule_meta.get(rule_id, {}).get("cwe", "N/A")
                github_file_url = make_github_file_url(file_path, line_number)

                findings.append({
                    "source": "CodeQL",
                    "rule_id": f"CodeQL: {rule_id}",
                    "file": file_path,
                    "line": line_number,
                    "severity": severity,
                    "description": message,
                    "cwe": cwe,
                    "owasp": "CodeQL",
                    "rule_url": rule_url,
                    "github_file_url": github_file_url
                })

    except Exception as e:
        print(f"Failed to parse CodeQL SARIF file {sarif_file}: {e}")


# Normalize severity
for finding in findings:
    finding["severity"] = normalize(finding["severity"])

# Sort by severity
priority = {"HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
findings.sort(key=lambda x: priority.get(x["severity"], 4))

# Summary counts
counts = Counter(f["severity"] for f in findings)
high_count = counts.get("HIGH", 0)
medium_count = counts.get("MEDIUM", 0)
low_count = counts.get("LOW", 0)
unknown_count = counts.get("UNKNOWN", 0)

source_counts = Counter(f["source"] for f in findings)
semgrep_count = source_counts.get("Semgrep", 0)
codeql_count = source_counts.get("CodeQL", 0)

max_count = max(high_count, medium_count, low_count, unknown_count, 1)

# Generate HTML
html_output = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SAST Dashboard</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --text: #1f2937;
      --card: #ffffff;
      --border: #dbe2ea;
      --shadow: rgba(0,0,0,0.08);
      --muted: #6b7280;
      --link: #2563eb;
      --high: #dc2626;
      --medium: #f59e0b;
      --low: #16a34a;
      --unknown: #6b7280;
      --input-bg: #ffffff;
      --header-bg: #ffffff;
    }}

    body.dark {{
      --bg: #0f172a;
      --text: #e5e7eb;
      --card: #111827;
      --border: #334155;
      --shadow: rgba(0,0,0,0.35);
      --muted: #94a3b8;
      --link: #60a5fa;
      --high: #f87171;
      --medium: #fbbf24;
      --low: #4ade80;
      --unknown: #cbd5e1;
      --input-bg: #1f2937;
      --header-bg: #111827;
    }}

    * {{
      box-sizing: border-box;
    }}

    body {{
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 0;
      background: var(--bg);
      color: var(--text);
      transition: background 0.25s ease, color 0.25s ease;
    }}

    .container {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 28px;
    }}

    .topbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
      margin-bottom: 24px;
      background: var(--header-bg);
      padding: 20px;
      border: 1px solid var(--border);
      border-radius: 16px;
      box-shadow: 0 4px 14px var(--shadow);
    }}

    h1 {{
      margin: 0;
      font-size: 2rem;
    }}

    .subtitle {{
      color: var(--muted);
      margin-top: 6px;
    }}

    .toggle-btn {{
      background: var(--card);
      color: var(--text);
      border: 1px solid var(--border);
      padding: 10px 14px;
      border-radius: 10px;
      cursor: pointer;
      font-weight: bold;
      box-shadow: 0 2px 8px var(--shadow);
    }}

    .toggle-btn:hover {{
      opacity: 0.95;
    }}

    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}

    .summary-card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 18px;
      box-shadow: 0 4px 14px var(--shadow);
    }}

    .summary-label {{
      color: var(--muted);
      font-size: 0.95rem;
      margin-bottom: 8px;
    }}

    .summary-value {{
      font-size: 1.8rem;
      font-weight: bold;
    }}

    .high-text {{ color: var(--high); }}
    .medium-text {{ color: var(--medium); }}
    .low-text {{ color: var(--low); }}
    .unknown-text {{ color: var(--unknown); }}

    .panel {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 24px;
      box-shadow: 0 4px 14px var(--shadow);
    }}

    .panel h2 {{
      margin-top: 0;
    }}

    .chart-wrap {{
      margin-top: 18px;
    }}

    .bar-row {{
      margin-bottom: 18px;
    }}

    .bar-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
      font-weight: bold;
    }}

    .bar-track {{
      width: 100%;
      height: 18px;
      background: rgba(148, 163, 184, 0.18);
      border-radius: 999px;
      overflow: hidden;
    }}

    .bar-fill {{
      height: 100%;
      border-radius: 999px;
      transition: width 0.5s ease;
    }}

    .bar-high {{ background: var(--high); }}
    .bar-medium {{ background: var(--medium); }}
    .bar-low {{ background: var(--low); }}
    .bar-unknown {{ background: var(--unknown); }}

    .controls {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 20px;
    }}

    .search-input {{
      flex: 1;
      min-width: 260px;
      padding: 12px 14px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--input-bg);
      color: var(--text);
    }}

    .card {{
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 18px;
      margin: 14px 0;
      box-shadow: 0 4px 14px var(--shadow);
      background: var(--card);
    }}

    .finding-title {{
      margin-top: 0;
      margin-bottom: 10px;
    }}

    .finding-title.high-text,
    .finding-title.medium-text,
    .finding-title.low-text,
    .finding-title.unknown-text {{
      font-weight: 700;
    }}

    .meta {{
      margin: 8px 0;
      line-height: 1.5;
    }}

    .github-link, .rule-link {{
      color: var(--link);
      text-decoration: none;
      word-break: break-word;
    }}

    .github-link:hover, .rule-link:hover {{
      text-decoration: underline;
    }}

    .pill {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 0.84rem;
      font-weight: bold;
      margin-left: 8px;
      vertical-align: middle;
      border: 1px solid var(--border);
    }}

    .source-pill {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 0.84rem;
      font-weight: bold;
      margin-left: 8px;
      vertical-align: middle;
      background: rgba(37, 99, 235, 0.12);
      color: var(--link);
      border: 1px solid var(--border);
    }}

    .footer-note {{
      color: var(--muted);
      margin-top: 8px;
      font-size: 0.92rem;
    }}
  </style>
</head>
<body>
  <div class="container">

    <div class="topbar">
      <div>
        <h1>SAST Security Dashboard</h1>
        <div class="subtitle">Combined Semgrep and CodeQL findings</div>
      </div>
      <button class="toggle-btn" onclick="toggleTheme()">Toggle Dark Mode</button>
    </div>

    <div class="summary-grid">
      <div class="summary-card">
        <div class="summary-label">High</div>
        <div class="summary-value high-text">{high_count}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Medium</div>
        <div class="summary-value medium-text">{medium_count}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Low</div>
        <div class="summary-value low-text">{low_count}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Unknown</div>
        <div class="summary-value unknown-text">{unknown_count}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Semgrep Findings</div>
        <div class="summary-value">{semgrep_count}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">CodeQL Findings</div>
        <div class="summary-value">{codeql_count}</div>
      </div>
    </div>

    <div class="panel">
      <h2>Vulnerability Severity Graph</h2>
      <div class="chart-wrap">
        <div class="bar-row">
          <div class="bar-header">
            <span class="high-text">High</span>
            <span>{high_count}</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill bar-high" style="width: {(high_count / max_count) * 100:.2f}%"></div>
          </div>
        </div>

        <div class="bar-row">
          <div class="bar-header">
            <span class="medium-text">Medium</span>
            <span>{medium_count}</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill bar-medium" style="width: {(medium_count / max_count) * 100:.2f}%"></div>
          </div>
        </div>

        <div class="bar-row">
          <div class="bar-header">
            <span class="low-text">Low</span>
            <span>{low_count}</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill bar-low" style="width: {(low_count / max_count) * 100:.2f}%"></div>
          </div>
        </div>

        <div class="bar-row">
          <div class="bar-header">
            <span class="unknown-text">Unknown</span>
            <span>{unknown_count}</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill bar-unknown" style="width: {(unknown_count / max_count) * 100:.2f}%"></div>
          </div>
        </div>
      </div>
      <div class="footer-note">The bar lengths are scaled relative to the largest severity count.</div>
    </div>

    <div class="panel">
      <h2>Search Findings</h2>
      <div class="controls">
        <input type="text" id="search" class="search-input" placeholder="Search findings by source, rule, file, CWE, OWASP, or description...">
      </div>
    </div>
"""

# Render findings
for finding in findings:
    severity_class = f"{finding['severity'].lower()}-text"

    html_output += f"""
    <div class="card">
      <h2 class="finding-title {severity_class}">
        [{html.escape(str(finding['severity']))}] {html.escape(str(finding['rule_id']))}
        <span class="source-pill">{html.escape(str(finding['source']))}</span>
      </h2>

      <p class="meta">
        <b>Impacted File:</b>
        }" target="_blank">
          {html.escape(str(finding['file']))}:{html.escape(str(finding['line']))}
        </a>
      </p>

      <p class="meta">
        <b>Description:</b> {html.escape(str(finding['description']))}
      </p>

      <p class="meta">
        <b>CWE:</b> {html.escape(str(finding['cwe']))}
        <span class="pill">{html.escape(str(finding['severity']))}</span>
      </p>

      <p class="meta">
        <b>OWASP / Source Category:</b> {html.escape(str(finding['owasp']))}
      </p>

      <p class="meta">
        <b>Remediation:</b><br>
        }" target="_blank">
           View Fix Guidance
        </a>
      </p>
    </div>
    """

# Add scripts and close HTML
html_output += """
  </div>

  <script>
    function applySavedTheme() {
      const savedTheme = localStorage.getItem("theme");
      if (savedTheme === "dark") {
        document.body.classList.add("dark");
      }
    }

    function toggleTheme() {
      document.body.classList.toggle("dark");
      const isDark = document.body.classList.contains("dark");
      localStorage.setItem("theme", isDark ? "dark" : "light");
    }

    applySavedTheme();

    document.getElementById('search').addEventListener('input', function(e) {
      let term = e.target.value.toLowerCase();
      document.querySelectorAll('.card').forEach(card => {
        card.style.display = card.innerText.toLowerCase().includes(term) ? '' : 'none';
      });
    });
  </script>
</body>
</html>
"""

# Save file
with open("output/security-report.html", "w", encoding="utf-8") as f:
    f.write(html_output)

print("Dashboard generated: output/security-report.html")