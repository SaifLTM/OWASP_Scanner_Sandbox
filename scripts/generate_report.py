import json
import html
from collections import Counter

WEBGOAT_REPO_URL = "https://github.com/WebGoat/WebGoat"
WEBGOAT_BRANCH = "main"

def make_github_file_url(path, line=None):
    if not path:
        return "#"

    normalized = path.replace("\\", "/")

    if normalized.startswith("./"):
        normalized = normalized[2:]

    if normalized.startswith("WebGoat/"):
        normalized = normalized[len("WebGoat/"):]

    marker = "/WebGoat/"
    if marker in normalized:
        normalized = normalized.split(marker, 1)[1]

    url = f"{WEBGOAT_REPO_URL}/blob/{WEBGOAT_BRANCH}/{normalized}"

    if line:
        url += f"#L{line}"

    return url


# Load Semgrep results
with open("output/results.json") as f:
    data = json.load(f)

results = data.get("results", [])
findings = []

# Extract fields + generate Semgrep rule link + GitHub file link
for r in results:
    rule_id = r.get("check_id")
    meta = r.get("extra", {}).get("metadata", {})
    file_path = r.get("path")
    line_number = r.get("start", {}).get("line")

    rule_url = f"https://semgrep.dev/r?q={rule_id}"
    github_file_url = make_github_file_url(file_path, line_number)

    findings.append({
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


# Normalize severity
def normalize(sev):
    sev = str(sev).upper()
    if sev in ["ERROR", "HIGH"]:
        return "HIGH"
    elif sev in ["WARNING", "MEDIUM"]:
        return "MEDIUM"
    elif sev in ["INFO", "LOW"]:
        return "LOW"
    return "UNKNOWN"


for finding in findings:
    finding["severity"] = normalize(finding["severity"])

# Sort by severity
priority = {"HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
findings.sort(key=lambda x: priority[x["severity"]])

# Summary counts
counts = Counter(f["severity"] for f in findings)
high_count = counts.get("HIGH", 0)
medium_count = counts.get("MEDIUM", 0)
low_count = counts.get("LOW", 0)
unknown_count = counts.get("UNKNOWN", 0)

max_count = max(high_count, medium_count, low_count, 1)

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
        <div class="subtitle">Semgrep findings for WebGoat</div>
      </div>
      <button class="toggle-btn" onclick="toggleTheme()"> Toggle Dark Mode</button>
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
        <input type="text" id="search" class="search-input" placeholder="Search findings by rule, file, CWE, OWASP, or description...">
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
      </h2>

      <p class="meta">
        <b>Impacted File:</b>
        <a class="github-link" href="{html.escape(str(finding['github_file_url']))}" target="_blank">
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
        <b>OWASP:</b> {html.escape(str(finding['owasp']))}
      </p>

      <p class="meta">
        <b>Remediation:</b><br>
        <a class="rule-link" href="{html.escape(str(finding['rule_url']))}" target="_blank">
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