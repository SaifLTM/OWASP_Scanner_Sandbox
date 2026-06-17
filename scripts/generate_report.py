import json
from collections import Counter

# Load Semgrep results
with open("output/results.json") as f:
    data = json.load(f)

results = data.get("results", [])

findings = []

# Extract fields + generate Semgrep rule link
for r in results:
    rule_id = r.get("check_id")
    meta = r.get("extra", {}).get("metadata", {})

    rule_url = f"https://semgrep.dev/r?q={rule_id}"

    findings.append({
        "rule_id": rule_id,
        "file": r.get("path"),
        "line": r.get("start", {}).get("line"),
        "severity": r.get("extra", {}).get("severity", "UNKNOWN"),
        "description": r.get("extra", {}).get("message", ""),
        "cwe": meta.get("cwe", "N/A"),
        "owasp": meta.get("owasp", "N/A"),
        "rule_url": rule_url
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

for f in findings:
    f["severity"] = normalize(f["severity"])

# Sort by severity
priority = {"HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
findings.sort(key=lambda x: priority[x["severity"]])

# Summary counts
counts = Counter(f["severity"] for f in findings)

# Generate HTML
html = f"""
<html>
<head>
<title>SAST Dashboard</title>
<style>
body {{ font-family: Arial; margin: 30px; }}
.high {{ color: red; }}
.medium {{ color: orange; }}
.low {{ color: green; }}
.card {{
  border: 1px solid #ddd;
  border-radius: 12px;
  padding: 15px;
  margin: 10px 0;
  box-shadow: 2px 2px 8px #eee;
}}
.link {{
  display: inline-block;
  margin-top: 8px;
  color: #1a73e8;
  text-decoration: none;
}}
.link:hover {{
  text-decoration: underline;
}}
</style>
</head>
<body>

<h1>🔒 SAST Security Dashboard</h1>

<h2>Summary</h2>
<ul>
<li>High: {counts.get("HIGH", 0)}</li>
<li>Medium: {counts.get("MEDIUM", 0)}</li>
<li>Low: {counts.get("LOW", 0)}</li>
</ul>

<input type="text" id="search" placeholder="Search findings..." style="padding:8px;width:300px">

<hr>
"""

# Render findings
for f in findings:
    html += f"""
    <div class="card">
        <h2 class="{f['severity'].lower()}">[{f['severity']}] {f['rule_id']}</h2>
        <p><b>File:</b> {f['file']}:{f['line']}</p>
        <p><b>Description:</b> {f['description']}</p>
        <p><b>CWE:</b> {f['cwe']} | <b>OWASP:</b> {f['owasp']}</p>

        <p><b>Remediation:</b></p>
        <a class="link" href="{f['rule_url']}" target="_blank">
            🔧 View Fix Guidance
        </a>
    </div>
    """

# Search functionality
html += """
<script>
document.getElementById('search').addEventListener('input', function(e) {
  let term = e.target.value.toLowerCase();
  document.querySelectorAll('.card').forEach(card => {
    card.style.display = card.innerText.toLowerCase().includes(term) ? '' : 'none';
  });
});
</script>
"""

html += "</body></html>"

# Save file
with open("output/security-report.html", "w") as f:
    f.write(html)

print(" Dashboard generated: output/security-report.html")