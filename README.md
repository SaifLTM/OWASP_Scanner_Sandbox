# SAST Dashboard with Semgrep

## Overview

This project implements an automated static application security testing (SAST) pipeline that analyzes source code for vulnerabilities and generates a structured HTML dashboard.

The system uses Semgrep as the analysis engine and GitHub Actions for automation. It scans a target repository, processes the results, and produces a report that highlights security issues along with severity levels and references for remediation.

This project demonstrates how to build a lightweight security analysis platform by leveraging existing tooling and focusing on reporting, automation, and usability.

---

## Features

- Static code analysis using Semgrep
- Automated scanning via GitHub Actions
- Integration with external repositories such as OWASP WebGoat
- HTML dashboard output with:
  - Vulnerability type
  - File and line number
  - Severity classification (High, Medium, Low)
  - CWE and OWASP references
  - Links to remediation guidance
- Search and filtering functionality within the dashboard

---

## Architecture

The system follows a simple pipeline:

1. Clone target repository (e.g., WebGoat)
2. Run Semgrep scan using predefined rules (OWASP Top 10)
3. Output findings in JSON format
4. Process results with a Python script
5. Generate an HTML dashboard
