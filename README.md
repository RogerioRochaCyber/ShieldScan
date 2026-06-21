# 🛡️ ShieldScan

**Web Security Scanner** — Automated security analysis tool that scans websites and generates detailed security reports.

## 🔍 What it does

- Analyzes **HTTP Security Headers** (CSP, HSTS, X-Frame-Options, X-Content-Type, Referrer-Policy, Permissions-Policy, X-XSS-Protection)
- **SSL/HTTPS verification** — checks certificate validity
- **Security scoring system** — 0 to 100 score based on header criticality
- **SSRF protection** — blocks internal/private IPs to prevent Server-Side Request Forgery attacks
- **PDF report generation** — professional security reports with ReportLab
- **Professional dark mode UI** — built with Flask

## 🛠️ Tech Stack

- Python / Flask
- ReportLab (PDF generation)
- Requests / Socket libraries

## 🚀 How to run

```bash
pip install -r requirements.txt
python scanner_.py
```

## 👤 Author

**Rogério Rocha** — Cybersecurity Sales Engineer | AI Security Builder  
[LinkedIn](https://www.linkedin.com/in/rogério-rocha-bb8584289)

---
*Built as part of a cybersecurity portfolio focused on web security and AI security.*
