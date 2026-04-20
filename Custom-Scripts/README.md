# 🐍 Custom-Scripts

This directory contains custom Python and Bash scripts for security automation, log analysis, reconnaissance, and reporting. Scripts are written to be readable and well-documented so they can serve as learning references as well as practical tools.

---

## 📂 Contents

| File | Language | Description |
|---|---|---|
| `log_analyzer.py` | Python 3 | Parse and triage Apache, syslog, and auth.log files |

---

## 🎯 Goals

- **Automate repetitive tasks** common in SOC and pen-test workflows
- **Demonstrate secure coding practices** — no hardcoded credentials, proper input validation
- **Extend and compose** — scripts are modular and designed to be piped or imported

---

## ▶️ Usage

Each script includes a `--help` flag and inline documentation. Example:

```bash
python3 log_analyzer.py --file /var/log/auth.log --type auth
python3 log_analyzer.py --file /var/log/auth.log --type auth --threshold 5
```

---

## 🛠️ Requirements

- Python 3.8+
- No third-party dependencies for core scripts (stdlib only)
- Optional: `rich` library for coloured terminal output where noted

---

*See individual script docstrings for detailed usage information.*
