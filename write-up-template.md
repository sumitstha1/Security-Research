# Technical Write-Up Template

> **Title:** [Descriptive title of the research, lab, or CTF challenge]
> **Author:** [Your name / handle]
> **Date:** YYYY-MM-DD
> **Category:** Blue Team / AppSec / CTF / Malware Analysis / Network Security
> **Difficulty:** Beginner / Intermediate / Advanced
> **Tags:** `tag1` `tag2` `tag3`

---

## 1. Overview

*A concise (2–4 sentence) summary of what this write-up covers, why it is relevant, and what the reader will learn.*

---

## 2. Objectives

- [ ] Objective one
- [ ] Objective two
- [ ] Objective three

---

## 3. Environment & Prerequisites

| Item | Details |
|---|---|
| **Platform / Lab** | e.g. TryHackMe, HackTheBox, local VM |
| **Target OS** | e.g. Ubuntu 22.04, Windows Server 2019 |
| **Attacker OS** | e.g. Kali Linux 2024.1 |
| **Tools Required** | e.g. Burp Suite, Nmap, Python 3 |
| **Network Setup** | e.g. Isolated VPN, NAT network |

---

## 4. Reconnaissance / Information Gathering

*Describe the initial enumeration steps. Include commands run and relevant output.*

```bash
# Example command
nmap -sC -sV -oN initial_scan.txt <TARGET_IP>
```

**Key findings:**
- Finding one
- Finding two

---

## 5. Vulnerability Identification

*Explain the vulnerability or security weakness discovered. Reference CVEs, CWEs, or OWASP categories where applicable.*

| Attribute | Detail |
|---|---|
| **Vulnerability** | e.g. SQL Injection — CWE-89 |
| **OWASP Category** | e.g. A03:2021 – Injection |
| **CVE (if applicable)** | CVE-YYYY-NNNNN |
| **Severity** | Critical / High / Medium / Low / Informational |
| **CVSS Score** | e.g. 9.8 |

---

## 6. Exploitation / Lab Walkthrough

*Step-by-step walkthrough of the exploit or lab exercise. Include screenshots, command output, and payloads where relevant.*

### Step 1 — [Action]

*Description of what you did and why.*

```
[code, payload, or command output]
```

### Step 2 — [Action]

*Description.*

```
[code, payload, or command output]
```

---

## 7. Proof of Compromise / Evidence

*Include screenshots, flags captured, hashes, or other evidence of successful exploitation.*

```
Flag: FLAG{example_flag_here}
```

---

## 8. Impact Analysis

*Explain the real-world impact if this vulnerability were present in a production environment.*

- **Confidentiality:** High / Medium / Low — *reason*
- **Integrity:** High / Medium / Low — *reason*
- **Availability:** High / Medium / Low — *reason*

---

## 9. Remediation & Mitigations

*Provide actionable developer-focused recommendations to fix or mitigate the vulnerability.*

1. **Primary fix:** e.g. Use parameterised queries / prepared statements
2. **Defence-in-depth:** e.g. Apply WAF rules, principle of least privilege
3. **Detection:** e.g. Alert on anomalous query patterns in SIEM

```python
# Example: safe parameterised query (Python + SQLite)
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

---

## 10. Lessons Learned

*Reflect on what you learned from this exercise. What would you do differently next time?*

- Key takeaway one
- Key takeaway two

---

## 11. References

- [Reference 1](https://example.com)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [CVE Details](https://www.cvedetails.com/)

---

*This write-up follows the standard template from [Security-Research](../README.md).*
