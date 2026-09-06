# CodeAlpha_SecureCodingReview

A secure coding review performed as part of the **CodeAlpha Cyber Security Internship** (Task 3).

## What this project does

- Audits a small sample Flask web application (`vulnerable_app.py`) for security vulnerabilities
- Identifies **7 findings** mapped to [OWASP Top 10](https://owasp.org/Top10/) categories, ranging from Medium to Critical severity
- Validates the findings using **bandit**, a Python static analysis tool
- Provides a fully remediated version of the application (`secure_app.py`) with each fix documented

## Files in this folder

| File | Description |
|------|--------------|
| `vulnerable_app.py` | The sample Flask app containing intentional vulnerabilities (subject of the audit). **Do not deploy this code.** |
| `CODE_REVIEW_REPORT.md` | The full review — every finding explained with its risk, severity, OWASP category, and recommended fix. |
| `secure_app.py` | The corrected version of the app, with fixes numbered to match the report. |
| `bandit_scan_output.txt` | Raw output from running the `bandit` static analyzer against `vulnerable_app.py`, confirming the findings independently. |

## Key findings summary

| # | Finding | Severity |
|---|---------|----------|
| 1 | Hardcoded secret key | High |
| 2 | Weak, unsalted password hashing (MD5) | Critical |
| 3 | SQL Injection (register & login) | Critical |
| 4 | Reflected XSS on `/dashboard` | High |
| 5 | Insecure deserialization (`pickle.loads`) | Critical |
| 6 | Path traversal on `/download` | High |
| 7 | Debug mode enabled with public bind address | Medium |

See [`CODE_REVIEW_REPORT.md`](./CODE_REVIEW_REPORT.md) for the full write-up.

## How the review was done

1. **Manual line-by-line inspection** of the application source, checking authentication, data storage, input handling, and file access code paths.
2. **Static analysis** with `bandit`:
   ```bash
   pip install bandit
   bandit vulnerable_app.py
   ```
3. Each finding was cross-referenced against the OWASP Top 10 to classify its category and severity.
4. A corrected version (`secure_app.py`) was written, fixing every finding using standard secure-coding practices (parameterized queries, salted password hashing, safe serialization, path validation, environment-based secrets, and auto-escaped templating).

## Disclaimer

`vulnerable_app.py` is deliberately insecure and exists only to demonstrate common vulnerability patterns for this review. It must never be deployed or exposed on a real network.

---

*Built for the CodeAlpha Cyber Security Internship, Task 3: Secure Coding Review.*
