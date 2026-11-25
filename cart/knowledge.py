"""Knowledge base: severity, CWE / OWASP mapping and rule-based fixes.

Used by the rule-based remediation agent to attach a plain-English fix and a
reference patch to every proven finding.
"""

KB = {
    "sqli_auth_bypass": {
        "title": "SQL injection in login form (authentication bypass)",
        "severity": "critical", "cvss": 9.8, "cwe": "CWE-89", "owasp": "A03:2021 Injection",
        "impact": "Anyone can log in as any user, including the administrator, without a password.",
        "fix": "Use parameterised queries (placeholders) instead of building SQL with string formatting. "
               "Hash passwords (bcrypt/argon2) and add rate limiting on login.",
        "patch": 'row = db.execute(\n    "SELECT id, username, role FROM users WHERE username=? AND password=?",\n'
                 '    (username, password)).fetchone()',
    },
    "sqli": {
        "title": "SQL injection",
        "severity": "high", "cvss": 8.6, "cwe": "CWE-89", "owasp": "A03:2021 Injection",
        "impact": "Attacker can read data they should not see (e.g. every customer in the database).",
        "fix": "Use parameterised queries; never concatenate user input into SQL. Apply least-privilege DB accounts.",
        "patch": 'rows = db.execute(\n    "SELECT username, balance FROM users WHERE username LIKE ?",\n'
                 '    (f"%{holder}%",)).fetchall()',
    },
    "xss_reflected": {
        "title": "Reflected cross-site scripting (XSS)",
        "severity": "medium", "cvss": 6.1, "cwe": "CWE-79", "owasp": "A03:2021 Injection",
        "impact": "Attacker-supplied HTML/JS runs in the victim's browser (session theft, phishing).",
        "fix": "HTML-escape all user input on output (html.escape / template auto-escaping) and add a "
               "Content-Security-Policy header.",
        "patch": "shown = html.escape(q)",
    },
    "path_traversal": {
        "title": "Path traversal (arbitrary file read)",
        "severity": "high", "cvss": 7.5, "cwe": "CWE-22", "owasp": "A01:2021 Broken Access Control",
        "impact": "Attacker can read files outside the intended folder (configs, keys, source code).",
        "fix": "Resolve the final path and verify it stays inside the allowed base directory; "
               "prefer a whitelist of file names. Do NOT just strip '../' (bypassable with '....//').",
        "patch": "target = (FILES_DIR / name).resolve()\nif FILES_DIR.resolve() not in target.parents:\n    abort(403)",
    },
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
