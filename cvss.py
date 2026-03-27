def get_vulnerability_data(vuln_type, header=None):
    """
    Returns enriched vulnerability data including CVSS, Severity, OWASP mapping, 
    CWE ID, description, and remediation advice.
    """

    # ----------------------------------------
    # Comprehensive Knowledge Base
    # ----------------------------------------
    METRICS = {
        # --- SQL Injection ---
        "Error-Based SQL Injection": {
            "impact": 0.9, "exploitability": 0.8,
            "cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "desc": "The application returns database error messages indicating that user input is interpreted as an SQL command.",
            "remed": "Use parameterized queries (Prepared Statements) for all database access. Never concatenate user input directly into SQL strings."
        },
        "Boolean-Based Blind SQLi": {
            "impact": 0.85, "exploitability": 0.75,
            "cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "desc": "The application's response changes depending on whether an injected SQL condition evaluates to true or false.",
            "remed": "Implement strict input validation and use parameterized queries. Ensure ORM frameworks are used securely."
        },
        "Time-Based Blind SQLi": {
            "impact": 0.85, "exploitability": 0.7,
            "cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "desc": "The application takes longer to respond when a time-delay SQL payload is injected, proving code execution.",
            "remed": "Use stored procedures or parameterized queries. Validate all input types and lengths before processing."
        },
        "Content-Length Blind SQLi": {
            "impact": 0.75, "exploitability": 0.7,
            "cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "desc": "The application response size differs significantly based on injected SQL payloads.",
            "remed": "Parameterize queries and ensure consistent error handling that does not reflect database state."
        },
        "Header-Based SQL Injection": {
            "impact": 0.8, "exploitability": 0.6,
            "cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "desc": "SQL injection was successful by manipulating standard HTTP headers (like User-Agent).",
            "remed": "Treat all HTTP headers as untrusted user input. Parameterize when logging headers to databases."
        },
        "Cookie-Based SQL Injection": {
            "impact": 0.8, "exploitability": 0.6,
            "cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "desc": "The application processes cookie values insecurely, allowing SQL injection.",
            "remed": "Sign and encrypt cookies. Do not use direct database lookups based on unverified cookie values."
        },
        "NoSQL Injection": {
            "impact": 0.9, "exploitability": 0.75,
            "cwe": "CWE-943", "owasp": "A03:2021-Injection",
            "desc": "JSON payloads containing NoSQL query operators (like $ne) altered the application logic.",
            "remed": "Sanitize input, use strongly typed schemas, and avoid passing raw objects to NoSQL query APIs."
        },

        # --- XSS ---
        "Reflected XSS": {
            "impact": 0.6, "exploitability": 0.8,
            "cwe": "CWE-79", "owasp": "A03:2021-Injection",
            "desc": "User input is immediately reflected into the webpage without undergoing proper HTML entity encoding.",
            "remed": "Context-aware output encoding (HTML, JavaScript, CSS) must be applied to all user-controlled data before rendering."
        },
        "Attribute Context XSS": {
            "impact": 0.65, "exploitability": 0.8,
            "cwe": "CWE-79", "owasp": "A03:2021-Injection",
            "desc": "Input is reflected inside an HTML attribute allowing breakout and JavaScript execution.",
            "remed": "Ensure proper attribute encoding. Do not allow users to control element attributes directly."
        },
        "Script Context XSS": {
            "impact": 0.7, "exploitability": 0.75,
            "cwe": "CWE-79", "owasp": "A03:2021-Injection",
            "desc": "Data is reflected directly inside a <script> block, allowing immediate code execution.",
            "remed": "Use JSON serialization for data passed to JavaScript. Avoid injecting strings directly into script contexts."
        },
        "JSON Reflected XSS": {
            "impact": 0.6, "exploitability": 0.7,
            "cwe": "CWE-79", "owasp": "A03:2021-Injection",
            "desc": "Malicious script tags were reflected in JSON responses served with a dangerous Content-Type.",
            "remed": "Ensure API endpoints return responses with 'Content-Type: application/json' and use X-Content-Type-Options: nosniff."
        },
        "Template Injection": {
            "impact": 0.85, "exploitability": 0.75,
            "cwe": "CWE-1336", "owasp": "A03:2021-Injection",
            "desc": "Server-Side Template Injection (SSTI) allows attackers to execute arbitrary code via template engines.",
            "remed": "Use logic-less templates. Never pass raw user input as part of the template structure itself."
        },

        # --- Access Control ---
        "Insecure Direct Object Reference": {
            "impact": 0.8, "exploitability": 0.7,
            "cwe": "CWE-639", "owasp": "A01:2021-Broken Access Control",
            "desc": "An attacker can bypass authorization and access other users' data by modifying parameters like IDs.",
            "remed": "Implement robust access control checks in the backend for every object accessed by a user."
        },
        "Directory Traversal": {
            "impact": 0.85, "exploitability": 0.7,
            "cwe": "CWE-22", "owasp": "A01:2021-Broken Access Control",
            "desc": "Arbitrary files on the server file system can be accessed using dot-dot-slash (../) sequences.",
            "remed": "Validate input against an allowlist and ensure access is restricted only to intended directories."
        },
        "Local File Inclusion": {
            "impact": 0.9, "exploitability": 0.75,
            "cwe": "CWE-98", "owasp": "A01:2021-Broken Access Control",
            "desc": "Dynamic inclusion of files allows attackers to execute local server files or configuration scripts.",
            "remed": "Avoid passing user supply to filesystem APIs. Use indirect object references instead."
        },
        "Open Redirect": {
            "impact": 0.4, "exploitability": 0.6,
            "cwe": "CWE-601", "owasp": "A01:2021-Broken Access Control",
            "desc": "The application redirects users to arbitrary external URLs specified in parameters.",
            "remed": "Validate target URLs against a strict allowlist of authorized destinations before redirecting."
        },

        # --- Misconfiguration ---
        "HTTP Method Misconfiguration": {
            "impact": 0.5, "exploitability": 0.5,
            "cwe": "CWE-749", "owasp": "A05:2021-Security Misconfiguration",
            "desc": "Dangerous HTTP methods (like TRACE, PUT, or DELETE) are enabled when they are not required.",
            "remed": "Disable all HTTP methods except those absolutely necessary (typically GET, POST, and HEAD)."
        },
        "Clickjacking Vulnerability": {
            "impact": 0.45, "exploitability": 0.6,
            "cwe": "CWE-1021", "owasp": "A05:2021-Security Misconfiguration",
            "desc": "The page can be framed by external sites, potentially tricking users into clicking malicious links.",
            "remed": "Implement the X-Frame-Options: DENY header or a robust Content-Security-Policy with frame-ancestors."
        },
        "Server Banner Disclosure": {
            "impact": 0.3, "exploitability": 0.4,
            "cwe": "CWE-200", "owasp": "A05:2021-Security Misconfiguration",
            "desc": "The server exposes exact version information, aiding attackers in identifying known exploits.",
            "remed": "Configure the web server to suppress or obfuscate version banners and X-Powered-By headers."
        },
        "Directory Listing Enabled": {
            "impact": 0.55, "exploitability": 0.5,
            "cwe": "CWE-548", "owasp": "A05:2021-Security Misconfiguration",
            "desc": "The web server exposes a directory index, leaking file structures and potential sensitive content.",
            "remed": "Disable directory browsing/indexing in the web server configuration."
        },
        "CORS Misconfiguration": {
            "impact": 0.6, "exploitability": 0.6,
            "cwe": "CWE-942", "owasp": "A05:2021-Security Misconfiguration",
            "desc": "Cross-Origin Resource Sharing (CORS) allows requests from arbitrary origins or reflects the Origin header.",
            "remed": "Restrict CORS policies strictly to trusted domains. Do not use exact wildcard '*' if credentials are supported."
        },

        # --- Authentication / Session ---
        "Weak Cookie Configuration": {
            "impact": 0.6, "exploitability": 0.65,
            "cwe": "CWE-614", "owasp": "A07:2021-Identification and Authentication Failures",
            "desc": "Session cookies are missing the Secure, HttpOnly, or SameSite flags, increasing hijack risk.",
            "remed": "Set HttpOnly, Secure, and SameSite=Strict/Lax for all session cookies."
        },
        "Missing Rate Limiting": {
            "impact": 0.65, "exploitability": 0.7,
            "cwe": "CWE-770", "owasp": "A07:2021-Identification and Authentication Failures",
            "desc": "The endpoint does not restrict the number of requests, enabling brute-force and DoS attacks.",
            "remed": "Implement strict rate limiting and progressive delays for authentication and sensitive endpoints."
        },
        "Missing CSRF Protection": {
            "impact": 0.6, "exploitability": 0.65,
            "cwe": "CWE-352", "owasp": "A01:2021-Broken Access Control",
            "desc": "The application contains state-changing forms that do not employ anti-CSRF tokens.",
            "remed": "Implement unique, unpredictable anti-CSRF tokens for all state-changing operations, or use SameSite cookies."
        },

        # --- Info Disclosure / Data Risks ---
        "Sensitive Data Exposure": {
            "impact": 0.85, "exploitability": 0.6,
            "cwe": "CWE-200", "owasp": "A02:2021-Cryptographic Failures",
            "desc": "Sensitive configuration files, backups, or version control directories are publicly accessible.",
            "remed": "Remove all non-essential and sensitive files from the webroot. Restrict access to hidden directories."
        },
        "Unencrypted Connection (HTTP)": {
            "impact": 0.7, "exploitability": 0.5,
            "cwe": "CWE-319", "owasp": "A02:2021-Cryptographic Failures",
            "desc": "The application transmits data over unencrypted HTTP, risking interception.",
            "remed": "Enforce HTTPS globally and implement HTTP Strict Transport Security (HSTS)."
        },
        "Mixed Content Vulnerability": {
            "impact": 0.5, "exploitability": 0.6,
            "cwe": "CWE-319", "owasp": "A02:2021-Cryptographic Failures",
            "desc": "An HTTPS page loads scripts or resources over unencrypted HTTP.",
            "remed": "Ensure all resources are loaded via relative paths or explicit HTTPS URLs."
        },

        # --- Logic ---
        "Business Logic Flaw": {
            "impact": 0.6, "exploitability": 0.5,
            "cwe": "CWE-840", "owasp": "A04:2021-Insecure Design",
            "desc": "The application allows logical circumvention, such as placing orders with negative item quantities.",
            "remed": "Implement rigorous server-side validation for all business operations and state transitions."
        }
    }

    # ----------------------------------------
    # Special Handling for Security Headers
    # ----------------------------------------
    if vuln_type == "Missing Security Header":
        if header == "Content-Security-Policy":
            impact = 0.6; exploitability = 0.6; cwe = "CWE-116"; desc = "Missing CSP exposes to XSS."
        elif header == "X-Frame-Options":
            impact = 0.45; exploitability = 0.6; cwe = "CWE-1021"; desc = "Missing X-Frame-Options exposes to clickjacking."
        elif header == "Strict-Transport-Security":
            impact = 0.55; exploitability = 0.6; cwe = "CWE-319"; desc = "Missing HSTS allows downgrade attacks."
        else:
            impact = 0.4; exploitability = 0.5; cwe = "CWE-693"; desc = f"Missing {header} security header."
            
        owasp = "A05:2021-Security Misconfiguration"
        remed = f"Implement the {header} header properly in the web server configuration."

    elif vuln_type in METRICS:
        impact = METRICS[vuln_type]["impact"]
        exploitability = METRICS[vuln_type]["exploitability"]
        cwe = METRICS[vuln_type]["cwe"]
        owasp = METRICS[vuln_type]["owasp"]
        desc = METRICS[vuln_type]["desc"]
        remed = METRICS[vuln_type]["remed"]

    else:
        # Fallback for unknown/dynamic types
        impact = 0.3
        exploitability = 0.4
        cwe = "CWE-Unknown"
        owasp = "A00:Unknown"
        desc = "A vulnerability was detected but lacks a detailed signature."
        remed = "Investigate the affected endpoint manually."

    # ----------------------------------------
    # Score Calculation (CVSS 3.x simplified)
    # ----------------------------------------
    base_score = round((impact * 6 + exploitability * 4), 1)
    score = min(10.0, round(base_score, 1))

    if score >= 9.0:
        severity = "Critical"
    elif score >= 7.0:
        severity = "High"
    elif score >= 4.0:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "score": score,
        "severity": severity,
        "cwe": cwe,
        "owasp": owasp,
        "desc": desc,
        "remediation": remed
    }