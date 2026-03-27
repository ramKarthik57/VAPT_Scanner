import requests
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Shared session with realistic User-Agent
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
})
SESSION.verify = False

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
from core.waf_evasion import get_evasion_payloads, test_waf_blocking


# =====================================================
# ADVANCED SQL INJECTION ENGINE (GET & POST)
# =====================================================

def detect_advanced_sqli(url, forms=None, deep=False):
    findings = []
    if forms is None:
        forms = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    try:
        base = SESSION.get(url, timeout=5)
        base_text = base.text
        base_length = len(base_text)
    except:
        return findings

    sql_errors = [
        "sql syntax", "mysql", "odbc", "ora-",
        "postgres", "syntax error", "unclosed quotation",
        "microsoft ole db", "you have an error in your sql",
        "supplied argument is not a valid",
        "pg_query", "sqlite3", "warning: mysql"
    ]

    # --- GET Testing ---
    if params:
        for param in params:
            tp = params.copy()
            
            # Error-Based
            tp[param] = "'"
            try:
                r = SESSION.get(urllib3.util.parse_url(urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))).url, timeout=5)
                if any(err in r.text.lower() for err in sql_errors):
                    findings.append({"type": "Error-Based SQL Injection", "confidence": "High", "evidence": f"GET param {param}"})
                    break
            except:
                pass
                
            # Boolean-Based
            fp = params.copy()
            tp[param] = "' AND 1=1--"
            fp[param] = "' AND 1=2--"
            try:
                r_true = SESSION.get(urlunparse(parsed._replace(query=urlencode(tp, doseq=True))), timeout=5)
                r_false = SESSION.get(urlunparse(parsed._replace(query=urlencode(fp, doseq=True))), timeout=5)
                if (abs(len(r_true.text) - base_length) < 200 and abs(len(r_false.text) - base_length) > 500 and
                        r_true.status_code == base.status_code and r_true.text != r_false.text):
                    findings.append({"type": "Boolean-Based Blind SQLi", "confidence": "High", "evidence": f"GET param {param}"})
            except:
                pass
                
            # Time-Based
            if deep:
                tp[param] = "' AND SLEEP(3)--"
                try:
                    start = time.time()
                    SESSION.get(urlunparse(parsed._replace(query=urlencode(tp, doseq=True))), timeout=8)
                    elapsed = time.time() - start
                    if elapsed > 2.5:
                        findings.append({"type": "Time-Based Blind SQLi", "confidence": "High", "evidence": f"GET param {param}"})
                except:
                    pass

    # --- POST (Form) Testing ---
    for form in forms:
        if form["method"] == "POST":
            action = form["action"]
            data = {inp["name"]: inp.get("default", "") for inp in form["inputs"] if inp["name"]}
            
            for key in data.keys():
                test_data = data.copy()
                
                # Error-Based POST
                test_data[key] = "test'"
                try:
                    r = SESSION.post(action, data=test_data, timeout=5)
                    if any(err in r.text.lower() for err in sql_errors):
                        findings.append({"type": "Error-Based SQL Injection", "confidence": "High", "evidence": f"POST form param {key}"})
                        break
                except:
                    pass

                # Boolean POST
                test_data_true = data.copy(); test_data_true[key] = "test' OR 1=1--"
                test_data_false = data.copy(); test_data_false[key] = "test' AND 1=2--"
                try:
                    r_true = SESSION.post(action, data=test_data_true, timeout=5)
                    r_false = SESSION.post(action, data=test_data_false, timeout=5)
                    if r_true.text != r_false.text and len(r_true.text) > len(r_false.text):
                         # Just a simple heuristic for POST
                        findings.append({"type": "Boolean-Based Blind SQLi", "confidence": "Medium", "evidence": f"POST form param {key}"})
                except:
                    pass

    # Header-Based & Cookie-Based
    if deep and base.status_code == 200:
        try:
            r = SESSION.get(url, headers={"User-Agent": "' OR 1=1--"}, timeout=5)
            if any(err in r.text.lower() for err in sql_errors):
                findings.append({"type": "Header-Based SQL Injection", "confidence": "Medium", "evidence": "User-Agent header"})
        except:
            pass

        try:
            r = SESSION.get(url, cookies={"session": "' OR 1=1--"}, timeout=5)
            if any(err in r.text.lower() for err in sql_errors):
                findings.append({"type": "Cookie-Based SQL Injection", "confidence": "Medium", "evidence": "session cookie"})
        except:
            pass

    return list({(f['type'], f['evidence']): f for f in findings}.values()) # Deduplicate


# =====================================================
# ADVANCED XSS ENGINE
# =====================================================

def detect_advanced_xss(url, forms=None):
    findings = []
    if forms is None:
        forms = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    canary = "xSs7TeSt9CaNaRy"

    # Reference payloads
    payloads = {
        "Reflected XSS": f"<script>alert('{canary}')</script>",
        "Attribute Context XSS": f'" onmouseover=alert("{canary}") x="',
        "Script Context XSS": f"';alert('{canary}');//",
        "Template Injection": "{{7*7}}"
    }

    def check_xss_response(text, payload_type):
        if payload_type == "Template Injection":
            return "49" in text and payloads["Template Injection"] not in text
        if payload_type == "Reflected XSS":
            return payloads["Reflected XSS"] in text and "&lt;script&gt;" not in text.split(canary)[0][-50:]
        if payload_type == "Attribute Context XSS":
            return 'onmouseover=alert(' in text and canary in text
        if payload_type == "Script Context XSS":
            return payloads["Script Context XSS"] in text
        return False

    # --- GET Testing ---
    if params:
        for param in params:
            for p_type, base_payload in payloads.items():
                for payload_mut in get_evasion_payloads(base_payload):
                    tp = params.copy()
                    tp[param] = payload_mut
                    try:
                        r = SESSION.get(urlunparse(parsed._replace(query=urlencode(tp, doseq=True))), timeout=5)
                        if test_waf_blocking(r):
                            continue # Try next mutation
                        if check_xss_response(r.text, p_type):
                            is_mutated = payload_mut != base_payload
                            evidence = f"GET param {param}" + (f" (WAF Bypassed via {payload_mut})" if is_mutated else "")
                            findings.append({"type": p_type, "confidence": "High", "evidence": evidence})
                            break # Found vulnerability, don't need to try more mutations
                    except:
                        pass

    # --- POST Testing ---
    for form in forms:
        if form["method"] == "POST":
            action = form["action"]
            data = {inp["name"]: inp.get("default", "test") for inp in form["inputs"] if inp["name"]}
            
            for key in data.keys():
                for p_type, base_payload in payloads.items():
                    for payload_mut in get_evasion_payloads(base_payload):
                        test_data = data.copy()
                        test_data[key] = payload_mut
                        try:
                            r = SESSION.post(action, data=test_data, timeout=5)
                            if test_waf_blocking(r):
                                continue
                            if check_xss_response(r.text, p_type):
                                is_mutated = payload_mut != base_payload
                                evidence = f"POST form param {key}" + (f" (WAF Bypassed via mutation)" if is_mutated else "")
                                findings.append({"type": p_type, "confidence": "High", "evidence": evidence})
                                break
                        except:
                            pass

    return list({(f['type'], f['evidence']): f for f in findings}.values())


# =====================================================
# OTHER DETECTIONS
# =====================================================

def detect_idor(url, forms=None):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    try:
        base = SESSION.get(url, timeout=5)
    except:
        return findings

    for param in params:
        if params[param][0].isdigit():
            tp = params.copy()
            tp[param] = str(int(params[param][0]) + 1)
            try:
                r = SESSION.get(urlunparse(parsed._replace(query=urlencode(tp, doseq=True))), timeout=5)
                if r.status_code == 200 and base.status_code == 200 and abs(len(r.text) - len(base.text)) > 100 and r.text != base.text:
                    findings.append({"type": "Insecure Direct Object Reference", "confidence": "Medium", "evidence": f"GET param {param}"})
                    break
            except:
                pass
    return findings


def detect_directory_traversal(url):
    findings = []
    try:
        r = SESSION.get(url.rstrip("/") + "/../../etc/passwd", timeout=5)
        if "root:" in r.text and "bin/bash" in r.text:
            findings.append({"type": "Directory Traversal", "confidence": "High", "evidence": "URL Path manipulation"})
    except:
        pass
        
    # Test query params if present
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    for param in params:
        tp = params.copy()
        tp[param] = "../../../../etc/passwd"
        try:
            r = SESSION.get(urlunparse(parsed._replace(query=urlencode(tp, doseq=True))), timeout=5)
            if "root:" in r.text and "bin/bash" in r.text:
                findings.append({"type": "Local File Inclusion", "confidence": "High", "evidence": f"GET param {param}"})
        except:
            pass
            
    return findings


def detect_cors_misconfig(url):
    findings = []
    try:
        r = SESSION.get(url, headers={"Origin": "https://evil.com"}, timeout=5)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if acao in ["*", "https://evil.com"]:
            findings.append({"type": "CORS Misconfiguration", "confidence": "High", "evidence": f"Origin reflection: {acao}"})
    except:
        pass
    return findings


def detect_information_disclosure(url):
    findings = []
    sensitive_paths = ["/.git/HEAD", "/.env", "/backup.zip", "/.git/config", "/docker-compose.yml", "/phpinfo.php", "/server-status"]
    for path in sensitive_paths:
        test_url = urljoin(url, path)
        try:
            r = SESSION.get(test_url, timeout=5)
            if r.status_code == 200 and len(r.text) > 0:
                if "/.git" in path and ("ref:" in r.text or "[core]" in r.text):
                    findings.append({"type": "Sensitive Data Exposure", "confidence": "High", "evidence": path})
                elif "/.env" in path and "=" in r.text and len(r.text) < 10000:
                    findings.append({"type": "Sensitive Data Exposure", "confidence": "High", "evidence": path})
                elif path == "/backup.zip" and r.headers.get("Content-Type", "").startswith("application/"):
                    findings.append({"type": "Sensitive Data Exposure", "confidence": "High", "evidence": path})
                elif path == "/phpinfo.php" and "PHP Version" in r.text:
                    findings.append({"type": "Sensitive Data Exposure", "confidence": "High", "evidence": path})
        except:
            pass
    return findings


def detect_csrf(url, forms=None):
    if not forms:
        return False
        
    for form in forms:
        if form["method"] == "POST":
            # Check for generic CSRF token names
            has_token = False
            for inp in form["inputs"]:
                name = str(inp.get("name", "")).lower()
                if any(t in name for t in ["csrf", "token", "authenticity", "nonce", "_xsrf"]):
                    has_token = True
                    break
            
            if not has_token:
                # If we see a POST form without a token, flag it
                # Additional verification: check if cookies are SameSite
                return True
                
    return False


def detect_business_logic(url, forms=None):
    findings = []
    if forms is None:
        forms = []
        
    price_params = ["price", "amount", "qty", "quantity", "total", "cost", "value"]

    # GET
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    for param in params:
        if param.lower() in price_params:
            tp = params.copy()
            tp[param] = "-1"
            try:
                r = SESSION.get(urlunparse(parsed._replace(query=urlencode(tp, doseq=True))), timeout=5)
                if r.status_code == 200:
                    findings.append({"type": "Business Logic Flaw", "confidence": "Medium", "evidence": f"GET param {param} accepted negative value"})
            except:
                pass

    # POST
    for form in forms:
        if form["method"] == "POST":
            for inp in form["inputs"]:
                if str(inp.get("name")).lower() in price_params:
                    findings.append({"type": "Business Logic Flaw", "confidence": "Low", "evidence": f"POST param {inp['name']} may lack server-side bounds checking"})
                    
    return findings


def detect_rate_limiting(url, forms=None):
    findings = []
    
    # We only care about rate limiting on login/auth related paths or forms
    is_auth_endpoint = False
    
    if any(k in url.lower() for k in ["login", "signin", "auth"]):
        is_auth_endpoint = True
        
    if forms:
        for f in forms:
            for inp in f["inputs"]:
                if str(inp.get("type")).lower() == "password":
                    is_auth_endpoint = True
                    break
                    
    if not is_auth_endpoint:
        return findings
        
    try:
        success = 0
        total_requests = 10
        for _ in range(total_requests):
            r = SESSION.get(url, timeout=3)
            if r.status_code == 429:
                return findings
            if "Retry-After" in r.headers or "X-RateLimit" in r.headers.get("", ""):
                return findings
            if r.status_code == 200:
                success += 1

        if success == total_requests:
            findings.append({"type": "Missing Rate Limiting", "confidence": "High", "evidence": "Auth endpoint allowed 10 unthrottled requests"})
    except:
        pass
        
    return findings


def detect_open_redirect(url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    for param in params:
        if param.lower() in ["redirect", "url", "next", "return", "returnurl", "goto", "redir", "dest"]:
            tp = params.copy()
            tp[param] = "https://evil.com"
            try:
                r = SESSION.get(urlunparse(parsed._replace(query=urlencode(tp, doseq=True))), allow_redirects=False, timeout=5)
                if "Location" in r.headers and "evil.com" in r.headers["Location"]:
                    findings.append({"type": "Open Redirect", "confidence": "High", "evidence": f"GET param {param}"})
            except:
                pass
    return findings


def detect_http_methods(url):
    findings = []
    for method in ["PUT", "DELETE", "TRACE"]:
        try:
            r = SESSION.request(method, url, timeout=5)
            if r.status_code in [200, 201, 204]:
                if method == "TRACE" and "TRACE" in r.text:
                    findings.append({"type": "HTTP Method Misconfiguration", "confidence": "High", "evidence": "TRACE enabled"})
                    break
                elif method in ["PUT", "DELETE"]:
                    get_r = SESSION.get(url, timeout=5)
                    if r.text != get_r.text:
                        findings.append({"type": "HTTP Method Misconfiguration", "confidence": "High", "evidence": f"{method} method accepted"})
                        break
        except:
            pass
    return findings


def detect_weak_cookies(url):
    findings = []
    try:
        r = SESSION.get(url, timeout=5)
        set_cookies = r.headers.get("Set-Cookie", "")
        if set_cookies:
            cookie_lower = set_cookies.lower()
            is_session_cookie = any(name in cookie_lower for name in ["session", "sid", "token", "auth", "jwt", "login"])
            if is_session_cookie:
                missing = []
                if "httponly" not in cookie_lower:
                    missing.append("HttpOnly")
                if "secure" not in cookie_lower:
                    missing.append("Secure")
                if "samesite" not in cookie_lower:
                    missing.append("SameSite")
                    
                if missing:
                    findings.append({"type": "Weak Cookie Configuration", "confidence": "High", "evidence": f"Missing flags: {', '.join(missing)}"})
    except:
        pass
    return findings


def detect_server_banner(url):
    findings = []
    try:
        r = SESSION.get(url, timeout=5)
        server = r.headers.get("Server", "")
        powered_by = r.headers.get("X-Powered-By", "")

        version_pattern = re.compile(r'[\d]+\.[\d]+')

        if server and version_pattern.search(server):
            findings.append({"type": "Server Banner Disclosure", "confidence": "High", "evidence": f"Server: {server}"})
        elif powered_by and version_pattern.search(powered_by):
            findings.append({"type": "Server Banner Disclosure", "confidence": "High", "evidence": f"X-Powered-By: {powered_by}"})
    except:
        pass
    return findings


def detect_directory_listing(url):
    findings = []
    try:
        r = SESSION.get(url, timeout=5)
        if ("Index of /" in r.text or "Parent Directory" in r.text) and r.status_code == 200:
            findings.append({"type": "Directory Listing Enabled", "confidence": "High", "evidence": "Directory index found"})
    except:
        pass
    return findings

def detect_mixed_content(url):
    findings = []
    if not url.startswith("https://"):
        return findings
    try:
        r = SESSION.get(url, timeout=5)
        if "http://" in r.text:
            soup = BeautifulSoup(r.text, "html.parser")
            for script in soup.find_all("script", src=True):
                if script["src"].startswith("http://"):
                    findings.append({"type": "Mixed Content Vulnerability", "confidence": "High", "evidence": "Active mixed content (script) loaded over HTTP"})
                    return findings
    except:
        pass
    return findings

def detect_command_injection(url, forms=None):
    findings = []
    if forms is None:
        forms = []
        
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Time-based blind payload
    payloads = [
        "; ping -c 4 127.0.0.1 #",
        "| ping -n 4 127.0.0.1 #",
        "& ping -c 4 127.0.0.1 #",
        "`ping -c 4 127.0.0.1`"
    ]
    
    # GET testing
    if params:
        for param in params:
            for payload in payloads:
                tp = params.copy()
                tp[param] = [payload]
                try:
                    start_time = time.time()
                    SESSION.get(urlunparse(parsed._replace(query=urlencode(tp, doseq=True))), timeout=6)
                    elapsed = time.time() - start_time
                    if elapsed > 3.0:
                        findings.append({"type": "Blind OS Command Injection", "confidence": "Medium", "evidence": f"GET param {param} delayed response {round(elapsed, 2)}s"})
                except Exception:
                    findings.append({"type": "Blind OS Command Injection", "confidence": "High", "evidence": f"GET param {param} timed out (likely payload execution)"})
                    
    # POST testing
    for form in forms:
        if form["method"] == "POST":
            action = form["action"]
            data = {inp["name"]: inp.get("default", "test") for inp in form["inputs"] if inp["name"]}
            for key in data.keys():
                for payload in payloads:
                    test_data = data.copy()
                    test_data[key] = payload
                    try:
                        start_time = time.time()
                        SESSION.post(action, data=test_data, timeout=6)
                        elapsed = time.time() - start_time
                        if elapsed > 3.0:
                            findings.append({"type": "Blind OS Command Injection", "confidence": "Medium", "evidence": f"POST form param {key} delayed response {round(elapsed, 2)}s"})
                    except Exception:
                        findings.append({"type": "Blind OS Command Injection", "confidence": "High", "evidence": f"POST form param {key} timed out (likely payload execution)"})
                        
    return list({(f['type'], f['evidence']): f for f in findings}.values())

def detect_dom_xss(url):
    findings = []
    try:
        r = SESSION.get(url, timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        scripts = soup.find_all('script')
        
        sources = ['location.hash', 'location.search', 'window.name', 'document.referrer']
        sinks = ['innerhtml', 'document.write', 'eval(', 'settimeout(', 'setinterval(', 'outerhtml']
        
        for script in scripts:
            code = script.string
            if not code:
                continue
                
            code_lower = code.lower()
            found_source = any(source in code_lower for source in sources)
            found_sink = any(sink in code_lower for sink in sinks)
            
            if found_source and found_sink:
                findings.append({
                    "type": "DOM-Based XSS (Static Warning)", 
                    "confidence": "Low", 
                    "evidence": "Source and Sink detected in same inline JS block"
                })
                break
    except Exception:
        pass
    return findings