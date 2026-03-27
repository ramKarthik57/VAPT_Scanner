import requests
import socket
import ssl
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def fingerprint_technology(url, headers, text):
    """Detect server, framework, and CMS from response"""
    tech = []
    
    # 1. Header Analysis
    server = headers.get("Server", "")
    if server:
        tech.append({"name": "Web Server", "value": server})
        
    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        tech.append({"name": "Framework / Engine", "value": powered_by})

    asp_net = headers.get("X-AspNet-Version", "")
    if asp_net:
        tech.append({"name": "ASP.NET Version", "value": asp_net})

    # 2. HTML Meta Analysis
    try:
        soup = BeautifulSoup(text, "html.parser")
        generator = soup.find("meta", {"name": "generator"})
        if generator and generator.get("content"):
            tech.append({"name": "CMS / Generator", "value": generator["content"]})
    except:
        pass

    # 3. Cookie Analysis
    set_cookie = headers.get("Set-Cookie", "").lower()
    if "phpsessid" in set_cookie:
        tech.append({"name": "Language", "value": "PHP"})
    elif "jsessionid" in set_cookie:
        tech.append({"name": "Language", "value": "Java/JSP"})
    elif "sessionid" in set_cookie and "django" in set_cookie:
        tech.append({"name": "Framework", "value": "Django"})
    elif "rack.session" in set_cookie:
        tech.append({"name": "Framework", "value": "Ruby on Rails"})

    # Deduplicate
    unique_tech = []
    seen = set()
    for t in tech:
        val = t["value"].strip()
        if val not in seen:
            seen.add(val)
            unique_tech.append(t)
            
    return unique_tech

def check_ssl(hostname):
    """Retrieve SSL/TLS certificate information"""
    ssl_info = {}
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                
                # We can't easily parse x509 strictly without cryptography lib, 
                # but we can get basic protocol and cipher info
                ssl_info["Protocol"] = ssock.version()
                ssl_info["Cipher"] = cipher[0]
                ssl_info["Valid"] = True
    except Exception as e:
        ssl_info["Valid"] = False
        ssl_info["Error"] = str(e)
        
    return ssl_info

def check_dns(hostname):
    """Get basic DNS info"""
    dns_info = {}
    try:
        ip = socket.gethostbyname(hostname)
        dns_info["Resolved IP"] = ip
    except Exception as e:
        dns_info["Resolved IP"] = "Unknown"
        
    return dns_info

def comprehensive_header_audit(headers, is_https):
    """Check all security-relevant headers"""
    audit = []
    
    # Content-Security-Policy
    csp = headers.get("Content-Security-Policy", "")
    audit.append({
        "header": "Content-Security-Policy",
        "status": "Pass" if csp else "Fail",
        "value": csp if csp else "Missing",
        "recommendation": "Implement CSP to prevent XSS and data injection attacks."
    })
        
    # Strict-Transport-Security (only for HTTPS)
    if is_https:
        hsts = headers.get("Strict-Transport-Security", "")
        audit.append({
            "header": "Strict-Transport-Security",
            "status": "Pass" if hsts else "Fail",
            "value": hsts if hsts else "Missing",
            "recommendation": "Enforce HTTPS using HSTS to protect against man-in-the-middle attacks."
        })

    # X-Frame-Options
    xfo = headers.get("X-Frame-Options", "")
    audit.append({
        "header": "X-Frame-Options",
        "status": "Pass" if xfo else "Fail",
        "value": xfo if xfo else "Missing",
        "recommendation": "Set to DENY or SAMEORIGIN to protect against clickjacking."
    })

    # X-Content-Type-Options
    xcto = headers.get("X-Content-Type-Options", "")
    audit.append({
        "header": "X-Content-Type-Options",
        "status": "Pass" if xcto == "nosniff" else "Fail",
        "value": xcto if xcto else "Missing",
        "recommendation": "Set to 'nosniff' to prevent MIME-sniffing attacks."
    })

    # Referrer-Policy
    rp = headers.get("Referrer-Policy", "")
    audit.append({
        "header": "Referrer-Policy",
        "status": "Pass" if rp else "Fail",
        "value": rp if rp else "Missing",
        "recommendation": "Configure to prevent sensitive data leakage in the Referer header."
    })
    
    return audit

def perform_recon(target_url):
    """
    Perform passive reconnaissance on the target URL.
    Returns a dictionary of structured data for the report.
    """
    parsed = urlparse(target_url)
    hostname = parsed.netloc
    is_https = parsed.scheme == "https"
    
    recon_data = {
        "target": target_url,
        "hostname": hostname,
        "is_https": is_https,
        "technologies": [],
        "ssl": {},
        "dns": {},
        "header_audit": [],
        "response_time": 0
    }
    
    # 1. Basic Request & Fingerprinting
    try:
        start_time = time.time()
        r = requests.get(target_url, headers=HEADERS, verify=False, timeout=10, allow_redirects=True)
        recon_data["response_time"] = round(time.time() - start_time, 2)
        
        recon_data["technologies"] = fingerprint_technology(target_url, r.headers, r.text)
        recon_data["header_audit"] = comprehensive_header_audit(r.headers, is_https)
            
    except Exception as e:
        recon_data["error"] = str(e)
        
    # 2. SSL/TLS Info
    if is_https:
        recon_data["ssl"] = check_ssl(hostname)
        
    # 3. DNS Info
    recon_data["dns"] = check_dns(hostname.split(":")[0]) # remove port if present
    
    return recon_data
