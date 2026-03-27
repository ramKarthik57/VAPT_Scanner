import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import urllib3
import re
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# Common paths that might contain vulnerabilities, even if unlinked
COMMON_PATHS = [
    "/admin", "/admin.php", "/login", "/login.php",
    "/api", "/api/v1", "/wp-admin", "/administrator",
    "/phpmyadmin", "/dashboard", "/config", "/.git/config",
    "/backup.zip", "/test", "/dev", "/old"
]

API_PATHS = [
    "/swagger.json", "/api/swagger.json", "/openapi.json", 
    "/api/openapi.json", "/v2/api-docs", "/v3/api-docs"
]

def get_base_url(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def normalize_url(url):
    """Strip fragments and normalize trailing slashes consistently"""
    parsed = urlparse(url)
    path = parsed.path if parsed.path else "/"
    clean_url = f"{parsed.scheme}://{parsed.netloc}{path}"
    if parsed.query:
        clean_url += f"?{parsed.query}"
    return clean_url

def parse_robots_txt(base_url):
    """Extract allowed/disallowed paths and sitemap from robots.txt"""
    urls = set()
    sitemaps = []
    try:
        r = requests.get(urljoin(base_url, "/robots.txt"), headers=HEADERS, verify=False, timeout=5)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and not path.startswith("*"):
                        if path.startswith("/"):
                            urls.add(urljoin(base_url, path))
                elif line.lower().startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    sitemaps.append(sitemap_url)
    except:
        pass
    return urls, sitemaps

def parse_sitemap(sitemap_url):
    """Extract URLs from a sitemap XML"""
    urls = set()
    try:
        r = requests.get(sitemap_url, headers=HEADERS, verify=False, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "xml")
            for loc in soup.find_all("loc"):
                urls.add(loc.text.strip())
    except:
        pass
    return urls

def parse_swagger_api(api_json_url):
    """Parses an OpenAPI/Swagger definition to extract hidden API endpoints."""
    urls = set()
    try:
        r = requests.get(api_json_url, headers=HEADERS, verify=False, timeout=5)
        if r.status_code == 200 and "json" in r.headers.get("Content-Type", ""):
            data = r.json()
            base_url = get_base_url(api_json_url)
            base_path = data.get("basePath", "")
            
            paths = data.get("paths", {})
            for path, methods in paths.items():
                full_path = urljoin(base_url, base_path + path)
                query_params = []
                for method, details in methods.items():
                    if "parameters" in details:
                        for param in details["parameters"]:
                            if param.get("in") == "query":
                                query_params.append(f"{param.get('name')}=test")
                
                if query_params:
                    full_path += "?" + "&".join(query_params)
                urls.add(full_path)
    except Exception:
        pass
    return urls

def test_common_paths(base_url):
    """Check common paths for 200/401/403 responses"""
    valid_urls = set()
    def check_path(path):
        url = urljoin(base_url, path)
        try:
            r = requests.head(url, headers=HEADERS, verify=False, timeout=3, allow_redirects=True)
            if r.status_code in [200, 401, 403]:
                return url
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(check_path, COMMON_PATHS)
        for url in results:
            if url:
                valid_urls.add(url)
                
    return valid_urls

def extract_urls_from_page(html, base_url, source_url):
    """Extract URLs from a, form, script, iframe, and img tags"""
    found_urls = set()
    soup = BeautifulSoup(html, "html.parser")
    
    # Standard anchor links
    for link in soup.find_all("a", href=True):
        href = link["href"].strip()
        if not href.startswith(("javascript:", "mailto:", "#", "tel:", "data:")):
            found_urls.add(urljoin(source_url, href))
            
    # Form actions
    for form in soup.find_all("form"):
        action = form.get("action", "").strip()
        if action and not action.startswith(("javascript:", "mailto:", "#", "tel:")):
            found_urls.add(urljoin(source_url, action))
            
    # Resources that could have vulnerabilities or parameters
    for script in soup.find_all("script", src=True):
        src = script["src"].strip()
        found_urls.add(urljoin(source_url, src))
        
    for iframe in soup.find_all("iframe", src=True):
        src = iframe["src"].strip()
        found_urls.add(urljoin(source_url, src))
            
    return found_urls

def crawl_site(target_url, max_pages=15, deep_crawl=False):
    """
    Comprehensive crawler that discovers links through parsing, robots.txt, 
    sitemaps, and common path guessing.
    """
    base_url = get_base_url(target_url)
    target_domain = urlparse(base_url).netloc
    
    visited = set()
    to_visit = [normalize_url(target_url)]
    verified_urls = []
    
    # 1. Passive Discovery: robots.txt and sitemaps (mostly for deep crawls)
    if deep_crawl:
        robots_urls, sitemaps = parse_robots_txt(base_url)
        for url in robots_urls:
            if normalize_url(url) not in visited:
                to_visit.append(normalize_url(url))
                
        # Only parse first sitemap to avoid explosion
        if sitemaps:
            sitemap_urls = parse_sitemap(sitemaps[0])
            for url in list(sitemap_urls)[:10]: # Limit sitemap URLs
                if normalize_url(url) not in visited:
                    to_visit.append(normalize_url(url))

        # 2. Active Discovery: Common Paths
        common = test_common_paths(base_url)
        for url in common:
            if normalize_url(url) not in visited:
                to_visit.append(normalize_url(url))

        # 3. API Auto-Discovery (ZAP Parity feature)
        def check_api(path):
            url = urljoin(base_url, path)
            try:
                r = requests.head(url, headers=HEADERS, verify=False, timeout=3)
                if r.status_code in [200, 301, 302] and "json" in r.headers.get("Content-Type", ""):
                    return url
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=3) as executor:
            api_results = executor.map(check_api, API_PATHS)
            for api_url in api_results:
                if api_url:
                    api_endpoints = parse_swagger_api(api_url)
                    for ep in api_endpoints:
                        if normalize_url(ep) not in visited:
                            to_visit.append(normalize_url(ep))

    # 3. Active Crawling
    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        norm_url = normalize_url(url)
        
        if norm_url in visited:
            continue
            
        visited.add(norm_url)
        
        try:
            r = requests.get(url, timeout=8, headers=HEADERS, verify=False, allow_redirects=True)
            # Use the final URL after redirects if it's still on the same domain
            final_url = r.url
            if urlparse(final_url).netloc == target_domain:
                norm_final = normalize_url(final_url)
                if norm_final not in verified_urls:
                    verified_urls.append(norm_final)
                    
            # Only parse HTML pages for further links
            content_type = r.headers.get("Content-Type", "")
            if "text/html" in content_type:
                found = extract_urls_from_page(r.text, base_url, final_url)
                for f_url in found:
                    f_netloc = urlparse(f_url).netloc
                    # Map same domain or subdomains
                    if f_netloc == target_domain or f_netloc.endswith("." + target_domain):
                        norm_f = normalize_url(f_url)
                        if norm_f not in visited and norm_f not in to_visit:
                            to_visit.append(norm_f)

        except requests.exceptions.RequestException:
            continue
        except Exception:
            continue

    # Ensure the original target is included if it somehow was missed
    norm_target = normalize_url(target_url)
    if not any(u == norm_target for u in verified_urls):
        verified_urls.insert(0, norm_target)

    # Sort to put URLs with query parameters first, as they are most likely to be vulnerable
    verified_urls.sort(key=lambda x: 0 if "?" in x else 1)
    
    # Cap at max_pages, but prioritize parameter URLs
    return verified_urls[:max_pages]


def discover_forms(url):
    """Extract form details for active POST injection testing"""
    forms = []
    try:
        r = requests.get(url, timeout=8, headers=HEADERS, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")

        for idx, form in enumerate(soup.find_all("form")):
            action = form.get("action", "")
            # Resolve relative action URLs
            full_action = urljoin(url, action) if action else url
            method = form.get("method", "GET").upper()
            
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                type_attr = inp.get("type", "text").lower()
                value = inp.get("value", "")
                inputs.append({
                    "name": name,
                    "type": type_attr,
                    "default": value
                })
                
            forms.append({
                "id": f"form_{idx}",
                "source_url": url,
                "action": full_action,
                "method": method,
                "inputs": inputs
            })
    except Exception:
        pass

    return forms