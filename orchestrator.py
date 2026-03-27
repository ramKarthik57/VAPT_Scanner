import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
from crawler import crawl_site, discover_forms

class DistributedOrchestrator:
    """
    Intelligent orchestration layer for managing large-scale infrastructure assessments.
    Monitors latency and adapts scanning throughput to prevent Denial of Service.
    """
    
    def __init__(self, targets, max_workers=10):
        # Allow passing single string or list of strings
        self.targets = [targets] if isinstance(targets, str) else targets
        self.max_workers = max_workers
        self.global_results = {}
        
    def check_health_and_latency(self, test_url):
        try:
            start = time.time()
            r = requests.get(test_url, timeout=5)
            # Adapt constraints
            latency = time.time() - start
            if latency > 2.0:
                print(f"[ORCHESTRATOR] High latency ({round(latency,2)}s) on {test_url}. Reducing threads.")
                return 2  # Severe rate limit
            elif latency > 0.5:
                return 5  # Moderate rate limit
            return min(self.max_workers, 15)
        except Exception:
            return 0  # Host down
            
    def _scan_single_target(self, target, scan_func, config):
        """
        Executes the entire crawling and dynamic scanning flow for one host using its
        allowed thread capacity.
        """
        allowed_threads = self.check_health_and_latency(target)
        if allowed_threads == 0:
            return {"error": "Host unreachable"}
            
        print(f"[ORCHESTRATOR] Assigned {allowed_threads} worker threads to {target}")
        urls = crawl_site(target, max_pages=config.get("max_pages", 20), deep_crawl=config.get("deep_payloads", True))
        
        forms_map = {}
        for u in set(urls):
            forms_map[u] = discover_forms(u) or []
            
        findings = []
        csrf_flags = []
        
        with ThreadPoolExecutor(max_workers=allowed_threads) as executor:
            future_to_url = {
                executor.submit(scan_func, u, forms_map[u], config): u for u in urls
            }
            
            for future in as_completed(future_to_url):
                sub_findings, csrf = future.result()
                findings.extend(sub_findings)
                if csrf:
                    csrf_flags.append(future_to_url[future])
                    
        return {"findings": findings, "urls": urls, "csrf": csrf_flags}

    def run_distributed_scan(self, scan_func, config):
        """
        Dispatch all requested targets onto the threadpool.
        """
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=len(self.targets)) as global_executor:
            future_to_target = {
                global_executor.submit(self._scan_single_target, target, scan_func, config): target
                for target in self.targets
            }
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    res = future.result()
                    self.global_results[target] = res
                except Exception as e:
                    self.global_results[target] = {"error": str(e)}
                    
        duration = round(time.time() - start_time, 2)
        print(f"[ORCHESTRATOR] Distributed assessment completed in {duration}s")
        return self.global_results
