import requests
import time
import statistics
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

class ZeroDayAnalyzer:
    """
    A research-grade zero-day detection module that uses statistical anomaly detection
    instead of predefined signatures to identify previously unknown vulnerability classes.
    """
    
    def __init__(self, target_url, forms=None):
        self.target = target_url
        self.forms = forms or []
        self.baseline_timing = []
        self.baseline_length = []
        self.anomaly_threshold = 2.5 # Z-score threshold for anomalies
        
    def _gather_baseline(self):
        """Establish standard application behavior baselines."""
        for _ in range(5):
            try:
                start = time.time()
                r = requests.get(self.target, timeout=10)
                dur = time.time() - start
                self.baseline_timing.append(dur)
                self.baseline_length.append(len(r.text))
            except Exception:
                pass
                
        if not self.baseline_length:
            return False
            
        self.mean_timing = statistics.mean(self.baseline_timing)
        self.stdev_timing = statistics.stdev(self.baseline_timing) if len(self.baseline_timing) > 1 else 0.1
        self.mean_length = statistics.mean(self.baseline_length)
        self.stdev_length = statistics.stdev(self.baseline_length) if len(self.baseline_length) > 1 else 10.0
        
        # Prevent zero division
        self.stdev_timing = max(self.stdev_timing, 0.05)
        self.stdev_length = max(self.stdev_length, 5.0)
        
        return True

    def calculate_z_score(self, value, mean, stdev):
        return abs(value - mean) / stdev

    def analyze_anomalies(self):
        """
        Injects abstract mutations (fuzzing) to trigger unexpected execution states.
        It flags interactions that cause significant deviation from normal application behavior.
        """
        if not self._gather_baseline():
            return []

        anomalies = []
        mutations = [
            "%%00",          # Null Byte
            "\'\"",          # Quote collision
            "../../",        # Path escape abstract
            "{{7*7}}",       # Template Abstract
            "${jndi:}",      # JNDI abstract
            "\\u0000",       # Unicode null
            "%2e%2e/",       # Encoded traverse
            "A" * 5000       # Buffer extreme
        ]
        
        parsed = urllib.parse.urlparse(self.target)
        target_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query = urllib.parse.parse_qsl(parsed.query)

        def test_mutation(mut):
            sub_anomalies = []
            
            # 1. Query Parameter Fuzzing
            if query:
                for idx, (k, v) in enumerate(query):
                    mutated_query = query.copy()
                    mutated_query[idx] = (k, v + mut)
                    mutated_url = target_base + "?" + urllib.parse.urlencode(mutated_query)
                    
                    try:
                        start = time.time()
                        r = requests.get(mutated_url, timeout=10)
                        dur = time.time() - start
                        
                        len_z = self.calculate_z_score(len(r.text), self.mean_length, self.stdev_length)
                        time_z = self.calculate_z_score(dur, self.mean_timing, self.stdev_timing)
                        
                        if len_z > self.anomaly_threshold and r.status_code == 200:
                            sub_anomalies.append({
                                "type": "Zero-Day Research Candidate / Anomaly",
                                "confidence": "Medium",
                                "evidence": f"Input '{mut}' caused length deviation Z-score: {round(len_z, 2)}",
                                "url": mutated_url
                            })
                            
                        # Only flag extreme time delays to prevent false positive server lag
                        if time_z > self.anomaly_threshold * 1.5 and dur > 3.0:
                            sub_anomalies.append({
                                "type": "Behavioral Timing Deviation (Potential DOS/Injection)",
                                "confidence": "High",
                                "evidence": f"Input '{mut}' caused timing delay Z-score: {round(time_z, 2)}",
                                "url": mutated_url
                            })
                            
                    except requests.exceptions.Timeout:
                        sub_anomalies.append({
                            "type": "Application Crash / Unhandled State",
                            "confidence": "High",
                            "evidence": f"Server timed out permanently serving mutation: {mut}",
                            "url": mutated_url
                        })
                    except Exception:
                        pass
                        
            # 2. Path Fuzzing
            try:
                mutated_path_url = self.target + "/" + mut
                start = time.time()
                r = requests.get(mutated_path_url, timeout=10)
                dur = time.time() - start
                
                # Check for unexpected success status codes on garbage paths
                if r.status_code in [200, 201, 202, 206] and self.mean_length > 0:
                    len_z = self.calculate_z_score(len(r.text), self.mean_length, self.stdev_length)
                    if len_z > self.anomaly_threshold:
                        sub_anomalies.append({
                            "type": "Unexpected Route Resolution Anomaly",
                            "confidence": "Low",
                            "evidence": f"Path appended with '{mut}' resulted in 200 OK + distinct block format.",
                            "url": mutated_path_url
                        })
            except Exception:
                pass

            return sub_anomalies

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_mut = {executor.submit(test_mutation, mut): mut for mut in mutations}
            for future in as_completed(future_to_mut):
                res = future.result()
                if res:
                    anomalies.extend(res)

        return anomalies

def run_zero_day_analysis(target, forms=None):
    analyzer = ZeroDayAnalyzer(target, forms)
    return analyzer.analyze_anomalies()
