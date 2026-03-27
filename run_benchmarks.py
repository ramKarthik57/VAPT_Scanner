import requests
import os

URL = "http://127.0.0.1:5000/"

payload = {
    "target": "http://testphp.vulnweb.com/, http://demo.testfire.net",
    "scan_mode": "quick",
    "sast_dir": os.getcwd(),
    "critical_data": "on",
    "gdpr": "on"
}

print("Initiating Next-Gen Benchmarking Scan...")
try:
    r = requests.post(URL, data=payload, timeout=300)
    
    if "Execution Error" in r.text.replace("&#34;", '"'):
        print("[FAIL] Dashboard returned an execution error block.")
        print(r.text[:500])
    elif "Predictive Score" in r.text or "Security Score" in r.text or "AI Predictive Score" in r.text:
        print("[SUCCESS] Distributed AI Scan Completed Successfully.")
        print("Validating metrics generated:")
        
        if "SAST Active:</span> <span class=\"text-light ms-2\"><span class=\"text-success\">Yes</span>" in r.text:
            print(" - [PASS] SAST detected and executed.")
        else:
            print(" - [FAIL] SAST did not execute.")
            
        if "Multi-Domain:</span> <span class=\"text-light ms-2\">Enabled</span>" in r.text:
            print(" - [PASS] Multi-Domain orchestration executed.")
        else:
            print(" - [FAIL] Multi-Domain orchestration failed.")
            
        if "Safe PoC Generated:" in r.text:
            print(" - [PASS] Contextual Safe PoCs generation active.")
        else:
            print(" - [FAIL] Missing Safe PoC output.")
            
        if "MITIGATION PLAN" in r.text:
            print(" - [PASS] Autonomous Remediation Strategies mapped.")
            
    else:
        print("[FAIL] Unrecognized dashboard state.")
        
except Exception as e:
    print(f"[ERROR] Request failed: {e}")
