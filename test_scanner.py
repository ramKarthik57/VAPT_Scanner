import requests
import sys

URL = "http://127.0.0.1:5000/"

targets = [
    ("http://testphp.vulnweb.com/", "quick"),
    ("https://radio.garden/", "quick"),
    ("http://demo.testfire.net", "quick")
]

print("Starting scan tests...")

for target, mode in targets:
    print(f"\n==============================================")
    print(f"Scanning {target} (Mode: {mode})")
    print(f"==============================================\n")
    
    try:
        r = requests.post(URL, data={"target": target, "scan_mode": mode}, timeout=120)
        text = r.text
        
        if "Scan Error occurred:" in text:
            print("[FAIL] Scanner returned an error block.")
            continue
            
        if "Security Score" in text:
            # Extract score
            try:
                score_str = text.split('stat-val score">')[1].split(' /100')[0]
                print(f"[SUCCESS] Security Score: {score_str}/100")
            except:
                pass
                
            # Extract number of findings
            try:
                findings_str = text.split("Total Findings</div>")[1].split('stat-val">')[1].split('<')[0]
                print(f"[SUCCESS] Total Findings: {findings_str}")
            except:
                pass
                
            # Check for specific items
            if "Technology Profile &amp; Security Posture" in text:
                print("[SUCCESS] Reconnaissance profile generated")
                
            if "Missing Security Header" in text:
                print("[SUCCESS] Header audit executed")
                
        elif "Target Appears Secure" in text:
            print("[SUCCESS] Zero finds state rendered properly")
            
        else:
            print("[FAIL] Unknown dashboard state generated")
            
    except Exception as e:
        print(f"[ERROR] Request failed: {e}")

print("\nTests complete.")
