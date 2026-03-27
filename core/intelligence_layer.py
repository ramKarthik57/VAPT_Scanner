import json

class HybridIntelligenceLayer:
    """
    Unifies Static Analysis (SAST) and Dynamic Analysis (DAST) into an Interactive Testing approach.
    Reduces noise by correlating related findings.
    """
    
    def __init__(self, sast_findings, dast_findings):
        self.sast = sast_findings or []
        self.dast = dast_findings or []
        self.unified = []
        
    def cross_reference(self):
        """
        Looks for logical intersections between SAST and DAST results.
        If a static finding points to a flaw that is actively verified by DAST, it is escalated.
        """
        # 1. Look for correlated injections
        sast_sqli = any("SQL Injection" in s["type"] for s in self.sast)
        dast_sqli = [d for d in self.dast if "SQL" in d["type"]]
        
        if sast_sqli and dast_sqli:
            for d in dast_sqli:
                d["confidence"] = "Verified Critical"
                d["ai_reasoning"] = d.get("ai_reasoning", []) + [
                    "+0.5 | SAST logic flaw confirms DAST behavioral observation. Verified Vulnerability."
                ]
                d["ai_likelihood"] = 0.99
                
        # 2. Look for correlated path traversal / local file inclusion
        sast_sensitive = [s for s in self.sast if s["severity"] == "High"]
        dast_lfi = [d for d in self.dast if "Traversal" in d["type"] or "Disclosure" in d["type"]]
        
        if sast_sensitive and dast_lfi:
            for d in dast_lfi:
                d["evidence"] += " (CRITICAL: Static analysis shows high-value secrets exposed on this host.)"
                d["severity"] = "Critical"
                d["ai_likelihood"] = 0.95
                
        # 3. Assemble unified output
        self.unified = self.dast.copy()
        
        # Add orthogonal SAST findings to the unified flow
        for s in self.sast:
            # We don't add static SQLi if we found DAST SQLi (already correlated)
            if "SQL" in s["type"] and dast_sqli:
                continue
                
            self.unified.append({
                "type": s["type"],
                "confidence": "Static Only",
                "evidence": s["evidence"],
                "url": s.get("file", "Local Configuration"),
                "severity": s["severity"],
                "ai_likelihood": 0.4 if s["severity"] == "Medium" else 0.7,
                "ai_reasoning": [
                    "Static Analysis finding.",
                    "Exploitability depends on application deployment routing."
                ]
            })
            
        return self.unified

def correlate_hybrid_findings(sast, dast):
    layer = HybridIntelligenceLayer(sast, dast)
    return layer.cross_reference()
