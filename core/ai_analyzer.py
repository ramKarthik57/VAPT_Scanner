import re
import uuid

class AIAutonomousAnalyzer:
    """
    Simulated Artificial Intelligence Analyzer for interpreting vulnerabilities.
    Generates dynamic exploitability scores and benign Proof-of-Concepts (PoCs)
    without causing malicious side-effects.
    """
    
    def __init__(self, findings):
        self.findings = findings
        self.ai_insights = []
        
    def evaluate_exploitability(self, vulnerability_type, evidence, context=""):
        """
        Uses heuristic models to determine the practical exploitability of a flaw.
        In a cloud-connected setting, this sends context to OpenAI/Gemini APIs.
        """
        score = 0.5
        factors = []
        
        # Simulated Feature Weighting
        if "SQL" in vulnerability_type:
            factors.append("+0.2 | Database structural exposure indicates high data leak risk.")
            score += 0.2
            if "timeout" in evidence.lower():
                factors.append("+0.15 | Blind Time-Based injection is reliable.")
                score += 0.15
        elif "XSS" in vulnerability_type:
            factors.append("+0.1 | Client-side execution possible.")
            score += 0.1
            if "<script>" in evidence:
                factors.append("+0.2 | Unfiltered script tags suggest WAF bypass.")
                score += 0.2
        elif "Zero-Day" in vulnerability_type or "Anomaly" in vulnerability_type:
            factors.append("+0.3 | Unknown state deviation implies undefined application behavior.")
            score += 0.3
            if "Timing" in vulnerability_type:
                factors.append("+0.1 | Server resource consumption detected.")
                score += 0.1
                
        # Normalize score
        score = min(max(score, 0.1), 0.99)
        return {
            "exploitability_likelihood": score,
            "ai_reasoning": factors
        }

    def generate_safe_poc(self, vulnerability_type, target_url):
        """
        Generates an ethical, harmless Proof of Concept.
        In a deployed environment, this would build a dynamic Python snippet
        using an LLM to prove the flaw without causing destructive actions.
        """
        poc_id = str(uuid.uuid4())[:8]
        
        if "SQL" in vulnerability_type:
            return f"curl -X GET '{target_url}' -d 'id=1 AND 1=1 -- {poc_id}'  # (Safe Boolean Evaluation)"
        elif "XSS" in vulnerability_type:
            return f"curl -X GET '{target_url}' -d 'q=<script>console.log(\"VAPT_POC_{poc_id}\");</script>' # (Benign Console Log)"
        elif "Traversal" in vulnerability_type:
            return f"curl -X GET '{target_url}' -d 'file=../../../../etc/passwd' # (Read-Only access)"
        elif "Anomaly" in vulnerability_type:
            return f"curl -X GET '{target_url}' -d 'payload=%00%2e%2e/' # (Triggers behavioral deviation)"
        else:
            return f"curl -I '{target_url}' # Review response headers for {vulnerability_type} indicators."

    def process_findings(self):
        """
        Enriches the core findings with AI-driven intelligence.
        """
        for finding in self.findings:
            vuln_type = finding["type"]
            evidence = finding["evidence"]
            
            ai_eval = self.evaluate_exploitability(vuln_type, evidence)
            poc = self.generate_safe_poc(vuln_type, finding.get("url", "unknown"))
            
            enriched = {
                **finding,
                "ai_likelihood": ai_eval["exploitability_likelihood"],
                "ai_reasoning": ai_eval["ai_reasoning"],
                "safe_poc": poc
            }
            self.ai_insights.append(enriched)
            
        return self.ai_insights

def run_ai_analysis(findings):
    analyzer = AIAutonomousAnalyzer(findings)
    return analyzer.process_findings()
