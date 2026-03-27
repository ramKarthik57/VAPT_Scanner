class AdvancedRiskIntelligence:
    """
    Transforms simple CVSS scores into contextual Risk Intelligence scores.
    Combines Exploitability Base, Business Impact, and AI Threat Likelihood.
    """
    
    def __init__(self, findings, business_context=None):
        self.findings = findings
        self.business_context = business_context or {
            "critical_data_assets": True,
            "public_facing": True,
            "compliance_scoping": ["PCI-DSS", "GDPR"]
        }
        
    def calculate_priority_score(self, finding):
        """
        Risk = Threat_Likelihood * Potential_Impact
        Threat_Likelihood incorporates CVSS Base + AI Reasoning
        Potential_Impact incorporates Business Context
        """
        # Base CVSS out of 10.0
        base_cvss = float(finding.get("cvss", 5.0))
        
        # AI Likelihood out of 1.0
        ai_likeli = float(finding.get("ai_likelihood", 0.5))
        
        # Business Context Modifier (1.0 to 1.5)
        # e.g., SQLi on a GDPR/PCI system is highly impactful
        impact_modifier = 1.0
        vuln_type = finding.get("type", "")
        
        if "SQL" in vuln_type or "Information Disclosure" in vuln_type or "LFI" in vuln_type:
            if "GDPR" in self.business_context.get("compliance_scoping", []):
                impact_modifier += 0.3
                
        if self.business_context.get("public_facing"):
            if "XSS" in vuln_type or "Zero-Day" in vuln_type:
                impact_modifier += 0.2
                
        # Calculate Final Priority Score
        raw_priority = (base_cvss * ai_likeli) * impact_modifier
        
        # Normalize to 10.0 scale and limit
        priority_score = min(10.0, max(1.0, round(raw_priority * 1.5, 1)))
        
        new_severity = "Low"
        if priority_score >= 9.0:
            new_severity = "Critical"
        elif priority_score >= 7.0:
            new_severity = "High"
        elif priority_score >= 4.0:
            new_severity = "Medium"
            
        finding["priority_score"] = priority_score
        finding["contextual_severity"] = new_severity
        
        # Attack Path Context Generation
        path = ["Attacker Discovers Target"]
        if finding.get("forms", []):
            path.append("Submits payload via identified Form field")
        elif "url" in finding:
            path.append("Manipulates GET query parameter / Path Segment")
            
        if "SQL" in vuln_type:
            path.extend(["Triggers Database Syntax Error", "Extracts underlying Data Structure"])
        elif "XSS" in vuln_type:
            path.extend(["Bypasses client-side rendering filters", "Executes arbitrary JavaScript in Victim Browser"])
        elif "Zero-Day" in vuln_type or "Anomaly" in vuln_type:
            path.extend(["Causes behavioral timing/length deviation", "Indicates undocumented application state transfer"])
            
        finding["attack_path"] = " ➔ ".join(path)
        
        return finding
        
    def process(self):
        prioritized = []
        for f in self.findings:
            prioritized.append(self.calculate_priority_score(f))
            
        # Sort by the new intelligent priority score instead of raw CVSS
        return sorted(prioritized, key=lambda x: x["priority_score"], reverse=True)

def apply_risk_intelligence(findings, business_context=None):
    model = AdvancedRiskIntelligence(findings, business_context)
    return model.process()
