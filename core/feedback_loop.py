import json
import os
from datetime import datetime

class SelfLearningFeedbackLoop:
    """
    Implements a continuous feedback loop and reinforcement model.
    Tracks vulnerabilities found and their validation status to dynamically
    adjust 'Confidence' and 'Severity' across future scans based on historical accuracy.
    """
    
    def __init__(self, db_path="feedback_weights.json"):
        self.db_path = db_path
        self.weights = self._load_db()

    def _load_db(self):
        if os.path.exists(self.db_path):
            with open(self.db_path, "r") as f:
                return json.load(f)
        return {
            "historical_accuracy": {}, # { 'SQL Injection': { verified: 10, false_positive: 2 } }
            "global_confidence_modifiers": {}
        }

    def _save_db(self):
        with open(self.db_path, "w") as f:
            json.dump(self.weights, f, indent=4)

    def log_feedback(self, vuln_type, is_verified):
        """
        Register a verified true positive or a flagged false positive to adjust future AI weights.
        """
        if vuln_type not in self.weights["historical_accuracy"]:
            self.weights["historical_accuracy"][vuln_type] = {"verified": 0, "false_positive": 0}
            
        if is_verified:
            self.weights["historical_accuracy"][vuln_type]["verified"] += 1
        else:
            self.weights["historical_accuracy"][vuln_type]["false_positive"] += 1
            
        self._calculate_modifiers()
        self._save_db()

    def _calculate_modifiers(self):
        """
        Recalculates global confidence multipliers based on Bayesian updating or simple ratios.
        """
        for vuln_type, stats in self.weights["historical_accuracy"].items():
            total = stats["verified"] + stats["false_positive"]
            if total > 5: # Need a minimum sample size to adjust weights
                ratio = stats["verified"] / total
                # If historically accurate > 80%, increase confidence multiplier
                # If highly false positive, decrease confidence multiplier
                modifier = max(0.5, min(1.5, ratio * 1.5))
                self.weights["global_confidence_modifiers"][vuln_type] = round(modifier, 2)

    def apply_learning(self, findings):
        """
        Correlates active findings with historical learning weights to adjust 
        confidence scores dynamically.
        """
        adjusted_findings = []
        for finding in findings:
            vuln_type = finding["type"]
            original_confidence = finding.get("confidence", "Medium")
            
            modifier = self.weights["global_confidence_modifiers"].get(vuln_type, 1.0)
            
            new_confidence = original_confidence
            if modifier < 0.7:
                new_confidence = "Low"
                finding["ai_reasoning"] = finding.get("ai_reasoning", []) + [
                    f"-0.5 | Downgraded from {original_confidence} -> Low due to historical False Positive rates ({modifier} multiplier)"
                ]
                finding["ai_likelihood"] = max(0.1, finding.get("ai_likelihood", 0.5) - 0.3)
            elif modifier > 1.2 and original_confidence != "High":
                new_confidence = "High"
                finding["ai_reasoning"] = finding.get("ai_reasoning", []) + [
                    f"+0.3 | Upgraded from {original_confidence} -> High due to strong historical verification ({modifier} multiplier)"
                ]
                finding["ai_likelihood"] = min(0.99, finding.get("ai_likelihood", 0.5) + 0.3)
                
            finding["confidence"] = new_confidence
            adjusted_findings.append(finding)
            
        return adjusted_findings
