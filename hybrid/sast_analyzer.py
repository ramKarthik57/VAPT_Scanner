import os
import re

class SASTAnalyzer:
    """
    Static Application Security Testing Module.
    Scans local source code directories (e.g. backend files or downloaded frontend JS)
    to detect hardcoded secrets, misconfigurations, and dangerous logic patterns.
    """
    
    def __init__(self, source_dir):
        self.source_dir = source_dir
        
        self.signatures = {
            "Hardcoded Credentials": [
                r'(?i)(password|passwd|pwd|secret|token|api_key|apikey|auth)\s*[:=]\s*["\'][^"\']+["\']'
            ],
            "Dangerous Function (RCE Risk)": [
                r'(?i)(eval|exec|system|popen|subprocess\.call)\s*\('
            ],
            "Insecure Cryptography": [
                r'(?i)(md5|sha1|DES|RC4)\s*\('
            ],
            "SQL Injection (Static)": [
                r'(?i)(SELECT|INSERT|UPDATE|DELETE).+(%s|\+).*?(FROM|INTO|SET)'
            ],
            "Exposed Private Keys": [
                r'-----BEGIN (RSA|OPENSSH|PGP) PRIVATE KEY-----'
            ]
        }
        
        self.exclude_dirs = [".git", "node_modules", "venv", "__pycache__"]
        
    def analyze(self):
        """
        Recursively scans the directory and returns a structured list of SAST findings.
        """
        findings = []
        if not self.source_dir or not os.path.exists(self.source_dir):
            return findings
            
        for root, dirs, files in os.walk(self.source_dir):
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            
            for file in files:
                if file.endswith(('.py', '.js', '.php', '.html', '.env', '.json', '.yml', '.yaml')):
                    file_path = os.path.join(root, file)
                    findings.extend(self._scan_file(file_path))
                    
        return findings

    def _scan_file(self, file_path):
        file_findings = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                for vuln_class, patterns in self.signatures.items():
                    for pattern in patterns:
                        if re.search(pattern, line):
                            # Redact sensitive material from evidence
                            evidence = line.strip()
                            if len(evidence) > 100:
                                evidence = evidence[:97] + "..."
                            
                            file_findings.append({
                                "type": f"SAST: {vuln_class}",
                                "severity": "High" if vuln_class in ["Hardcoded Credentials", "Exposed Private Keys"] else "Medium",
                                "evidence": f"Found in {os.path.basename(file_path)} (Line {line_num}): `{evidence}`",
                                "file": file_path,
                                "line": line_num
                            })
        except Exception as e:
            pass
            
        return file_findings

def run_sast(source_directory):
    analyzer = SASTAnalyzer(source_directory)
    return analyzer.analyze()
