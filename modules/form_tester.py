import requests
import urllib.parse
from typing import List, Dict, Any
from utils.logger import info, success, error
from utils.input_analyzer import analyze_input, is_reflected_xss
from utils.xss_payloads import XSS_PAYLOADS
from utils.file_writer import save_vulnerability, increment_payload_stat
from modules.sql_injection import get_sqli_payloads, is_sqli_response
from modules.open_redirect import test_open_redirect
import uuid

requests.packages.urllib3.disable_warnings()


def _absolute_action(action: str, base_url: str) -> str:
    if action.lower().startswith(("http://", "https://")):
        return action
    return urllib.parse.urljoin(base_url, action)


def _build_payload(inputs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    payload_sets = []
    for inp in inputs:
        name = inp.get("input_name")
        if not name:
            continue
        attrs = inp.get("attrs", {})
        input_type = inp.get("input_type", "text")
        analyzed = analyze_input(input_type, name, attrs)
        for payload in analyzed.get("payloads", []):
            payload_sets.append({name: payload})
    return payload_sets


def test_form(form: Dict[str, Any], base_url: str, timeout: int = 10) -> List[Dict[str, Any]]:
    method = form.get("method", "get").lower()
    action_raw = form.get("action", "")
    action = _absolute_action(action_raw, base_url)
    inputs = form.get("inputs", [])

    detailed_inputs = []
    for inp in inputs:
        name = inp.get("name")
        input_type = inp.get("type", "text")
        attrs = inp.get("attrs", {})
        detailed = analyze_input(input_type, name, attrs)
        detailed_inputs.append(detailed)

    results = []

    for input_payload in _build_payload(detailed_inputs):
        data = {}
        for inp in inputs:
            inp_name = inp.get("name")
            inp_type = inp.get("type", "text")
            if inp_type == "submit":
                data[inp_name] = input_payload.get(inp_name, "Submit")
            elif inp_name in input_payload:
                data[inp_name] = input_payload[inp_name]
            else:
                data[inp_name] = ""

        info(f"[Form Test] {method.upper()} {action} — Payload: {input_payload}")

        try:
            if method == "post":
                resp = requests.post(action, data=data, timeout=timeout, verify=False, allow_redirects=True)
            else:
                resp = requests.get(action, params=data, timeout=timeout, verify=False, allow_redirects=True)

            reflected = any(val in resp.text for val in input_payload.values() if val)
            vulnerable = reflected or resp.status_code >= 500

            for val in input_payload.values():
                if val and is_reflected_xss(resp.text, val):
                    vuln_id = str(uuid.uuid4())
                    success(f"    🚨 XSS Tespit Edildi! Payload: {val}")
                    vuln_data = {
                        "id": vuln_id,
                        "type": "XSS",
                        "input": list(input_payload.keys())[0],
                        "payload": val,
                        "response_snippet": resp.text[:1000],
                        "method": method,
                        "action": action,
                        "status": resp.status_code
                    }
                    save_vulnerability(vuln_data)
                    increment_payload_stat("XSS", val)

            for name in input_payload:
                for sqli_payload in get_sqli_payloads():
                    test_data = data.copy()
                    test_data[name] = sqli_payload
                    info(f"    [SQLi Test] {name} = {sqli_payload}")
                    try:
                        if method == "post":
                            test_resp = requests.post(action, data=test_data, timeout=timeout, verify=False)
                        else:
                            test_resp = requests.get(action, params=test_data, timeout=timeout, verify=False)

                        if is_sqli_response(test_resp.text):
                            vuln_id = str(uuid.uuid4())
                            success(f"    🚨 SQLi Tespit Edildi! Payload: {sqli_payload}")
                            vuln_data = {
                                "id": vuln_id,
                                "type": "SQLi",
                                "input": name,
                                "payload": sqli_payload,
                                "response_snippet": test_resp.text[:1000],
                                "method": method,
                                "action": action,
                                "status": test_resp.status_code
                            }
                            save_vulnerability(vuln_data)
                            increment_payload_stat("SQLi", sqli_payload)

                    except Exception as sqli_exc:
                        error(f"    SQLi testi başarısız: {sqli_exc}")

            for name in input_payload:
                redirect_result = test_open_redirect(
                    action=action,
                    method=method,
                    data=data,
                    input_name=name,
                    timeout=timeout
                )
                if redirect_result:
                    vuln_id = str(uuid.uuid4())
                    success(f"    🚨 Open Redirect Tespit Edildi! Payload: {redirect_result['payload']}")
                    vuln_data = {
                        "id": vuln_id,
                        "type": "OpenRedirect",
                        "input": name,
                        "payload": redirect_result["payload"],
                        "response_snippet": redirect_result["response_snippet"],
                        "method": method,
                        "action": action,
                        "status": redirect_result["status"],
                        "location": redirect_result["location"]
                    }
                    save_vulnerability(vuln_data)
                    increment_payload_stat("OpenRedirect", redirect_result["payload"])

            if vulnerable:
                success(f"    ⚠️ Potansiyel açık! ({resp.status_code})")
            else:
                info(f"    Güvenli yanıt ({resp.status_code})")

            results.append({
                "method": method,
                "action": action,
                "payload": input_payload,
                "status": resp.status_code,
                "vulnerable": vulnerable,
                "reflected": reflected
            })
        #
        except Exception as exc:
            error(f"    İstek başarısız: {exc}")
            results.append({
                "method": method,
                "action": action,
                "payload": input_payload,
                "error": str(exc),
                "vulnerable": False,
            })

    return results


def test_forms(forms: List[Dict[str, Any]], base_url: str, timeout: int = 10) -> List[Dict[str, Any]]:
    all_results = []
    for idx, form in enumerate(forms, 1):
        info(f"[Form {idx}] Test ediliyor: {form.get('method', 'GET').upper()} {form.get('action')}")
        results = test_form(form, base_url, timeout=timeout)
        all_results.extend(results)
    return all_results
