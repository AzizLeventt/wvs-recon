import requests
import urllib.parse
from typing import List, Dict, Any
from utils.logger import info, success, error
from utils.input_analyzer import analyze_input

requests.packages.urllib3.disable_warnings()  # SSL uyarılarını bastır

def _absolute_action(action: str, base_url: str) -> str:
    """Form action değerini tam URL hâline getirir."""
    if action.lower().startswith(("http://", "https://")):
        return action
    return urllib.parse.urljoin(base_url, action)

def _build_payload(inputs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """
    Her input için uygun payload listesini hazırlar.
    Dönen liste, input adı ve payload çifti dict'lerinden oluşur.
    """
    payload_sets = []
    for inp in inputs:
        name = inp.get("input_name")
        if not name:
            continue
        # Burada attribute'ları da gönderiyoruz, eğer varsa
        attrs = inp.get("attrs", {})
        input_type = inp.get("input_type", "text")
        analyzed = analyze_input(input_type, name, attrs)
        for payload in analyzed.get("payloads", []):
            payload_sets.append({name: payload})
    return payload_sets

def test_form(form: Dict[str, Any], base_url: str, timeout: int = 10) -> List[Dict[str, Any]]:
    """
    Bir forma ait tüm payload setlerini tek tek gönderip test eder.
    Her payload için HTTP yanıtı ve vulnerability durumu döner.
    """
    method = form.get("method", "get").lower()
    action_raw = form.get("action", "")
    action = _absolute_action(action_raw, base_url)
    inputs = form.get("inputs", [])

    # Detaylı analizli input listesi (analyze_input çıktı formatı)
    detailed_inputs = []
    for inp in inputs:
        name = inp.get("name")
        input_type = inp.get("type", "text")
        # Scanner'dan gelen attribute bilgisi varsa ekle, yoksa boş dict
        attrs = inp.get("attrs", {})
        detailed = analyze_input(input_type, name, attrs)
        detailed_inputs.append(detailed)

    results = []

    # Her payload kombinasyonunu deniyoruz
    # Şimdilik her input için ayrı ayrı payload gönderiliyor, ileride kombinasyon yapılabilir
    for input_payload in _build_payload(detailed_inputs):
        data = {}
        # Formda submit type input varsa ona da uygun değer atamak gerekebilir
        for inp in inputs:
            inp_name = inp.get("name")
            inp_type = inp.get("type", "text")
            if inp_type == "submit":
                data[inp_name] = input_payload.get(inp_name, "Submit")
            elif inp_name in input_payload:
                data[inp_name] = input_payload[inp_name]
            else:
                # Diğer inputlar için boş ya da default değer
                data[inp_name] = ""

        info(f"[Form Test] {method.upper()} {action} — Payload: {input_payload}")

        try:
            if method == "post":
                resp = requests.post(action, data=data, timeout=timeout, verify=False, allow_redirects=True)
            else:
                resp = requests.get(action, params=data, timeout=timeout, verify=False, allow_redirects=True)

            vulnerable = False
            # Basit heuristik: payload yansıması veya sunucu hatası
            for val in input_payload.values():
                if val and val in resp.text:
                    vulnerable = True
                    break
            if resp.status_code >= 500:
                vulnerable = True

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
            })

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
    """
    Birden fazla form için testleri çalıştırır.
    """
    all_results = []
    for idx, form in enumerate(forms, 1):
        info(f"[Form {idx}] Test ediliyor: {form.get('method', 'GET').upper()} {form.get('action')}")
        results = test_form(form, base_url, timeout=timeout)
        all_results.extend(results)
    return all_results
