
"""Improved waf_features.py
Implements enhanced URL and payload heuristics to reduce false negatives.
"""
import re
import urllib.parse
from typing import Dict, Any, Optional, List

# Basic attack words with weights
ATTACK_WORDS = {
    # SQL Injection
    "union": 150, "select": 150, "insert": 150, "update": 150, "delete": 150, "drop": 150,
    "information_schema": 150, "cast(": 80, "load_file(": 150, "into outfile": 180,
    "waitfor": 250, "delay": 250, "benchmark(": 120, "sleep(": 120,
    "'": 50, # Thêm dấu nháy đơn
    "--": 100, # Thêm comment SQL
    
    # XSS
    "<script": 250, "alert(": 150, "document.cookie": 200, "onload=": 150, "onerror=": 150,
    
    # Command Injection / Traversal
    "xp_cmdshell": 200,
    "../": 100,
    "..%2f": 100,
    
    # Regex cho các mẫu linh hoạt hơn (ví dụ: có khoảng trắng)
    r"or\s+1\s*=\s*1": 300,
    r"and\s+1\s*=\s*1": 300,
    r"1\s*=\s*1": 150, # Giữ lại '1=1' gốc nếu cần
}

SENSITIVE_URL_PATTERNS = {
    # Các mẫu gốc
    "/_vti_inf.html": 200, "/msadc/msadcs.dll": 250, "/iissamples/": 200,
    "/webspheresamples/": 200, ".inc": 200, ".old": 200, ".bak": 200, ".backup": 200,
    
    # Bổ sung các mẫu thường thấy
    "WEB-INF": 300,
    "/admin": 100,
    "/login": 50,
    "/administrator": 150,
    ".ini": 200,
    ".log": 150,
    ".sql": 200,
    ".config": 200,
    "/.git/": 250,
    "/.svn/": 250,
    "/etc/passwd": 300,
}

SUSPICIOUS_URL_REGEX = [
    (re.compile(r"/_vti_inf\.html\b", re.I), 200),
    (re.compile(r"/msadc/msadcs\.dll\b", re.I), 250),
    (re.compile(r"/iissamples?/.*", re.I), 200),
    (re.compile(r"/webspheresamples?/.*", re.I), 200),
    (re.compile(r"\.inc\b", re.I), 200),
    (re.compile(r"\.old\b", re.I), 200),
    (re.compile(r"/\d+\.jsp\b", re.I), 150),
]

TAUTOLOGY_REGEX = re.compile(r"\b(?:or|and)\s*1\s*=\s*1\b", re.I)
SUSPICIOUS_VALUE_CHARS = {
    "<", ">", "$", "{", "}", "[", "]",
    "\\", 
    "|", "&", # Pipe và ampersand cho command injection
    ";", # Dấu chấm phẩy
}
CREDIT_CARD_REGEX = re.compile(r"\b\d{13,19}\b")
MANIPULATION_WEIGHT = 80

def _to_str(x: Optional[str]) -> str:
    return "" if x is None else str(x)

def clean_request_url(raw_url: str) -> str:
    if not raw_url:
        return ""
    parts = raw_url.split(" HTTP/")
    url = parts[0]
    # remove leading method if present
    tokens = url.strip().split(" ")
    if tokens and tokens[0].upper() in {"GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH"}:
        url = " ".join(tokens[1:])
    return urllib.parse.unquote(url)

def extract_features_from_request(request: Dict[str, Any], label: Optional[int] = None) -> Dict[str, Any]:
    method = _to_str(request.get("method", "GET")).upper()
    raw_url = _to_str(request.get("url", ""))
    payload_raw = _to_str(request.get("payload", "") or request.get("body", ""))
    headers_raw = request.get("headers", {}) or {}

    url = clean_request_url(raw_url)
    payload = urllib.parse.unquote(payload_raw)
    headers = {k: urllib.parse.unquote(_to_str(v)) for k,v in headers_raw.items()}

    url_weight = _calc_url_weight(url)
    attack_words_weight = _calc_attack_words_in_inputs(url + "\n" + payload + "\n" + " ".join(f"{k}={v}" for k,v in headers.items()))
    manipulated_weight = _calc_manipulated_payload_weight(payload, headers)
    ratio_weight = _calc_ratio_weight(payload)
    files_weight = _calc_files_weight(request.get("files", []))

    attack_weight = url_weight + attack_words_weight + manipulated_weight + ratio_weight + files_weight

    features = {
        "payload_len": len(payload),
        "alpha_ratio": _calc_alpha_ratio(payload),
        "nonalpha_ratio": _calc_nonalpha_ratio(payload),
        "url_weight": url_weight,
        "attack_words_weight": attack_words_weight,
        "manipulated_weight": manipulated_weight,
        "ratio_weight": ratio_weight,
        "files_weight": files_weight,
        "attack_weight": attack_weight
    }
    if label is not None:
        features["label"] = label
    return features

def _calc_url_weight(url: str) -> int:
    url_lower = (url or "").lower()
    score = 0
    for pattern, w in SENSITIVE_URL_PATTERNS.items():
        if pattern in url_lower:
            score += w
    for rgx, w in SUSPICIOUS_URL_REGEX:
        if rgx.search(url_lower):
            score += w
    for word, w in ATTACK_WORDS.items():
        if word in url_lower:
            score += w * url_lower.count(word)
    if "%" in url:
        score += 30
    if TAUTOLOGY_REGEX.search(url_lower):
        score += 200
    return score

def _calc_attack_words_in_inputs(text: str) -> int:
    t = (text or "").lower()
    score = 0
    for word, w in ATTACK_WORDS.items():
        count = t.count(word)
        if count:
            score += w * count
    if "%27" in text or "%22" in text or "%3D" in text:
        score += 40
    return score

def _calc_manipulated_payload_weight(payload: str, headers: Dict[str,str]) -> int:
    score = 0
    try:
        pairs = urllib.parse.parse_qsl(payload, keep_blank_values=True)
    except Exception:
        pairs = []
    numeric_like_keys = {"id", "age", "phone", "quantity", "amount", "uid", "ntc"}
    for k,v in pairs:
        k_lower = k.lower()
        if k_lower in numeric_like_keys and v and not v.isdigit():
            score += MANIPULATION_WEIGHT
        if CREDIT_CARD_REGEX.search(v):
            score += 120
        if any(marker in v.lower() for marker in ("inject","drop table","select * from",";--"," or "," and ")):
            score += 100
        if any(ch in v for ch in SUSPICIOUS_VALUE_CHARS):
            score += 25
    return score

def _calc_ratio_weight(payload: str) -> int:
    a = _calc_alpha_ratio(payload)
    na = _calc_nonalpha_ratio(payload)
    score = 0
    if a < 20 and na > 30:
        score += 60
    return score

def _calc_alpha_ratio(text: str) -> float:
    s = _to_str(text)
    if not s:
        return 0.0
    alpha = sum(c.isalpha() for c in s)
    return 100.0 * alpha / len(s)

def _calc_nonalpha_ratio(text: str) -> float:
    s = _to_str(text)
    if not s:
        return 0.0
    nonalpha = sum((not c.isalpha()) for c in s)
    return 100.0 * nonalpha / len(s)

def _calc_files_weight(files: List[dict]) -> int:
    if not files:
        return 0
    return 80

if __name__ == "__main__":
    sample = {"method":"POST","url":"/tienda1/publico/vaciar.jsp HTTP/1.1","payload":"modo=registro&login=beaumont&password=quEratItiS"}
    print(extract_features_from_request(sample))
