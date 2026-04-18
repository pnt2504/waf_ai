# =============================================================================
# features/helpers.py
# Các hàm tiện ích thuần túy — không phụ thuộc state, dễ test độc lập
# =============================================================================

import math
import re
import urllib.parse

from config.keywords import (
    ATTACK_KEYWORDS,
    CRITICAL_EXTENSIONS,
    MALICIOUS_UPLOAD_EXTS,
    SCANNER_UA_PATTERNS,
    SQLI_BOUNDARY_KEYWORDS,
    SQLI_LITERAL_KEYWORDS,
    SUSPICIOUS_CACHE_VALUES,
    WEIGHTS,
)


def calculate_param_name_entropy(payload: str) -> float:
    """
    Shannon entropy của tên (key) các tham số trong query string / body.
    Attack payload thường có tên tham số ngẫu nhiên → entropy cao hơn normal.
    """
    if not payload:
        return 0.0
    params = payload.split('&')
    names = []
    for p in params:
        key = p.split('=')[0] if '=' in p else p
        names.append(urllib.parse.unquote(key))
    combined = ''.join(names)
    if not combined:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(combined.count(chr(x))) / len(combined)
        if p_x > 0:
            entropy -= p_x * math.log(p_x, 2)
    return entropy


def calculate_entropy(text: str) -> float:
    """
    Tính Shannon entropy của chuỗi.
    Entropy cao → chuỗi ngẫu nhiên / mã hóa → dấu hiệu đáng ngờ.
    """
    if not text:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy -= p_x * math.log(p_x, 2)
    return entropy


def count_keywords(text: str, keyword_list: list) -> int:
    """
    Đếm số từ khóa trong keyword_list xuất hiện trong text (sau URL decode).
    Dùng khớp substring đơn giản (case-insensitive cả text lẫn keyword).
    """
    if not text:
        return 0
    text_lower = urllib.parse.unquote(str(text)).lower()
    return sum(1 for kw in keyword_list if kw.lower() in text_lower)


def count_sqli_keywords(text: str) -> int:
    """
    Đếm từ khóa SQLi với 2 chiến lược:
    - SQLI_BOUNDARY_KEYWORDS: khớp có ranh giới từ (tránh false positive)
    - SQLI_LITERAL_KEYWORDS : khớp substring bình thường
    """
    if not text:
        return 0
    t = urllib.parse.unquote(str(text)).lower()
    count = 0

    boundary_pattern = r'(?<![a-z0-9_])%s(?![a-z0-9_])'
    for word in SQLI_BOUNDARY_KEYWORDS:
        if re.search(boundary_pattern % re.escape(word), t):
            count += 1

    for kw in SQLI_LITERAL_KEYWORDS:
        if kw in t:
            count += 1

    return count


def header_anomaly_score(headers: dict) -> int:
    """
    Tính điểm bất thường của headers. Điểm cao → request đáng ngờ hơn.

    Các kiểm tra (mỗi điều kiện cộng 1 trừ scanner UA cộng 2):

    [Cũ – giữ nguyên]
    1. user_agent / pragma / connection / referer == "invalid"  → +1 mỗi trường
    2. UA quá ngắn (< 12 ký tự)                                 → +1

    [Mới – bổ sung để bắt Nhóm A]
    3. UA khớp scanner/bot đã biết (Konqueror, Nikto, …)        → +2
       (nhân đôi vì đây là dấu hiệu chắc chắn hơn)
    4. Mozilla version giả (< 4, ví dụ Mozilla/0.5)             → +1
    5. accept_charset chứa charset trùng lặp                     → +1
       (fingerprint của CSIC scanner: "utf-8, utf-8;q=0.5, *;q=0.5")
    6. accept_language là "non-standard" / "*" / "-"             → +1
    7. cache_control là directive hiếm gặp ở browser thật        → +1
    """
    if not isinstance(headers, dict):
        return 0

    score = 0

    # --- 1. Giá trị "invalid" trên các trường quan trọng ---
    for key in ('user_agent', 'pragma', 'connection', 'referer'):
        value = str(headers.get(key, '')).strip().lower()
        if value == 'invalid':
            score += 1

    # --- 2. UA quá ngắn ---
    ua = str(headers.get('user_agent', '')).strip()
    if ua and len(ua) < 12:
        score += 1

    # --- 3. UA khớp với scanner / bot đã biết ---
    ua_lower = ua.lower()
    for pattern in SCANNER_UA_PATTERNS:
        if pattern in ua_lower:
            score += 2
            break  # chỉ cộng một lần dù khớp nhiều pattern

    # --- 4. Mozilla version giả (browser thật dùng 4.0 hoặc 5.0) ---
    moz_match = re.search(r'mozilla/(\d+)', ua_lower)
    if moz_match and int(moz_match.group(1)) < 4:
        score += 1

    # --- 5. accept_charset có giá trị bị lặp ---
    # Ví dụ: "utf-8, utf-8;q=0.5, *;q=0.5" → "utf-8" xuất hiện 2 lần
    ac = str(headers.get('accept_charset', '')).strip()
    if ac and ac not in ('-', ''):
        parts = [p.strip().split(';')[0].strip().lower() for p in ac.split(',')]
        if len(parts) != len(set(parts)):
            score += 1

    # --- 6. accept_language bất thường ---
    # "non-standard", "-", "" → rõ ràng lạ
    # "*" hoặc "*;q=..." → wildcard language không browser thật nào gửi
    al = str(headers.get('accept_language', '')).strip().lower()
    if al in ('non-standard', '-', '') or al == '*' or al.startswith('*;'):
        score += 1

    # --- 7. cache_control là directive hiếm gặp ở browser thật ---
    # Khớp cả "max-stale" lẫn "max-stale=172" bằng cách kiểm tra prefix
    cc = str(headers.get('cache_control', '')).strip().lower()
    cc_base = cc.split('=')[0].strip()   # lấy phần trước dấu '='
    if cc in SUSPICIOUS_CACHE_VALUES or cc_base in SUSPICIOUS_CACHE_VALUES:
        score += 1

    return score


def check_critical_extension(url: str) -> int:
    """
    Kiểm tra URL có trỏ đến file nhạy cảm không (bak, sql, env...).
    Trả về 1 nếu có, 0 nếu không.
    """
    try:
        url_lower = str(url).lower()
        # Bỏ phần query string trước khi kiểm tra extension
        if '?' in url_lower:
            url_lower = url_lower.split('?')[0]
        url_lower = url_lower.rstrip('/')
        for ext in CRITICAL_EXTENSIONS:
            if url_lower.endswith(ext):
                return 1
    except Exception:
        return 0
    return 0


def calculate_files_weight(payload: str) -> int:
    """
    Phát hiện upload file độc hại trong payload.
    Tìm 'filename=...' và kiểm tra extension.
    """
    if not payload:
        return 0
    weight = 0
    filenames = re.findall(
        r'filename=["\']?([^"\';\r\n]+)["\']?',
        str(payload),
        re.IGNORECASE,
    )
    for fname in filenames:
        fname_lower = fname.lower()
        for ext in MALICIOUS_UPLOAD_EXTS:
            if fname_lower.endswith(ext):
                weight += WEIGHTS['invalid_file']
                break
    return weight
