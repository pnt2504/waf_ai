# =============================================================================
# features/extractor.py
# Class FeatureExtractor — chuyển đổi 1 HTTP request entry thành vector số
# =============================================================================

import re
import urllib.parse

from config.keywords import (
    ATTACK_KEYWORDS,
    SCANNER_UA_PATTERNS,
    SUSPICIOUS_CHARS,
    TAMPERING_PARAMS,
    URL_PENALTY_PATTERNS,
    WEIGHTS,
)
from features.helpers import (
    calculate_entropy,
    calculate_files_weight,
    calculate_param_name_entropy,
    check_critical_extension,
    count_keywords,
    count_sqli_keywords,
    header_anomaly_score,
)


class FeatureExtractor:
    """
    Trích xuất vector đặc trưng từ một HTTP request entry (dict).

    Sử dụng:
        extractor = FeatureExtractor()
        features = extractor.extract(entry)   # → list[float]
        names    = extractor.feature_names    # → list[str]
    """

    @property
    def feature_names(self) -> list[str]:
        """Tên các feature theo đúng thứ tự trong vector trả về."""
        return [
            "input_len",
            "alpha_ratio",
            "special_ratio",
            "raw_ratio",
            "z_score",
            "sqli_count",
            "xss_count",
            "path_count",
            "cmd_count",
            "php_count",
            "probing_kw_count",
            "param_count",
            "max_param_len",
            "uppercase_ratio",
            "digit_ratio",
            "entropy_score",
            "critical_score",
            "is_critical_ext",
            "files_weight",
            "url_penalty",
            "manipulate_weight",
            "header_anomaly",
            "uncommon_method",
            "is_empty_probe",    # GET không payload + header scanner (bắt Konqueror GET /)
            "extra_header_risk", # header_anomaly vượt ngưỡng 3 (bắt scanner rõ ràng hơn)
            "is_scanner_ua",     # UA khớp đúng tên scanner (Konqueror, nikto, sqlmap...)
            "param_name_entropy",# Shannon entropy của tên tham số — attack có entropy cao hơn
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, entry: dict) -> list:
        """
        Nhận vào 1 entry JSON (dict) và trả về list các giá trị số.
        Thứ tự khớp với self.feature_names.
        """
        method  = entry.get('method', 'GET')
        url     = str(entry.get('url', ''))
        body    = str(entry.get('payload', ''))
        headers = entry.get('headers', {})

        effective_payload = self._get_effective_payload(method, url, body)
        injection_text    = f"{url} {effective_payload}"

        # --- Thống kê ký tự ---
        char_stats        = self._char_stats(effective_payload)
        input_len         = char_stats['input_len']
        alpha_ratio       = char_stats['alpha_ratio']
        special_ratio     = char_stats['special_ratio']
        uppercase_ratio   = char_stats['uppercase_ratio']
        digit_ratio       = char_stats['digit_ratio']
        raw_ratio         = (alpha_ratio / special_ratio) if special_ratio > 0 else 0

        # --- Đếm từ khóa (chỉ quét injection_text, không quét header) ---
        sqli_count        = count_sqli_keywords(injection_text)
        xss_count         = count_keywords(injection_text, ATTACK_KEYWORDS['xss'])
        path_count        = count_keywords(injection_text, ATTACK_KEYWORDS['path_traversal'])
        cmd_count         = count_keywords(injection_text, ATTACK_KEYWORDS['cmd_injection'])
        php_count         = count_keywords(injection_text, ATTACK_KEYWORDS['php_injection'])
        probing_kw_count  = count_keywords(injection_text, ATTACK_KEYWORDS['probing'])

        # --- Các chỉ số đặc biệt ---
        is_critical_ext   = check_critical_extension(url)
        critical_score    = is_critical_ext * 500_000
        files_weight      = calculate_files_weight(effective_payload)
        url_penalty       = self._url_penalty(url)
        manipulate_weight = self._manipulate_weight(effective_payload)
        header_anomaly    = header_anomaly_score(headers)
        uncommon_method   = 1 if str(method).upper() not in ('GET', 'POST') else 0

        # --- Tham số ---
        param_count       = effective_payload.count('&') + 1 if effective_payload else 0
        max_param_len     = self._max_param_len(effective_payload)
        entropy_score     = calculate_entropy(effective_payload)

        # --- Feature mới 0: is_scanner_ua ---
        # Binary: 1 nếu user_agent khớp đúng tên scanner/bot đã biết.
        # Khác với header_anomaly (tổng hợp nhiều tín hiệu) — feature này chỉ bật
        # khi UA là Konqueror, nikto, sqlmap, ... → dùng được trong hard rule mà
        # không bắt nhầm request normal có header hơi lạ.
        ua_lower     = str(headers.get('user_agent', '')).strip().lower()
        is_scanner_ua      = int(any(p in ua_lower for p in SCANNER_UA_PATTERNS))
        param_name_entropy = calculate_param_name_entropy(effective_payload)

        # --- Feature mới 1: is_empty_probe ---
        # GET không có query string / payload nhưng header bị đánh dấu bất thường (≥ 2).
        # Đây là fingerprint của scanner dò endpoint (e.g. Konqueror GET /).
        # Normal browser: header_anomaly thường = 0 → is_empty_probe = 0 → không bị phạt.
        is_empty_probe = int(
            method.upper() == 'GET'
            and not effective_payload
            and header_anomaly >= 2
        )

        # --- Feature mới 2: extra_header_risk ---
        # Mỗi bậc header_anomaly vượt qua ngưỡng 3 đều đáng ngờ hơn tuyến tính.
        # h=3 → extra=0, h=4 → extra=1, h=5 → extra=2, ...
        # Giúp model phân biệt scanner "rõ ràng" (h=5-7) với scanner "nhẹ" (h=3).
        extra_header_risk = max(0, int(header_anomaly) - 3)

        # --- Tổng điểm Z ---
        z = (
            sqli_count        * WEIGHTS['sqli']          +
            xss_count         * WEIGHTS['xss']           +
            path_count        * WEIGHTS['path']          +
            cmd_count         * WEIGHTS['cmd']           +
            php_count         * WEIGHTS['php_injection'] +
            probing_kw_count  * WEIGHTS['probing']       +
            critical_score    + files_weight             +
            url_penalty       + manipulate_weight        +
            header_anomaly    * 220                      +
            uncommon_method   * 180                      +
            is_empty_probe    * WEIGHTS['empty_probe']   +
            extra_header_risk * WEIGHTS['extra_header']
        )

        return [
            input_len, alpha_ratio, special_ratio, raw_ratio, z,
            sqli_count, xss_count, path_count, cmd_count, php_count, probing_kw_count,
            param_count, max_param_len,
            uppercase_ratio, digit_ratio, entropy_score,
            critical_score, is_critical_ext, files_weight, url_penalty, manipulate_weight,
            header_anomaly, uncommon_method,
            is_empty_probe, extra_header_risk, is_scanner_ua,
            param_name_entropy,
        ]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_effective_payload(self, method: str, url: str, body: str) -> str:
        """
        Với GET request: lấy query string từ URL.
        Với POST/PUT: lấy body.
        """
        if method.upper() == 'GET' and '?' in url:
            try:
                return url.split('?', 1)[1]
            except Exception:
                return ''
        return body

    def _char_stats(self, text: str) -> dict:
        """Tính tỷ lệ ký tự alphanum / đặc biệt / hoa / số."""
        input_len = len(text)
        if input_len == 0:
            return {
                'input_len': 0,
                'alpha_ratio': 0.0,
                'special_ratio': 0.0,
                'uppercase_ratio': 0.0,
                'digit_ratio': 0.0,
            }
        num_alphanum = sum(c.isalnum() for c in text)
        num_special  = input_len - num_alphanum
        num_upper    = sum(c.isupper() for c in text)
        num_digit    = sum(c.isdigit() for c in text)
        return {
            'input_len':      input_len,
            'alpha_ratio':    (num_alphanum / input_len) * 100,
            'special_ratio':  (num_special  / input_len) * 100,
            'uppercase_ratio':(num_upper    / input_len) * 100,
            'digit_ratio':    (num_digit    / input_len) * 100,
        }

    def _max_param_len(self, payload: str) -> int:
        """Độ dài tham số dài nhất trong query string."""
        if not payload:
            return 0
        return max(len(p) for p in payload.split('&'))

    def _url_penalty(self, url: str) -> int:
        """
        Phạt điểm các URL có pattern đặc trưng của công cụ quét / exploit.
        """
        url_lower = str(url).lower()
        penalty   = 0
        for pattern in URL_PENALTY_PATTERNS:
            if re.search(pattern, url_lower):
                penalty += 300
        return penalty

    def _manipulate_weight(self, payload: str) -> int:
        """
        Tính trọng số thao túng tham số:
        - Đếm ký tự đáng ngờ
        - Phát hiện parameter tampering
        - Phạt tham số quá dài (> 150 ký tự)
        """
        if not payload:
            return 0

        decoded  = urllib.parse.unquote_plus(payload)
        weight   = 0

        # Ký tự đáng ngờ
        for char in SUSPICIOUS_CHARS:
            weight += decoded.count(char) * WEIGHTS['manipulation']

        # Parameter tampering điển hình
        for param in TAMPERING_PARAMS:
            if param in payload:
                weight += 300

        # Tham số quá dài
        if self._max_param_len(payload) > 150:
            weight += WEIGHTS['manipulation']

        return weight
