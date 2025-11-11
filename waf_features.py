# waf_features.py
"""
Module trích xuất đặc trưng cho mô hình WAF dựa trên bài
"Web Application Firewall Using Machine Learning and Features Engineering" (2022).

Đầu vào chính: 1 HTTP request (raw hoặc đã parse).
Đầu ra: dict gồm 4 đặc trưng số + optional label (nếu bạn có).

Các đặc trưng cuối:
- payload_len
- alpha_ratio
- nonalpha_ratio
- attack_weight
"""

import re
import urllib.parse #dùng để parse query string (parse_qsl)
from typing import Dict, Any, Optional, List #type hints


# ===== 1. CÁC BẢNG THAM CHIẾU (tạm đủ dùng, bạn mở rộng sau) =====

# Từ/câu hay gặp trong tấn công (payload + header)
ATTACK_WORDS = {
    "union": 150,
    "select": 150,
    "insert": 150,
    "update": 150,
    "delete": 150,
    "drop": 150,
    "or 1=1": 150,
    "' or 1=1 --": 150,
    "\" or 1=1 --": 150,
    "sleep(": 150,
    "benchmark(": 150,
    "../": 120,
    "<script": 150,
    "onerror=": 150,
    "onload=": 150,
    "alert(": 150,
}

# Truy cập tài nguyên nhạy cảm trong URL
SENSITIVE_URL_PATTERNS = {
    ".env": 200,
    ".git": 200,
    ".svn": 200,
    "wp-config.php": 200,
    "/admin": 150,
    "/phpmyadmin": 200,
    "/etc/passwd": 250,
    ".bak": 200,
}

# Kiểu "manipulation" đơn giản: gửi chữ vào chỗ đáng lẽ là số
# (bài báo làm phần này bằng bảng trong DB – ở đây mình mock logic)
MANIPULATION_WEIGHT = 100 #trọng số dùng khi phát hiện manipulation

# Phần mở rộng file nguy hiểm
SUSPICIOUS_EXTENSIONS = {
    ".php": 300,
    ".phtml": 300,
    ".asp": 300,
    ".aspx": 300,
    ".jsp": 300,
    ".exe": 300,
    ".bin": 300,
    ".sh": 300,
}

# Thêm vào phần constants
SUSPICIOUS_POST_MIN_LEN = 30  # Ngưỡng độ dài tối thiểu cho POST request
SUSPICIOUS_POST_WEIGHT = 100  # Trọng số cho POST request đáng ngờ

# ===== 2. HÀM PHỤ =====

def _to_str(val: Any) -> str:
    #chuyển giá trị thành string an toàn, None -> "", tránh lỗi khi gọi .lower() hoặc len()
    return val if isinstance(val, str) else ("" if val is None else str(val))


def _extract_payload_from_request(req: Dict[str, Any]) -> str:
    """
    Chuẩn hóa lại payload để tính toán.
    Hỗ trợ:
        - req["body"]
        - req["payload"]
        - req["data"]
    """
    for key in ("body", "payload", "data"):
        if key in req and req[key]:
            return _to_str(req[key])
    return ""


def _extract_headers_from_request(req: Dict[str, Any]) -> Dict[str, str]:
    #lấy headers từ request, chuẩn hóa key thành lowercase và value thành str
    return {k.lower(): _to_str(v) for k, v in req.get("headers", {}).items()}


def _extract_files_from_request(req: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    files = [
        {"filename": "shell.php", "content_type": "application/x-php", "size": 1234},
        ...
    ]
    """
    return req.get("files", []) #trả về danh sách file, mặc định rỗng nếu không có


def _count_alpha_numeric_ratio(s: str) -> (float, float):
    #tính tỉ lệ ký tự chữ và số trên tổng độ dài chuỗi
    if not s:
        return 0.0, 0.0 #tránh chia 0(nếu rỗng)
    total = len(s)# tổng số ký tự
    alpha = sum(ch.isalnum() for ch in s) #đếm kí tự chữ hoặc số
    alpha_ratio = (alpha / total) * 100# tỉ lệ % alnum(chữ và số)
    nonalpha_ratio = 100 - alpha_ratio #tỉ lệ % ký tự đặc biệt
    return alpha_ratio, nonalpha_ratio


def _calc_url_weight(url: str) -> int:
    """
    Tính trọng số URL (u) dựa trên:
    1. Truy cập tài nguyên nhạy cảm (SENSITIVE_URL_PATTERNS)
    2. Từ khóa tấn công (ATTACK_WORDS) xuất hiện trong URL
    (Theo bài báo )
    """
    url_lower = url.lower()
    score = 0
    
    # 1. Kiểm tra tài nguyên nhạy cảm (bạn đã làm)
    for pattern, w in SENSITIVE_URL_PATTERNS.items():
        if pattern in url_lower:
            score += w
            
    # 2. Bổ sung: Kiểm tra từ khóa tấn công trong URL
    # (Bài báo gộp chung 'attack words' vào )
    for word, w in ATTACK_WORDS.items():
        if word in url_lower:
            # Bài báo không nói rõ có nhân count ở URL không,
            # nhưng để nhất quán với hàm 'v', ta nên nhân.
            count = url_lower.count(word)
            score += w * count # Giả định trọng số 'w' áp dụng cả ở URL

    # Heuristic của bạn (có thể giữ lại)
    if "%" in url:
        score += 30
        
    return score


def _calc_attack_words_in_inputs(payload: str, headers: Dict[str, str]) -> int:
    #nối payload và headers thành 1 chuỗi lớn để dò tìm từ tấn công
    text = payload.lower() + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
    score = 0
    for word, w in ATTACK_WORDS.items(): #duyệt qua các từ tấn công
        if word in text: 
            # đếm số lần xuất hiện
            count = text.count(word)
            score += w * count #cộng trọng số tương ứng
    return score


def _calc_manipulated_payload_weight(payload: str) -> int:
    """
    Heuristic đơn giản:
    - Nếu payload trông giống form (a=b&c=d)
    - Mà có biến tên 'id', 'age', 'phone' nhưng giá trị không phải số -> tính điểm
    """
    if not payload or "=" not in payload:
        return 0 #nếu không có cặp key=value thì bỏ qua

    score = 0
    #parse_qsl trả về list các cặp (key, value) từ query/form-encoded body
    pairs = urllib.parse.parse_qsl(payload, keep_blank_values=True)
    numeric_like_keys = {"id", "age", "phone", "quantity", "amount", "uid"} #các field đáng lẽ numeric
    for k, v in pairs:
        k_lower = k.lower()
        if k_lower in numeric_like_keys and v and not v.isdigit():
            # nếu key là field numeric mà value không phải số -> nghi ngờ thao tác
            score += MANIPULATION_WEIGHT
    return score


def _calc_alpha_to_special_ratio(alpha_ratio: float, nonalpha_ratio: float) -> int:
    """
    Bài báo làm kiểu:
        if (nonalpha/alpha) >= 0.3: r = 500 else 0
    Ở đây mình bám gần giống, chỉ cần alpha_ratio > 0 để tránh chia 0.
    """
    if alpha_ratio <= 0:
        return 0 #tránh chia 0
    ratio = nonalpha_ratio / alpha_ratio  # tỉ lệ ký tự đặc biệt trên ký tự chữ+số
    if ratio >= 0.3:
        return 500
    return 0


def _calc_files_weight(files: List[Dict[str, Any]]) -> int:
    """
    Tính trọng số file (F)
    Bài báo [cite: 393, 395] tính trọng số cho 1 file (f) = w1 + w2 + w3 + w4
    w1 = 300 (extension)
    w2 = 200 (Kaspersky)
    w3 = 200 (MalwareBytes)
    w4 = 200 (BitDefender)
    
    Trọng số F là tổng của tất cả các file f[cite: 401].
    
    Ở đây ta mô phỏng:
    - Input 'files' có thể chứa cờ cho từng AV.
    """
    total_F = 0
    
    for f in files:
        file_score_f = 0
        filename = _to_str(f.get("filename", "")).lower()

        # 1. Tính w1 (Invalid extension) 
        for ext, w_ext in SUSPICIOUS_EXTENSIONS.items():
            if filename.endswith(ext):
                file_score_f += w_ext # w1 = 300
                break # Chỉ tính 1 lần cho mỗi file
                
        # 2. Tính w2, w3, w4 (AV scans) 
        # Giả sử input 'f' có các cờ này
        if f.get("av_kaspersky_positive", False):
            file_score_f += 200 # w2
        if f.get("av_malwarebytes_positive", False):
            file_score_f += 200 # w3
        if f.get("av_bitdefender_positive", False):
            file_score_f += 200 # w4

        # Ví dụ mô phỏng cờ "malware" chung của bạn (nếu dùng)
        # Nếu cờ 'malware' đại diện cho *ít nhất 1* AV dương tính
        # if f.get("malware", False):
        #    file_score_f += 200 # Đây là cách bạn làm
        #
        # Nếu 'malware' là tổng hợp cả 3 (cách mô phỏng tốt hơn)
        # if f.get("malware", 0) == 3: # (ví dụ 3/3 AV phát hiện)
        #    file_score_f += 600

        total_F += file_score_f # Cộng trọng số của file này vào tổng F
        
    return total_F


# ===== 3. HÀM CHÍNH TRÍCH XUẤT ĐẶC TRƯNG =====

# ===== 3. HÀM CHÍNH TRÍCH XUẤT ĐẶC TRƯNG =====

def extract_features_from_request(request: Dict[str, Any], label: Optional[int] = None) -> Dict[str, Any]:
    """
    request: dạng dict chuẩn hóa...
    """
    method = _to_str(request.get("method", "GET"))

    # ===== THAY ĐỔI QUAN TRỌNG Ở ĐÂY =====
    # Chúng ta phải GIẢI MÃ (DECODE) dữ liệu trước khi phân tích
    
    url_raw = _to_str(request.get("url", ""))
    payload_raw = _extract_payload_from_request(request)
    headers_raw = _extract_headers_from_request(request)

    url = urllib.parse.unquote(url_raw)
    payload = urllib.parse.unquote(payload_raw)
    
    # Headers cũng có thể chứa payload đã mã hóa (ví dụ trong Cookie)
    headers = {k: urllib.parse.unquote(v) for k, v in headers_raw.items()}
    
    # (Phần còn lại của file giữ nguyên)
    # ========================================

    files = _extract_files_from_request(request) #danh sách file nếu có

    # 1) payload_len
    # TÍNH TOÁN DỰA TRÊN PAYLOAD GỐC (chưa giải mã) HAY ĐÃ GIẢI MÃ?
    # Bài báo không nói rõ, nhưng logic là độ dài của payload nhận được
    # Hãy dùng payload_raw để nhất quán
    payload_len = len(payload_raw) 

    # 2) alpha_ratio & nonalpha_ratio
    # Tỷ lệ ký tự nên được tính trên payload GỐC (raw)
    # vì %27 là 3 ký tự, không phải ' (1 ký tự)
    alpha_ratio, nonalpha_ratio = _count_alpha_numeric_ratio(payload_raw)

    # 3) attack_weight = u + v + m + r + F
    #
    # *** TẤT CẢ TÍNH TOÁN TRỌNG SỐ PHẢI DÙNG DỮ LIỆU ĐÃ GIẢI MÃ ***
    #
    url_weight = _calc_url_weight(url) # Dùng url (đã giải mã)
    attack_words_weight = _calc_attack_words_in_inputs(payload, headers) # Dùng payload, headers (đã giải mã)
    manipulated_weight = _calc_manipulated_payload_weight(payload) # Dùng payload (đã giải mã)
    
    # Tỷ lệ r nên được tính trên payload ĐÃ GIẢI MÃ
    # vì chúng ta quan tâm đến tỷ lệ ký tự đặc biệt 'thật'
    alpha_ratio_decoded, nonalpha_ratio_decoded = _count_alpha_numeric_ratio(payload)
    ratio_weight = _calc_alpha_to_special_ratio(alpha_ratio_decoded, nonalpha_ratio_decoded)
    
    files_weight = _calc_files_weight(files)

    # Thêm kiểm tra POST request có payload ngắn
    suspicious_post_weight = 0
    if method.upper() == "POST" and payload_len < SUSPICIOUS_POST_MIN_LEN:
        suspicious_post_weight = SUSPICIOUS_POST_WEIGHT

    # Cập nhật attack_weight
    attack_weight = url_weight + attack_words_weight + manipulated_weight + ratio_weight + files_weight + suspicious_post_weight

    features = {
        "payload_len": payload_len,
        "alpha_ratio": alpha_ratio,
        "nonalpha_ratio": nonalpha_ratio, 
        "attack_weight": attack_weight,
        "suspicious_post": True if suspicious_post_weight > 0 else False  # Thêm flag để debug
    }

    if label is not None:
        features["label"] = int(label)

    return features 


# ===== 4. VÍ DỤ CHẠY THỬ =====
if __name__ == "__main__":
    sample_req = {
        "method": "POST",
        "url": "http://victim.local/.env",
        "headers": {
            "User-Agent": "sqlmap/1.5",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        "body": "username=admin&password=' or 1=1 --&id=abc",
        "files": [
            {"filename": "shell.php"},
        ],
    }
    feats = extract_features_from_request(sample_req, label=1)
    print(feats)
    # Kỳ vọng: payload_len > 0, alpha_ratio < 100, attack_weight rất lớn
