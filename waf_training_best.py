import json
import numpy as np
import urllib.parse
import pickle
import math
import re  
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# --- 1. DANH SÁCH "TỬ ĐỊA" (CRITICAL EXTENSIONS) ---
CRITICAL_EXTENSIONS = [
    '.bak', '.old', '.inc', '.nsf', '.tpl', '.cfm', '.cgi',
    '.ini', '.config', '.conf', '.env', '.dat', '.log', '.sql', '.git', '.svn',
    '.sh', '.bin', '.pl', '.py', '.bat', '.cmd', '.mdb', '.sav', '.tmp',
    '.swp', '.lock', '.ds_store', '.java', '.class', '~'
]

# --- 2. DANH SÁCH ĐUÔI FILE NGUY HIỂM KHI UPLOAD ---
MALICIOUS_UPLOAD_EXTS = [
    '.php', '.php3', '.php4', '.php5', '.phtml', '.exe', '.bin', '.sh', '.bat',
    '.cmd', '.cgi', '.pl', '.jsp', '.asp', '.aspx', '.py', '.dll'
]

# --- 3. TỪ ĐIỂN TỪ KHÓA ---
# Từ SQL ngắn: khớp có ranh giới (tránh "insert" trong tham số fuzz / từ ghép vô hại)
SQLI_BOUNDARY_KEYWORDS = [
    'select', 'union', 'insert', 'update', 'delete', 'drop', 'from', 'where',
]
# Chuỗi / toán tử SQL: giữ khớp substring (không dùng ';' đơn lẻ — trùng Accept;q=...)
SQLI_LITERAL_KEYWORDS = [
    'create table', 'alter table', 'truncate table', '--', '#', '/*', '*/', '%00',
    '1=1', 'or 1=1', 'and 1=1', 'or true', 'or 1=1--', 'version()', 'database()',
    'user()', '@@version', 'sleep(', 'benchmark(', 'delay(', 'waitfor', 'concat(',
]

ATTACK_KEYWORDS = {
    'sqli': SQLI_BOUNDARY_KEYWORDS + SQLI_LITERAL_KEYWORDS,
    'xss': [
        '<script', '</script>', '<img', '<svg', '<body', '<iframe', 'onload', 'onerror', 
        'onclick', 'javascript:', 'vbscript:', 'document.cookie', 'alert(', 'prompt(',
        # Bổ sung các từ khóa né filter XSS
        'scriptalert', 'crosssitescripting', 'xss','expression', 'write(', 'confirm('
    ],
    'path_traversal': [
        '../', '..\\', '/etc/passwd', 'windows/system32', 'boot.ini',
        # Bổ sung các mục tiêu dò quét LFI / Path
        'win.ini', 'file:/', 'c:/windows', 'c:\\windows', 'inetpub', 'wwwroot', 'global.asa'
    ],
    # Không dùng ';', '|', '&' đơn lẻ: mọi query có & nối tham số sẽ bị tính nhầm
    'cmd_injection': [
        '&&', '||', '`', '$()', '/bin/sh', 'cmd.exe', 'powershell',
        'wget', 'curl', 'ping', 'whoami', 'cat ', 'grep', 'rm -rf',
    ],
    'php_injection': [
        'php://input', 'php://filter', 'expect://', 'data://', 'exec(', 'system(', 'shell_exec('
    ],
    'probing': [
        'phpinfo()', 'info.php', '/admin', '/backup', '/private',
        '.gif', '.jpg', '.png', '.ico', '.css', '.js', '.aspx',
        # Bổ sung các file cấu hình nhạy cảm
        'web-inf', 'web.xml', '{file}'
    ]
}

# Đã tăng trọng số manipulation lên 150 để thuật toán nhạy bén hơn
WEIGHTS = {
    'sqli': 150, 'xss': 120, 'path': 200, 'cmd': 250, 
    'php_injection': 250, 'probing': 150,
    'invalid_file': 300, 'manipulation': 150 
}

# --- CÁC HÀM XỬ LÝ ---

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def count_keywords(text, keyword_list):
    if not text: return 0
    text_lower = urllib.parse.unquote(str(text)).lower()
    count = 0
    for kw in keyword_list:
        if kw in text_lower:
            count += 1
    return count

def count_sqli_keywords(text):
    if not text:
        return 0
    t = urllib.parse.unquote(str(text)).lower()
    count = 0
    boundary = r'(?<![a-z0-9_])%s(?![a-z0-9_])'
    for w in SQLI_BOUNDARY_KEYWORDS:
        if re.search(boundary % re.escape(w), t):
            count += 1
    for kw in SQLI_LITERAL_KEYWORDS:
        if kw in t:
            count += 1
    return count

def header_anomaly_score(headers):
    if not isinstance(headers, dict):
        return 0
    score = 0
    for key in ('user_agent', 'pragma', 'connection', 'referer'):
        v = str(headers.get(key, '')).strip().lower()
        if v == 'invalid':
            score += 1
    ua = str(headers.get('user_agent', '')).strip()
    if ua and len(ua) < 12:
        score += 1
    return score

def check_critical_extension(url):
    try:
        url_lower = str(url).lower()
        if '?' in url_lower:
            url_lower = url_lower.split('?')[0]
        url_lower = url_lower.rstrip('/')
            
        for ext in CRITICAL_EXTENSIONS:
            if url_lower.endswith(ext):
                return 1
    except:
        return 0
    return 0

def calculate_files_weight(payload):
    weight = 0
    if not payload:
        return 0
    filenames = re.findall(r'filename=["\']?([^"\';\r\n]+)["\']?', str(payload), re.IGNORECASE)
    for fname in filenames:
        fname_lower = fname.lower()
        for ext in MALICIOUS_UPLOAD_EXTS:
            if fname_lower.endswith(ext):
                weight += WEIGHTS['invalid_file']
                break
    return weight

def extract_features_v5(entry):
    method = entry.get('method', 'GET')
    url = str(entry.get('url', ''))
    body = str(entry.get('payload', ''))
    headers = entry.get('headers', {})
    
    effective_payload = body
    if method == 'GET' and '?' in url:
        try:
            effective_payload = url.split('?', 1)[1]
        except:
            effective_payload = ""
    
    # Chỉ quét injection trên URL + phần tham số/payload — không dùng headers (tránh ; trong Accept;q=)
    injection_text = f"{url} {effective_payload}"
    header_anomaly = header_anomaly_score(headers)
    input_len = len(effective_payload)
    
    # Ratios
    alpha_ratio = 0
    special_ratio = 0
    uppercase_ratio = 0
    digit_ratio = 0
    
    if input_len > 0:
        num_alphanum = sum(c.isalnum() for c in effective_payload)
        num_special = input_len - num_alphanum
        num_upper = sum(c.isupper() for c in effective_payload)
        num_digit = sum(c.isdigit() for c in effective_payload)
        
        alpha_ratio = (num_alphanum / input_len) * 100
        special_ratio = (num_special / input_len) * 100
        uppercase_ratio = (num_upper / input_len) * 100
        digit_ratio = (num_digit / input_len) * 100
    
    raw_ratio = 0
    if special_ratio > 0:
        raw_ratio = alpha_ratio / special_ratio

    # Keywords (chỉ injection_text)
    sqli_count = count_sqli_keywords(injection_text)
    xss_count = count_keywords(injection_text, ATTACK_KEYWORDS['xss'])
    path_count = count_keywords(injection_text, ATTACK_KEYWORDS['path_traversal'])
    cmd_count = count_keywords(injection_text, ATTACK_KEYWORDS['cmd_injection'])
    php_count = count_keywords(injection_text, ATTACK_KEYWORDS['php_injection'])
    probing_kw_count = count_keywords(injection_text, ATTACK_KEYWORDS['probing'])
    
    # Quyết định bằng URL
    is_critical_ext = check_critical_extension(url)
    critical_score = is_critical_ext * 500000 
    
    # Trọng số file đính kèm
    files_weight = calculate_files_weight(effective_payload)
    
    # --- CẬP NHẬT: TRỌNG SỐ THAO TÚNG THAM SỐ (MANIPULATE WEIGHT) ---
    manipulate_weight = 0
    decoded_payload = urllib.parse.unquote_plus(effective_payload)
    
    # Đếm số lượng các ký tự dị thường hay dùng để Fuzzing / Injection
    suspicious_chars = ['*', '?', '!', "'", '"', '`', '<', '>', ';', '|', '{', '}', '-']
    for char in suspicious_chars:
        manipulate_weight += decoded_payload.count(char) * WEIGHTS['manipulation']
        
    # Phát hiện nỗ lực Parameter Tampering (đổi tên biến thành cpA=, dniA=)
    if 'cpA=' in effective_payload or 'dniA=' in effective_payload:
        manipulate_weight += 300

    param_count = effective_payload.count('&') + 1 if effective_payload else 0
    entropy_score = calculate_entropy(effective_payload)
    
    max_param_len = 0
    if effective_payload:
        params = effective_payload.split('&')
        for p in params:
            if len(p) > max_param_len:
                max_param_len = len(p)
                
    if max_param_len > 150:
        manipulate_weight += WEIGHTS['manipulation']

    # --- TRỌNG SỐ URL PENALTY ---
    url_penalty = 0
    url_lower = str(url).lower()

    if '.jsp/' in url_lower or '.gif/' in url_lower or '.php/' in url_lower or '.html/' in url_lower:
        url_penalty += 300
    if 'asf-logo-wide' in url_lower or '/manager/html' in url_lower or 'tomcat.css' in url_lower:
        url_penalty += 300
    if '/compass' in url_lower or 'logon.jsp' in url_lower:
        url_penalty += 300
    if re.search(r'\d{10,}\.(jsp|php)', url_lower):
        url_penalty += 300

    method_upper = str(method).upper()
    uncommon_method = 1 if method_upper not in ('GET', 'POST') else 0
    
    # TỔNG TÍNH Z (cộng thêm tín hiệu header bất thường — CSIC thường gắn attack với UA/pragma lạ)
    z = (sqli_count * WEIGHTS['sqli']) + (xss_count * WEIGHTS['xss']) + \
        (path_count * WEIGHTS['path']) + (cmd_count * WEIGHTS['cmd']) + \
        (php_count * WEIGHTS['php_injection']) + \
        (probing_kw_count * WEIGHTS['probing']) + \
        critical_score + files_weight + url_penalty + manipulate_weight + \
        (header_anomaly * 220) + (uncommon_method * 180)

    return [input_len, alpha_ratio, special_ratio, raw_ratio, z, 
            sqli_count, xss_count, path_count, cmd_count, php_count, probing_kw_count,
            param_count, max_param_len, 
            uppercase_ratio, digit_ratio, entropy_score,
            critical_score, is_critical_ext, files_weight, url_penalty, manipulate_weight,
            header_anomaly, uncommon_method] 

def main():
    print("Đang đọc và xử lý dữ liệu...")
    try:
        with open('csic_ecml_features.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("Lỗi file.")
        return

    X = []
    y = []
    raw_entries = []

    for entry in data:
        features = extract_features_v5(entry)
        X.append(features)
        
        label = 0
        if 'label_id' in entry:
            label = entry['label_id']
        elif 'classification' in entry:
            label = int(entry['classification'])
        y.append(label)
        raw_entries.append(entry)

    X = np.array(X)
    y = np.array(y)
    
    indices = np.arange(len(X))
    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y, indices, test_size=0.2, random_state=42, stratify=y
    )
    
    print("\n--- HUẤN LUYỆN VỚI RANDOM FOREST (V5.2 - GIẢM NHIỄU HEADER + CÂN LỚP) ---")
    rf_model = RandomForestClassifier(
        n_estimators=300, max_depth=30, random_state=42, class_weight='balanced'
    )
    rf_model.fit(X_train, y_train)
    
    y_pred = rf_model.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    print(f"Random Forest Accuracy: {acc*100:.2f}%")
    print(classification_report(y_test, y_pred))
    
    print("\n--- TRÍCH XUẤT VÀ LƯU CÁC LỖI BỎ LỌT (FALSE NEGATIVES) ---")
    count_err = 0
    missed_attacks_data = []
    
    # Danh sách tên các feature tương ứng với hàm extract_features_v5
    feature_names = [
        "input_len", "alpha_ratio", "special_ratio", "raw_ratio", "z_score", 
        "sqli_count", "xss_count", "path_count", "cmd_count", "php_count", "probing_kw_count",
        "param_count", "max_param_len", "uppercase_ratio", "digit_ratio", "entropy_score",
        "critical_score", "is_critical_ext", "files_weight", "url_penalty", "manipulate_weight",
        "header_anomaly", "uncommon_method",
    ]

    for i in range(len(y_test)):
        # y_test = 1 (Thực tế là tấn công), y_pred = 0 (Model đoán là an toàn)
        if y_test[i] == 1 and y_pred[i] == 0:
            original_idx = idx_test[i]
            entry = raw_entries[original_idx]
            features_array = X_test[i]
            
            # Map giá trị với tên feature tương ứng
            extracted_features = dict(zip(feature_names, features_array))
            
            # Đóng gói dữ liệu
            missed_info = {
                "raw_request": entry,
                "extracted_features": extracted_features
            }
            missed_attacks_data.append(missed_info)
            count_err += 1
            
    print(f"Tổng số tấn công bị bỏ lọt: {count_err} / {sum(y_test == 1)}")
    
    # Lưu ra file json
    if count_err > 0:
        output_file = 'missed_attacks.json'
        with open(output_file, 'w', encoding='utf-8') as outfile:
            json.dump(missed_attacks_data, outfile, ensure_ascii=False, indent=4)
        print(f"Đã xuất chi tiết toàn bộ các request bỏ lọt vào file: {output_file}")
    
    # Lưu model
    with open('waf_model_final_v6.pkl', 'wb') as f:
        pickle.dump(rf_model, f)
    print("Đã lưu model V5.2.")

if __name__ == "__main__":
    main()