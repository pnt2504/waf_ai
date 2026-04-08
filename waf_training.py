import json
import numpy as np
import pandas as pd
import urllib.parse
import pickle
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# --- CẤU HÌNH TRỌNG SỐ TẤN CÔNG (Dựa trên bài báo) ---
# Bài báo sử dụng cơ sở dữ liệu từ khóa riêng, đây là bộ từ khóa mô phỏng lại
ATTACK_KEYWORDS = {
    'sqli': [
        # Basic SQL
        'select', 'union', 'insert', 'update', 'delete', 'drop', 'from', 'where', 
        'create table', 'alter table', 'truncate table',
        
        # Comments & Obfuscation
        '--', '#', '/*', '*/', ';', '%00',
        
        # Logical & Boolean Injection
        '1=1', 'or 1=1', 'and 1=1', 'or true', 'or 1=1--', 
        
        # Functions & System Variables (Specific to MySQL, MSSQL, PostgreSQL)
        'version()', 'database()', 'user()', '@@version', '@@datadir',
        'sleep(', 'benchmark(', 'delay(', 'waitfor', 
        'char(', 'concat(', 'group_concat', 'cast(', 'convert(',
        'information_schema', 'sys.tables', 'sys.columns', 'table_name'
    ],
    
    'xss': [
        # Tags
        '<script', '</script>', '<img', '<svg', '<body', '<iframe', '<object', '<embed', '<style',
        
        # Attributes & Events (Rất quan trọng cho DOM XSS)
        'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur', 
        'onchange', 'onsubmit', 'onkeydown', 'onkeyup', 'autofocus',
        
        # Protocols & Methods
        'javascript:', 'vbscript:', 'data:', 'expression(', 'eval(', 
        'alert(', 'prompt(', 'confirm(', 'document.cookie', 'document.domain',
        'window.location', 'self.location', 'parent.location', 'fromCharCode'
    ],
    
    'path_traversal': [
        # Directory Navigation
        '../', '..\\', './', '.\\', '%2e%2e%2f', '%2e%2e/', '..%2f',
        
        # Linux System Files
        '/etc/passwd', '/etc/shadow', '/etc/hosts', '/proc/self/environ',
        
        # Windows System Files
        'c:/', 'c:\\', 'windows/system32', 'boot.ini', 'win.ini'
    ],
    
    'cmd_injection': [
        # Command Separators
        ';', '|', '&', '&&', '||', '`', '$()', 
        
        # Common Binaries (Linux/Unix)
        '/bin/sh', '/bin/bash', 'cmd.exe', 'powershell',
        'wget', 'curl', 'netcat', 'nc ', 'ping', 'whoami', 
        'cat ', 'grep', 'more ', 'less ', 'tail ', 'head ',
        'rm -rf', 'mkdir', 'touch'
    ],
    
    'php_injection': [
        # PHP Wrappers & Functions (Nguy hiểm cho web PHP)
        'php://input', 'php://filter', 'expect://', 'data://',
        'exec(', 'system(', 'passthru(', 'shell_exec(', 'pcntl_exec(', 'popen('
    ],
    
    'ldap_injection': [
        # Tấn công LDAP (nếu hệ thống dùng LDAP login)
        '*(', '*&', '(|', ')(', 'cn='
    ]
}

# --- TRỌNG SỐ (WEIGHTS) ĐƯỢC TINH CHỈNH ---
# Nguyên tắc: Từ khóa càng hiếm gặp trong văn bản thường nhưng phổ biến trong tấn công thì điểm càng cao.
WEIGHTS = {
    'sqli': 150,           # SQL Injection rất nguy hiểm
    'xss': 120,            # Tăng nhẹ vì XSS rất phổ biến
    'path': 200,           # Path Traversal hầu như không bao giờ xuất hiện trong request sạch
    'cmd': 250,            # Command Injection cực kỳ nguy hiểm (RCE)
    'php_injection': 250,  # Rất nguy hiểm nếu server chạy PHP
    'ldap_injection': 100,
    'invalid_file': 300,   # File độc hại (.exe, .php) luôn là mức cảnh báo cao nhất
    'manipulation': 100    # Điểm cộng thêm cho hành vi bất thường (Payload lạ)
}

def get_keyword_weight(text):
    """Tính tổng trọng số các từ khóa tấn công tìm thấy trong văn bản."""
    if not text: return 0
    text_lower = urllib.parse.unquote(str(text)).lower()
    total_weight = 0
    
    for k_type, keywords in ATTACK_KEYWORDS.items():
        count = 0
        for kw in keywords:
            if kw in text_lower:
                count += 1
        if count > 0:
            total_weight += count * WEIGHTS.get(k_type, 100)
    return total_weight

def extract_features(entry):
    """
    Trích xuất 4 đặc trưng cốt lõi theo bài báo:
    1. Input Length (l)
    2. Alphanumeric Ratio (a)
    3. Special Char Ratio (s)
    4. Attack Weight (z)
    """
    method = entry.get('method', 'GET')
    url = str(entry.get('url', ''))
    body = str(entry.get('payload', ''))
    headers = entry.get('headers', {})
    
    # --- XỬ LÝ PAYLOAD ---
    # Bài báo định nghĩa Payload là "toàn bộ dữ liệu client gửi lên".
    # Với GET, payload nằm trong Query String của URL.
    # Với POST, payload nằm trong Body.
    effective_payload = body
    if method == 'GET' and '?' in url:
        try:
            effective_payload = url.split('?', 1)[1]
        except:
            effective_payload = ""
            
    # 1. Input Length (l)
    input_len = len(effective_payload)
    
    # 2 & 3. Ratios (a, s)
    alpha_ratio = 0
    special_ratio = 0
    
    if input_len > 0:
        # Đếm số ký tự chữ và số
        num_alphanum = sum(c.isalnum() for c in effective_payload)
        # Số ký tự đặc biệt = Tổng - (Chữ + Số)
        num_special = input_len - num_alphanum
        
        alpha_ratio = (num_alphanum / input_len) * 100
        special_ratio = (num_special / input_len) * 100
    
    # 4. Attack Weight (z) = u + v + m + r + F
    # (i) URL weight (u)
    u = get_keyword_weight(url)
    
    # (ii) Attack words in Inputs (v) - Kiểm tra Payload và Headers
    header_str = " ".join([str(v) for k, v in headers.items()])
    v = get_keyword_weight(effective_payload) + get_keyword_weight(header_str)
    
    # (iii) Manipulate payload (m)
    # Heuristic: Nếu payload dài nhưng tỷ lệ chữ/số quá thấp (<10%), có thể là mã hóa nhị phân độc hại
    m = 0
    if input_len > 20 and alpha_ratio < 10:
        m = WEIGHTS['manipulation']
        
    # (iv) Alpha to Special Ratio Score (r) - Công thức (8) trong bài báo
    # Nếu a/s < 0.3 -> r = 500 (Dấu hiệu bất thường cao)
    r = 0
    if special_ratio > 0:
        if (alpha_ratio / special_ratio) < 0.3:
            r = 500
            
    # (v) Files Weight (F)
    # Kiểm tra đuôi file nguy hiểm trong payload
    F = 0
    dangerous_exts = ['.exe', '.php', '.jsp', '.sh', '.bin', '.pl', '.py']
    payload_lower = effective_payload.lower()
    if any(ext in payload_lower for ext in dangerous_exts):
        F = WEIGHTS['invalid_file']
        
    z = u + v + m + r + F
    
    return [input_len, alpha_ratio, special_ratio, z]

def main():
    # 1. Đọc dữ liệu
    print("Đang đọc file dữ liệu csic_training_data.json...")
    try:
        with open('csic_training_data.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("Lỗi: Không tìm thấy file csic_training_data.json")
        return

    # 2. Trích xuất đặc trưng
    print(f"Đang trích xuất đặc trưng cho {len(data)} bản ghi...")
    X = []
    y = []
    
    for entry in data:
        features = extract_features(entry)
        X.append(features)
        
        # Lấy nhãn (Label)
        # Ưu tiên lấy 'label_id' (đã xử lý ở bước trước), nếu không thì parse từ 'classification'
        label = 0
        if 'label_id' in entry:
            label = entry['label_id']
        elif 'classification' in entry:
            label = int(entry['classification'])
        y.append(label)

    X = np.array(X)
    y = np.array(y)
    
    # 3. Chia tập dữ liệu (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 4. Huấn luyện Mô hình
    print("\n--- KẾT QUẢ HUẤN LUYỆN ---")
    
    # Model 1: Naive Bayes (Bài báo khuyến nghị)
    nb_model = GaussianNB()
    nb_model.fit(X_train, y_train)
    y_pred_nb = nb_model.predict(X_test)
    print(f"\n[Naive Bayes] Accuracy: {accuracy_score(y_test, y_pred_nb)*100:.2f}%")
    
    # Model 2: Decision Tree (Thường tốt hơn với dữ liệu rời rạc)
    dt_model = DecisionTreeClassifier()
    dt_model.fit(X_train, y_train)
    y_pred_dt = dt_model.predict(X_test)
    print(f"\n[Decision Tree] Accuracy: {accuracy_score(y_test, y_pred_dt)*100:.2f}%")
    print(classification_report(y_test, y_pred_dt))
    
    # 5. Lưu model tốt nhất
    best_model = dt_model if accuracy_score(y_test, y_pred_dt) > accuracy_score(y_test, y_pred_nb) else nb_model
    model_filename = 'waf_model.pkl'
    with open(model_filename, 'wb') as f:
        pickle.dump(best_model, f)
    print(f"\nĐã lưu model tốt nhất vào '{model_filename}'. Bạn có thể dùng nó để predict real-time.")

if __name__ == "__main__":
    main()