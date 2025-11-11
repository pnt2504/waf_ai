import csv
from waf_features import extract_features_from_request
from collections import Counter
import json
from datetime import datetime

# Đường dẫn file
CSV_PATH = r'd:\Tai lieu 20251\Project 3\cisc 2010\csic_database.csv'
RESULT_PATH = 'csic_analysis_results.json'

def normalize_header(name: str) -> str:
    """Chuyển tên cột về dạng viết thường không khoảng trắng"""
    return name.strip().lower().replace("-", "_").replace(" ", "_")

def parse_row(row):
    """Chuyển một dòng CSV thành dạng request chuẩn"""
    normalized = {normalize_header(k): v for k, v in row.items()}

    # TÌM NHÃN GỐC: kiểm tra nhiều candidate keys (có thể cột đầu không có header)
    label_val = None
    for cand in ("", "classification", "label", "original_label", "original", "class", "type"):
        if cand in normalized and normalized.get(cand) not in (None, ""):
            label_val = normalized.get(cand)
            break

    # Chuẩn hóa nhãn gốc về "Normal" / "Attack"
    def normalize_label(v):
        if v is None:
            return "Normal"
        s = str(v).strip().lower()
        if s in ("1", "attack", "att", "malicious", "true"):
            return "Attack"
        if s in ("0", "normal", "benign", "false"):
            return "Normal"
        # cố gắng detect từ chuỗi
        if "attack" in s or "mal" in s or "sql" in s:
            return "Attack"
        return "Normal"

    original_label = normalize_label(label_val)

    return {
        "method": normalized.get("method", "GET"),
        "url": normalized.get("url", ""),
        "headers": {
            "User-Agent": normalized.get("user_agent", ""),
            "Content-Type": normalized.get("content_type", ""),
            "Cookie": normalized.get("cookie", ""),
            "Accept": normalized.get("accept", ""),
        },
        "body": normalized.get("content", normalized.get("body", normalized.get("params", ""))),
        "original_label": original_label
    }

def analyze_csic():
    """Phân tích toàn bộ dataset CSIC"""
    stats = Counter()
    results = []
    
    print(f"Bắt đầu phân tích file: {CSV_PATH}")
    print("=" * 50)
    
    with open(CSV_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=1):
            # Parse và extract features
            req = parse_row(row)
            feats = extract_features_from_request(req)
            attack_weight = feats.get("attack_weight", 0)
            alpha_ratio = feats.get("alpha_ratio", 0)
            nonalpha_ratio = feats.get("nonalpha_ratio", 0)

            # Lấy nhãn gốc từ request (sửa lỗi: biến original chưa được định nghĩa)
            original = req.get("original_label", "Normal")
            
            # Phân loại dựa trên attack_weight
                       # ======= PHÂN LOẠI =======
            if attack_weight > 0:
                predicted = "Attack"
            else:
                predicted = "Normal"

            
            # Cập nhật thống kê
            stats["total"] += 1
            stats[predicted] += 1
            if predicted != original:
                stats["mismatches"] += 1
            
            # Lưu kết quả chi tiết
            result = {
                "row": i+1,
                "url": req["url"],
                "method": req["method"],
                "attack_weight": attack_weight,
                "predicted": predicted,
                "original_label": original,
                "features": feats
            }
            results.append(result)
            
            # In tiến trình
            if i % 100 == 0:
                print(f"Đã xử lý {i} requests...")

    # Lưu kết quả vào file JSON
    output = {
        "timestamp": datetime.now().isoformat(),
        "statistics": dict(stats),
        "results": results
    }
    
    with open(RESULT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # In thống kê
    print("\nKết quả phân tích:")
    print(f"Tổng số requests: {stats['total']}")
    print(f"Phân loại Normal: {stats['Normal']}")
    print(f"Phân loại Attack: {stats['Attack']}")
    print(f"Số lượng không khớp với nhãn gốc: {stats['mismatches']}")
    print(f"\nKết quả chi tiết đã được lưu vào: {RESULT_PATH}")

if __name__ == "__main__":
    analyze_csic()
