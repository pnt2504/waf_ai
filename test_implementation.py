import csv
from waf_features import extract_features_from_request

# === Đường dẫn tới file Excel/CSV (sửa lại cho đúng trên máy bạn) ===
CSV_PATH = r'd:\Tai lieu 20251\Project 3\cisc 2010\csic_database.csv'

def normalize_header(name: str) -> str:
    """Chuyển tên cột về dạng viết thường không khoảng trắng để so khớp dễ hơn"""
    return name.strip().lower().replace("-", "_").replace(" ", "_")

def parse_row(row):
    """Chuyển một dòng CSV thành dạng request"""
    # Chuẩn hóa tên cột
    normalized = {normalize_header(k): v for k, v in row.items()}

    return {
        "method": normalized.get("method", "GET"),
        "url": normalized.get("url", ""),
        "headers": {
            "User-Agent": normalized.get("user_agent", ""),
            "Content-Type": normalized.get("content_type", ""),
            "Cookie": normalized.get("cookie", ""),
            "Accept": normalized.get("accept", ""),
        },
        # Payload có thể nằm ở Content / Body / Params
        "body": normalized.get("content", normalized.get("body", normalized.get("params", ""))),
    }

def main():
    print("Đang đọc file:", CSV_PATH)
    with open(CSV_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=1):
            req = parse_row(row)
            feats = extract_features_from_request(req)
            attack_weight = feats.get("attack_weight", 0)

            # Gắn nhãn tạm: >150 là attack
            label = "Normal" if attack_weight == 0 else "Attack"

            print(f"Row {i}: attack_weight={attack_weight:.2f} -> {label}")

if __name__ == "__main__":
    main()
