"""
Converter: Biblio-US17 → JSON format của WAF model

Format nguồn (tab-delimited):
  [MM-DD-Fnnnnnn]  METHOD  URI  PROTOCOL»  RESP_CODE  RESP_SIZE

Cách dùng:
  python convert_biblio.py --clean_dir /path/to/CLEAN --attack_dir /path/to/ATTACK
                           --output biblio_training_data.json
                           --max_normal 36000 --max_attack 25000
"""

import os
import re
import json
import random
import argparse
import urllib.parse
from pathlib import Path

# Ký tự separator trong file: có thể là tab hoặc space
LINE_RE = re.compile(
    r'^\[(\S+)\]\s+(\w+)\s+(\S+)\s+HTTP/[\d.]+["\s]*\s+(\d+)\s+(\d+)',
    re.IGNORECASE
)


def parse_line(line: str):
    """Parse một dòng record, trả về dict hoặc None nếu không hợp lệ."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    m = LINE_RE.match(line)
    if not m:
        return None

    identifier, method, uri, resp_code, resp_size = m.groups()

    # Tách query string từ URI
    if '?' in uri:
        path, query = uri.split('?', 1)
        payload = query
    else:
        path, payload = uri, ''

    return {
        'method': method.upper(),
        'url': f'http://biblio-us17{uri}',    # synthetic host
        'payload': payload,
        'headers': {},                          # không có headers trong dataset này
        'resp_code': int(resp_code),
        'resp_size': int(resp_size),
        '_identifier': identifier,
        '_path': path,
    }


def load_files(directory: str, label: int, max_records: int, shuffle: bool = True) -> list:
    """Đọc tất cả .cl hoặc .att files trong thư mục, lấy tối đa max_records records."""
    directory = Path(directory)
    all_files = sorted(list(directory.glob('*.cl')) + list(directory.glob('*.att'))
                       + list(directory.glob('*.raw')) + list(directory.glob('*.clean')))

    if not all_files:
        print(f"  [!] Không tìm thấy file .cl/.att trong {directory}")
        return []

    print(f"  Tìm thấy {len(all_files)} files trong {directory}")

    records = []
    for fpath in all_files:
        try:
            with open(fpath, encoding='utf-8', errors='replace') as f:
                for line in f:
                    parsed = parse_line(line)
                    if parsed:
                        parsed['label_id'] = label
                        records.append(parsed)
        except Exception as e:
            print(f"  [!] Lỗi đọc {fpath}: {e}")

        if len(records) >= max_records * 3:  # đọc dư để shuffle được tốt
            break

    if shuffle:
        random.shuffle(records)

    return records[:max_records]


def main():
    parser = argparse.ArgumentParser(description='Convert Biblio-US17 to WAF JSON format')
    parser.add_argument('--clean_dir',  required=True, help='Thư mục chứa .cl files (normal traffic)')
    parser.add_argument('--attack_dir', required=True, help='Thư mục chứa .att files (attack traffic)')
    parser.add_argument('--output',     default='biblio_training_data.json', help='File JSON output')
    parser.add_argument('--max_normal', type=int, default=36000, help='Số records normal tối đa')
    parser.add_argument('--max_attack', type=int, default=25000, help='Số records attack tối đa')
    parser.add_argument('--seed',       type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)

    print(f"[1/3] Đọc normal traffic từ: {args.clean_dir}")
    normals = load_files(args.clean_dir, label=0, max_records=args.max_normal)
    print(f"      → {len(normals)} normal records")

    print(f"[2/3] Đọc attack traffic từ: {args.attack_dir}")
    attacks = load_files(args.attack_dir, label=1, max_records=args.max_attack)
    print(f"      → {len(attacks)} attack records")

    all_records = normals + attacks
    random.shuffle(all_records)

    print(f"[3/3] Ghi {len(all_records)} records → {args.output}")
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(all_records, f, ensure_ascii=False, indent=2)

    print(f"\n✓ Hoàn thành! File: {args.output}")
    print(f"  Normal: {len(normals)}, Attack: {len(attacks)}")
    print(f"\nLưu ý: Dataset này không có HTTP headers → các features")
    print(f"  header_anomaly, is_scanner_ua, is_empty_probe sẽ = 0")
    print(f"  Model sẽ phụ thuộc vào URI-based features nhiều hơn.")


if __name__ == '__main__':
    main()
