# =============================================================================
# merge_datasets.py
# Bước 1 — Baseline: Hợp nhất 3 dataset HTTP thành merged_baseline.json
#
# Xử lý:
#   - CSIC 2010      : csic_training_data.json   (đủ fields, thiếu http_version)
#   - ECML/PKDD      : ecml_final.json            (đầy đủ nhất)
#   - HTTPParam      : converted_httpparam_data.json (chỉ có method + payload + label_id)
#
# Chiến lược normalize HTTPParam (Direct Concat — baseline):
#   - url            → "" (rỗng, giữ nguyên)
#   - headers        → {} (rỗng, giữ nguyên)
#   - payload_length → str(len(payload))
#   - http_version   → "HTTP/1.1" (mặc định)
#   - time           → "2026-01-01T12:00:00+07:00"
#   - src_ip         → "0.0.0.0"
#   - status         → 0
#   - label          → "normal" hoặc "attack" map từ label_id
#   - source         → tên dataset gốc (để phân tích sau)
# =============================================================================

import json
import os
from collections import Counter

BASE = os.path.dirname(os.path.abspath(__file__))


def load_json(filename: str) -> list:
    path = os.path.join(BASE, filename)
    print(f"  Đọc {filename}...")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    print(f"  → {len(data):,} records")
    return data


def normalize_csic(records: list) -> list:
    """
    CSIC: thiếu http_version → điền mặc định.
    Thêm field source để tracking.
    """
    result = []
    for r in records:
        entry = dict(r)
        entry.setdefault("http_version", "HTTP/1.1")
        entry["source"] = "csic"
        result.append(entry)
    return result


def normalize_ecml(records: list) -> list:
    """ECML: đầy đủ, chỉ thêm source."""
    result = []
    for r in records:
        entry = dict(r)
        entry["source"] = "ecml"
        result.append(entry)
    return result


def normalize_httpparam(records: list) -> list:
    """
    HTTPParam: chỉ có method + payload + label_id.
    Điền tất cả fields còn thiếu bằng giá trị mặc định (Direct Concat baseline).
    """
    label_map = {0: "normal", 1: "attack"}
    result = []
    for r in records:
        payload = str(r.get("payload", ""))
        label_id = int(r.get("label_id", 0))
        entry = {
            "time":           "2026-01-01T12:00:00+07:00",
            "src_ip":         "0.0.0.0",
            "http_version":   "HTTP/1.1",
            "method":         r.get("method", "POST"),
            "url":            "",
            "payload":        payload,
            "payload_length": str(len(payload)),
            "headers": {
                "user_agent":    "-",
                "referer":       "-",
                "cookie":        "-",
                "content_type":  "-",
                "authorization": "-",
                "x_forwarded_for": "-",
                "host":          "-",
                "accept":        "-",
            },
            "status":   0,
            "label_id": label_id,
            "label":    label_map.get(label_id, "normal"),
            "source":   "httpparam",
        }
        result.append(entry)
    return result


def print_stats(name: str, records: list) -> None:
    labels = Counter(r.get("label", r.get("label_id")) for r in records)
    print(f"  {name}: {len(records):,} records | {dict(labels)}")


def main():
    print("=" * 60)
    print("BƯỚC 1 — BASELINE: HỢP NHẤT 3 DATASET")
    print("=" * 60)

    # --- Load ---
    print("\n[1/3] Đọc datasets...")
    csic      = load_json("csic_training_data.json")
    ecml      = load_json("ecml_final.json")
    httpparam = load_json("httpparam_data.json")

    # --- Normalize ---
    print("\n[2/3] Normalize từng dataset...")
    csic_norm      = normalize_csic(csic)
    ecml_norm      = normalize_ecml(ecml)
    httpparam_norm = normalize_httpparam(httpparam)

    print_stats("CSIC     ", csic_norm)
    print_stats("ECML     ", ecml_norm)
    print_stats("HTTPParam", httpparam_norm)

    # --- Merge ---
    merged = csic_norm + ecml_norm + httpparam_norm
    print(f"\n[3/3] Tổng hợp: {len(merged):,} records")
    print_stats("MERGED   ", merged)

    # Label distribution tổng
    label_dist = Counter(r["label"] for r in merged)
    normal_pct = label_dist["normal"] / len(merged) * 100
    attack_pct = label_dist["attack"] / len(merged) * 100
    print(f"\n  normal: {label_dist['normal']:,} ({normal_pct:.1f}%)")
    print(f"  attack: {label_dist['attack']:,} ({attack_pct:.1f}%)")

    # --- Lưu ---
    output_path = os.path.join(BASE, "merged_baseline.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
    print(f"\n✓ Đã lưu: merged_baseline.json ({len(merged):,} records)")
    print("=" * 60)


if __name__ == "__main__":
    main()
