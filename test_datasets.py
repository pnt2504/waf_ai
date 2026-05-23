"""
test_datasets.py
================
Đánh giá model WAF trên 4 tập dữ liệu: CSIC, ECML, HTTParam, Biblio-US17

Chạy trực tiếp (không cần server, nhanh nhất):
    python test_datasets.py                              # tất cả 4 dataset
    python test_datasets.py --datasets csic,ecml,http   # chỉ 3 dataset gốc
    python test_datasets.py --datasets biblio           # chỉ Biblio
    python test_datasets.py --model waf_model_moe_v2_best.pkl
    python test_datasets.py --model waf_model_moe_v2_best.pkl --threshold 0.45

Chạy qua WAF API /predict (localhost:8000):
    python test_datasets.py --http
    python test_datasets.py --http --limit 500

Chạy qua Nginx thực tế (localhost:8080) — đúng pipeline production:
    python test_datasets.py --nginx
    python test_datasets.py --nginx --limit 1000
    python test_datasets.py --nginx --workers 8 --limit 2000
"""

import warnings
warnings.filterwarnings("ignore")

import argparse
import json
import os
import pickle
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    accuracy_score, classification_report,
    confusion_matrix, f1_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split

# Tắt sklearn joblib parallel warnings (xuất hiện nhiều lần khi dùng RandomForest)
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", message=".*sklearn.utils.parallel.*")

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))
from features.extractor import FeatureExtractor

# Tham số split phải khớp với moe_train_v2.py
SPLIT_TEST_SIZE   = 0.2
SPLIT_RANDOM_STATE = 42

# =============================================================================
# Cấu hình mặc định
# =============================================================================
DEFAULT_MODEL     = "waf_model_baseline.pkl"
DEFAULT_THRESHOLD = 0.50
WAF_API_URL       = "http://localhost:8000/predict"
NGINX_URL         = "http://localhost:8080"

# =============================================================================
# Load & chuẩn hoá dữ liệu
# =============================================================================

def load_csic(limit=None):
    data = json.load(open(BASE / "csic_training_data.json", encoding="utf-8"))
    if limit:
        data = data[:limit]
    return data, "csic"


def load_ecml(limit=None):
    data = json.load(open(BASE / "ecml_final.json", encoding="utf-8"))
    if limit:
        data = data[:limit]
    return data, "ecml"


def load_httpparam(limit=None):
    raw  = json.load(open(BASE / "httpparam_data.json", encoding="utf-8"))
    data = []
    for r in raw:
        p = str(r.get("payload", ""))
        data.append({
            "time": "2026-01-01T12:00:00+07:00", "src_ip": "0.0.0.0",
            "method": r.get("method", "POST"), "url": "", "payload": p,
            "payload_length": str(len(p)),
            "headers": {
                "user_agent": "-", "referer": "-", "cookie": "-",
                "content_type": "-", "authorization": "-",
                "x_forwarded_for": "-", "host": "-", "accept": "-",
            },
            "status": 0, "label_id": int(r.get("label_id", 0)),
            "label": "attack" if r.get("label_id") == 1 else "normal",
        })
    if limit:
        data = data[:limit]
    return data, "httpparam"


def load_biblio(limit=None):
    """Load Biblio-US17 từ biblio_training_data.json (đã convert từ .cl/.att)."""
    raw  = json.load(open(BASE / "biblio_training_data.json", encoding="utf-8"))
    lmap = {0: "normal", 1: "attack"}
    data = []
    for r in raw:
        raw_label = r.get("label", r.get("label_id", "normal"))
        if isinstance(raw_label, str):
            lid = 1 if raw_label.lower() == "attack" else 0
        else:
            lid = int(raw_label)
        data.append({
            "time":           r.get("time", "2017-01-01T00:00:00+00:00"),
            "src_ip":         r.get("src_ip", "0.0.0.0"),
            "http_version":   r.get("http_version", "HTTP/1.1"),
            "method":         r.get("method", "GET"),
            "url":            r.get("url", "/"),
            "payload":        r.get("payload", ""),
            "payload_length": str(r.get("payload_length", 0)),
            "headers": {
                "user_agent":      r.get("headers", {}).get("user_agent", "-"),
                "referer":         r.get("headers", {}).get("referer", "-"),
                "cookie":          r.get("headers", {}).get("cookie", "-"),
                "content_type":    r.get("headers", {}).get("content_type", "-"),
                "authorization":   r.get("headers", {}).get("authorization", "-"),
                "x_forwarded_for": r.get("headers", {}).get("x_forwarded_for", "-"),
                "host":            r.get("headers", {}).get("host", "-"),
                "accept":          r.get("headers", {}).get("accept", "-"),
            },
            "status":    int(r.get("status", 0)),
            "label_id":  lid,
            "label":     lmap[lid],
            "source":    "biblio",
        })
    if limit:
        data = data[:limit]
    return data, "biblio"


def load_test_split():
    """
    Tái tạo đúng tập test 20% dùng trong training (random_state=42).
    Trả về dict {source: [records]} để test từng dataset riêng.
    Bao gồm cả Biblio-US17 (biblio_training_data.json).
    """
    extractor = FeatureExtractor()

    # Load & chuẩn hoá giống moe_train_v2.py
    csic_data,   _ = load_csic()
    ecml_data,   _ = load_ecml()
    http_data,   _ = load_httpparam()
    biblio_data, _ = load_biblio()

    all_records = []
    for r in csic_data:
        r["source"] = "csic";     all_records.append(r)
    for r in ecml_data:
        r["source"] = "ecml";     all_records.append(r)
    for r in http_data:
        r["source"] = "httpparam"; all_records.append(r)
    for r in biblio_data:
        r["source"] = "biblio";   all_records.append(r)

    print(f"  Trích xuất features từ {len(all_records):,} records...", end=" ", flush=True)
    t0 = time.perf_counter()
    X  = np.array([extractor.extract(r) for r in all_records], dtype=np.float32)
    y  = np.array([int(r.get("label_id", 0)) for r in all_records])
    print(f"xong ({time.perf_counter()-t0:.1f}s)")

    # Tái tạo đúng split — phải khớp với moe_train_v2.py
    idx = np.arange(len(all_records))
    _, _, _, _, idx_train, idx_test = train_test_split(
        X, y, idx,
        test_size=SPLIT_TEST_SIZE,
        random_state=SPLIT_RANDOM_STATE,
        stratify=y,
    )

    # Gom records test theo từng nguồn
    split = {"csic": [], "ecml": [], "httpparam": [], "biblio": []}
    for i in idx_test:
        src = all_records[i]["source"]
        split[src].append(all_records[i])

    sizes = {k: len(v) for k, v in split.items()}
    print(f"  Test split: {sum(sizes.values()):,} records  "
          f"({sizes['csic']:,} CSIC / {sizes['ecml']:,} ECML / "
          f"{sizes['httpparam']:,} HTTP / {sizes['biblio']:,} Biblio)")
    return split, X[idx_test], y[idx_test], extractor


# =============================================================================
# Predict — mode trực tiếp
# =============================================================================

def predict_direct(records, model, extractor, threshold):
    """Chạy predict trực tiếp qua model pkl — dùng batch predict_proba (nhanh hơn ~100x)."""
    t0 = time.perf_counter()

    # Trích xuất tất cả features thành một ma trận → gọi predict_proba 1 lần duy nhất
    X      = np.array([extractor.extract(r) for r in records], dtype=np.float32)
    y_true = np.array([int(r.get("label_id", 0)) for r in records])

    raw    = model.predict_proba(X)
    y_proba = raw[:, 1] if raw.ndim == 2 else raw
    y_pred  = (y_proba >= threshold).astype(int)

    elapsed = time.perf_counter() - t0
    return y_true, y_pred, y_proba, elapsed


# =============================================================================
# Predict — mode WAF API (/predict)
# =============================================================================

def predict_http(records, threshold, waf_url):
    """Gửi từng request lên WAF server qua /predict (JSON API)."""
    y_true, y_pred, y_proba = [], [], []
    t0   = time.perf_counter()
    errs = 0

    for i, r in enumerate(records):
        if i % 200 == 0 and i > 0:
            elapsed = time.perf_counter() - t0
            print(f"    {i}/{len(records)}  ({elapsed:.0f}s)...", end="\r")
        entry = {
            "method":  r.get("method", "GET"),
            "url":     r.get("url", "/"),
            "payload": r.get("payload", ""),
            "headers": r.get("headers", {}),
        }
        try:
            req  = urllib.request.Request(
                waf_url,
                data=json.dumps(entry).encode(),
                headers={"Content-Type": "application/json"},
            )
            resp  = urllib.request.urlopen(req, timeout=5)
            body  = json.loads(resp.read())
            proba = float(body.get("attack_probability", 0))
            pred  = 1 if proba >= threshold else 0
        except Exception:
            errs += 1
            proba = 0.0
            pred  = 0

        y_true.append(int(r.get("label_id", 0)))
        y_pred.append(pred)
        y_proba.append(proba)

    elapsed = time.perf_counter() - t0
    if errs:
        print(f"    ⚠  {errs} request lỗi")
    return np.array(y_true), np.array(y_pred), np.array(y_proba), elapsed


# =============================================================================
# Predict — mode Nginx thực tế (pipeline đầy đủ)
# =============================================================================

def _send_nginx_one(args):
    """Worker: gửi 1 request thật qua Nginx, trả (label, pred, proba)."""
    r, nginx_url, timeout = args
    method  = r.get("method", "GET").upper()
    url_path = r.get("url", "/") or "/"
    # Đảm bảo url_path bắt đầu bằng /
    if not url_path.startswith("/"):
        url_path = "/" + url_path
    payload = r.get("payload", "") or ""
    headers = r.get("headers", {}) or {}

    # Map header dict → HTTP headers thật
    hdr = {
        "User-Agent":      headers.get("user_agent", "TestClient/1.0"),
        "Accept":          headers.get("accept", "*/*"),
        "Accept-Language": headers.get("accept_language", ""),
        "Accept-Encoding": headers.get("accept_encoding", ""),
        "Referer":         headers.get("referer", ""),
        "Cookie":          headers.get("cookie", ""),
        "Connection":      "keep-alive",
    }
    # Bỏ header rỗng / "-"
    hdr = {k: v for k, v in hdr.items() if v and v != "-"}

    body_bytes = payload.encode("utf-8", errors="replace") if payload else None
    if body_bytes:
        hdr["Content-Type"]   = headers.get("content_type", "application/x-www-form-urlencoded")
        hdr["Content-Length"] = str(len(body_bytes))

    full_url = nginx_url.rstrip("/") + url_path
    label    = int(r.get("label_id", 0))

    try:
        req  = urllib.request.Request(full_url, data=body_bytes,
                                      headers=hdr, method=method)
        resp = urllib.request.urlopen(req, timeout=timeout)
        # 200 → NORMAL (WAF cho qua)
        # Đọc X-WAF-Probability nếu có
        prob_hdr = resp.headers.get("X-WAF-Probability", "")
        proba    = float(prob_hdr) if prob_hdr else 0.0
        return label, 0, proba
    except urllib.error.HTTPError as e:
        if e.code == 403:
            # 403 → WAF chặn → ATTACK
            prob_hdr = e.headers.get("X-WAF-Probability", "")
            proba    = float(prob_hdr) if prob_hdr else 1.0
            return label, 1, proba
        # Lỗi khác (500, timeout...) → coi là NORMAL
        return label, 0, 0.0
    except Exception:
        return label, 0, 0.0


def predict_nginx(records, nginx_url, workers=4, timeout=5):
    """
    Gửi request thật qua Nginx (port 8080) — đúng pipeline production.
    Dùng ThreadPoolExecutor để tăng tốc (I/O-bound).
    Không cần threshold vì Nginx trả 200/403.
    """
    t0     = time.perf_counter()
    args   = [(r, nginx_url, timeout) for r in records]
    n      = len(records)
    done   = 0

    results = [None] * n
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_send_nginx_one, a): i for i, a in enumerate(args)}
        for fut in as_completed(futures):
            idx          = futures[fut]
            results[idx] = fut.result()
            done        += 1
            if done % 200 == 0:
                elapsed = time.perf_counter() - t0
                rps = done / elapsed
                eta = (n - done) / rps if rps > 0 else 0
                print(f"    {done}/{n}  {rps:.0f} req/s  ETA {eta:.0f}s   ", end="\r")

    elapsed  = time.perf_counter() - t0
    y_true   = np.array([r[0] for r in results])
    y_pred   = np.array([r[1] for r in results])
    y_proba  = np.array([r[2] for r in results])
    return y_true, y_pred, y_proba, elapsed


# =============================================================================
# Hiển thị kết quả
# =============================================================================

def print_metrics(name, y_true, y_pred, y_proba, elapsed, verbose=True):
    acc  = accuracy_score(y_true, y_pred)
    f1   = f1_score(y_true, y_pred, average="macro", zero_division=0)
    try:
        auc = roc_auc_score(y_true, y_proba)
    except Exception:
        auc = float("nan")

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision_atk  = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall_atk     = tp / (tp + fn) if (tp + fn) > 0 else 0
    ms_per_req     = elapsed / len(y_true) * 1000

    n_atk    = int(y_true.sum())
    n_normal = len(y_true) - n_atk

    print(f"\n  ┌─ {name} ({len(y_true):,} records: {n_normal:,} normal / {n_atk:,} attack)")
    print(f"  │  Accuracy : {acc*100:.2f}%   F1-macro : {f1:.4f}   AUC : {auc:.4f}")
    print(f"  │  Detection: {recall_atk*100:.2f}%  (missed {fn}/{n_atk} attacks)")
    print(f"  │  Precision: {precision_atk*100:.2f}%  (false positive {fp}/{n_normal})")
    print(f"  │  Speed    : {ms_per_req:.3f} ms/req  (total {elapsed:.1f}s)")
    print(f"  └──────────────────────────────────────────")

    if verbose:
        print(f"\n  Confusion matrix ({name}):")
        print(f"              Predicted")
        print(f"              Normal   Attack")
        print(f"  Actual Normal  {tn:6d}   {fp:6d}   (FP={fp})")
        print(f"  Actual Attack  {fn:6d}   {tp:6d}   (missed={fn})")

    return {
        "dataset":   name,
        "n_total":   len(y_true),
        "n_attack":  n_atk,
        "n_normal":  n_normal,
        "accuracy":  round(acc, 4),
        "f1_macro":  round(f1, 4),
        "auc":       round(auc, 4),
        "precision_attack": round(precision_atk, 4),
        "recall_attack":    round(recall_atk, 4),
        "tp": int(tp), "tn": int(tn),
        "fp": int(fp), "fn": int(fn),
        "ms_per_req": round(ms_per_req, 3),
    }


def print_fp_examples(name, records, y_true, y_pred, y_proba, n=5):
    """In ví dụ false positive để debug."""
    fps = [(i, y_proba[i]) for i in range(len(y_true))
           if y_true[i] == 0 and y_pred[i] == 1]
    fps.sort(key=lambda x: -x[1])
    if not fps:
        return
    print(f"\n  Top {min(n, len(fps))} False Positives ({name}):")
    for i, (idx, prob) in enumerate(fps[:n]):
        r = records[idx]
        url  = r.get("url", "")[:60]
        body = r.get("payload", "")[:40]
        print(f"    [{i+1}] p={prob:.3f}  {r.get('method','?')} {url}")
        if body:
            print(f"         body: {body!r}")


def print_fn_examples(name, records, y_true, y_pred, y_proba, n=5):
    """In ví dụ missed attacks để debug."""
    fns = [(i, y_proba[i]) for i in range(len(y_true))
           if y_true[i] == 1 and y_pred[i] == 0]
    fns.sort(key=lambda x: x[1])
    if not fns:
        return
    print(f"\n  Top {min(n, len(fns))} Missed Attacks ({name}) [xác suất thấp nhất]:")
    for i, (idx, prob) in enumerate(fns[:n]):
        r = records[idx]
        url  = r.get("url", "")[:60]
        body = r.get("payload", "")[:40]
        print(f"    [{i+1}] p={prob:.3f}  {r.get('method','?')} {url}")
        if body:
            print(f"         body: {body!r}")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Đánh giá WAF model trên 3 dataset")
    parser.add_argument("--model",     default=DEFAULT_MODEL,
                        help=f"Tên file .pkl (mặc định: {DEFAULT_MODEL})")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help=f"Ngưỡng tấn công (mặc định: {DEFAULT_THRESHOLD})")
    parser.add_argument("--http",      action="store_true",
                        help="Test qua WAF API /predict (localhost:8000)")
    parser.add_argument("--nginx",     action="store_true",
                        help="Test qua Nginx thực tế (localhost:8080) — pipeline đầy đủ")
    parser.add_argument("--workers",   type=int, default=4,
                        help="Số luồng song song khi dùng --nginx (mặc định: 4)")
    parser.add_argument("--limit",     type=int, default=None,
                        help="Giới hạn số mẫu mỗi dataset (mặc định: toàn bộ)")
    parser.add_argument("--test-split", action="store_true",
                        help="Chỉ chạy trên 20%% test split (khớp với tập test lúc train)")
    parser.add_argument("--examples",  action="store_true",
                        help="In ví dụ FP/FN để debug")
    parser.add_argument("--datasets",  default="csic,ecml,http,biblio",
                        help="Dataset cần test, cách nhau dấu phẩy (csic/ecml/http/biblio)")
    args = parser.parse_args()

    model_path = BASE / args.model
    threshold  = args.threshold
    use_nginx  = args.nginx
    use_http   = args.http and not use_nginx

    print("=" * 65)
    print("  WAF DATASET EVALUATION")
    print("=" * 65)

    # ── Load model / kiểm tra server ─────────────────────────────────────────
    extractor = None
    model     = None

    if use_nginx:
        # Kiểm tra Nginx đang chạy
        try:
            urllib.request.urlopen(f"{NGINX_URL}/nginx-health", timeout=3)
            print(f"  Mode     : Nginx thực tế → {NGINX_URL}")
        except Exception:
            try:
                urllib.request.urlopen(NGINX_URL, timeout=3)
                print(f"  Mode     : Nginx thực tế → {NGINX_URL}")
            except Exception:
                print(f"  ✗ Nginx không phản hồi tại {NGINX_URL}")
                print(f"     Chạy: docker compose up -d  (trong thư mục lab/)")
                sys.exit(1)
        print(f"  Workers  : {args.workers} luồng song song")
        print(f"  Lưu ý   : Threshold do WAF server quyết định, không phải script này")

    elif use_http:
        # Kiểm tra WAF API
        try:
            urllib.request.urlopen("http://localhost:8000/health", timeout=3)
            print(f"  Mode     : WAF API → {WAF_API_URL}")
        except Exception:
            print(f"  ✗ WAF server không phản hồi tại localhost:8000")
            sys.exit(1)
        print(f"  Threshold: {threshold}")

    else:
        if not model_path.exists():
            print(f"  ✗ Không tìm thấy model: {model_path}")
            sys.exit(1)
        with open(model_path, "rb") as fp:
            model = pickle.load(fp)
        extractor  = FeatureExtractor()
        model_type = type(model).__name__
        n_feat     = getattr(model, "n_features_in_", "?")
        print(f"  Mode     : Trực tiếp (không qua server)")
        print(f"  Model    : {args.model}  ({model_type}, features={n_feat})")
        print(f"  Threshold: {threshold}")

    use_test_split = args.test_split
    _limit_str = "all" if not args.limit else str(args.limit)
    _data_str  = "20% test split (khớp train)" if use_test_split else f"toàn bộ  (limit={_limit_str})"
    print(f"  Tập data : {_data_str}")

    # ── Nhánh --test-split: load model trực tiếp, chạy trên 20% test ─────────
    if use_test_split:
        if use_nginx or use_http:
            print("  ⚠ --test-split chỉ hoạt động với mode trực tiếp (bỏ --nginx/--http)")
            sys.exit(1)
        if not model_path.exists():
            print(f"  ✗ Không tìm thấy model: {model_path}")
            sys.exit(1)
        with open(model_path, "rb") as fp:
            model = pickle.load(fp)

        print(f"\n  Load & split data...")
        split_records, _, _, _ = load_test_split()

        all_results = []
        all_true, all_pred, all_proba = [], [], []
        extractor = FeatureExtractor()
        key_label = {"csic": "CSIC", "ecml": "ECML", "httpparam": "HTTParam", "biblio": "Biblio"}

        for src_key, label in key_label.items():
            records = split_records[src_key]
            if not records:
                continue
            print(f"\n  Đang test {label} ({len(records):,} records — test split)...")
            y_true, y_pred, y_proba, elapsed = predict_direct(
                records, model, extractor, threshold)
            res = print_metrics(label, y_true, y_pred, y_proba, elapsed,
                                verbose=args.examples)
            all_results.append(res)
            if args.examples:
                print_fp_examples(label, records, y_true, y_pred, y_proba)
                print_fn_examples(label, records, y_true, y_pred, y_proba)
            all_true.extend(y_true.tolist())
            all_pred.extend(y_pred.tolist())
            all_proba.extend(y_proba.tolist())

        # Tổng hợp + bảng (dùng lại code bên dưới)
        _print_summary(all_results, all_true, all_pred, all_proba,
                       use_nginx, use_http)
        return

    # ── Nhánh thường: load từng dataset ───────────────────────────────────────
    dataset_map = {
        "csic":   load_csic,
        "ecml":   load_ecml,
        "http":   load_httpparam,
        "biblio": load_biblio,
    }
    label_name = {
        "csic": "CSIC", "ecml": "ECML",
        "http": "HTTParam", "biblio": "Biblio",
    }
    selected = [s.strip() for s in args.datasets.split(",")]

    all_results = []
    all_true, all_pred, all_proba = [], [], []

    for key in selected:
        if key not in dataset_map:
            print(f"  ⚠ Dataset không hợp lệ: {key}")
            continue

        records, src = dataset_map[key](limit=args.limit)
        label = label_name[key]

        print(f"\n  Đang test {label} ({len(records):,} records)...")

        if use_nginx:
            y_true, y_pred, y_proba, elapsed = predict_nginx(
                records, NGINX_URL, workers=args.workers)
        elif use_http:
            y_true, y_pred, y_proba, elapsed = predict_http(
                records, threshold, WAF_API_URL)
        else:
            y_true, y_pred, y_proba, elapsed = predict_direct(
                records, model, extractor, threshold)

        res = print_metrics(label, y_true, y_pred, y_proba, elapsed,
                            verbose=args.examples)
        all_results.append(res)

        if args.examples:
            print_fp_examples(label, records, y_true, y_pred, y_proba)
            print_fn_examples(label, records, y_true, y_pred, y_proba)

        all_true.extend(y_true.tolist())
        all_pred.extend(y_pred.tolist())
        all_proba.extend(y_proba.tolist())

    _print_summary(all_results, all_true, all_pred, all_proba,
                   use_nginx, use_http)


def _print_summary(all_results, all_true, all_pred, all_proba,
                   use_nginx=False, use_http=False):
    """In bảng tổng hợp cuối."""
    if len(all_results) > 1:
        at = np.array(all_true)
        ap = np.array(all_pred)
        ab = np.array(all_proba)
        print("\n")
        print_metrics("OVERALL", at, ap, ab, elapsed=0, verbose=False)

    print(f"\n{'='*65}")
    print(f"  {'Dataset':<12} {'Acc':>7} {'F1':>7} {'AUC':>7} "
          f"{'Detect%':>8} {'FP':>6} {'Miss':>6} {'ms/req':>8}")
    print(f"  {'-'*61}")
    for r in all_results:
        print(f"  {r['dataset']:<12}"
              f"  {r['accuracy']*100:>6.2f}%"
              f"  {r['f1_macro']:>6.4f}"
              f"  {r['auc']:>6.4f}"
              f"  {r['recall_attack']*100:>7.2f}%"
              f"  {r['fp']:>6}"
              f"  {r['fn']:>6}"
              f"  {r['ms_per_req']:>7.3f}ms")

    print(f"{'='*65}")
    mode_hint = "--nginx" if use_nginx else ("--http" if use_http else "")
    print(f"\n  Gợi ý:")
    print(f"    # Test trên 20%% test split  : python test_datasets.py --test-split")
    print(f"    # So sánh MoE               : python test_datasets.py --test-split --model waf_model_moe_v2_best.pkl")
    print(f"    # Xem FP/FN cụ thể         : python test_datasets.py --test-split {mode_hint} --examples")
    print(f"    # Test qua Nginx thực tế   : python test_datasets.py --nginx --limit 2000")
    print(f"    # Test Biblio riêng         : python test_datasets.py --datasets biblio")


if __name__ == "__main__":
    main()
