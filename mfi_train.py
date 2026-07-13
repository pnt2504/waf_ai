# =============================================================================
# mfi_train.py
# Bước 2 — So sánh 2 chiến lược MFI (Missing Feature Imputation):
#   - MFI-Mean            : thay thế feature thiếu = mean toàn bộ CSIC+ECML
#   - MFI-Class-Conditional: thay thế = mean theo class (normal/attack) CSIC+ECML
#
# Features có thể bị thiếu, theo từng nguồn:
#   HTTPParam (url="" và headers rỗng) → thiếu CẢ 7:
#     16 critical_score, 17 is_critical_ext, 19 url_penalty   (từ URL)
#     21 header_anomaly, 23 is_empty_probe, 24 extra_header_risk, 25 is_scanner_ua (từ Headers)
#   Biblio (có URL thật nhưng headers rỗng) → chỉ thiếu 4 feature Header:
#     21 header_anomaly, 23 is_empty_probe, 24 extra_header_risk, 25 is_scanner_ua
#
# Reference để tính mean impute: CSIC+ECML (hai nguồn duy nhất đủ cả 7 feature).
# So sánh: Baseline (zeros) vs MFI-Mean vs MFI-Class-Conditional
# =============================================================================

import json, os, pickle
import numpy as np
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score, f1_score
from sklearn.model_selection import train_test_split
from features.extractor import FeatureExtractor

BASE             = os.path.dirname(os.path.abspath(__file__))
RESULTS_OUT      = os.path.join(BASE, "mfi_results.json")
ATTACK_THRESHOLD = 0.50
CLASS_WEIGHT     = {0: 1, 1: 2}
N_ESTIMATORS     = 300
MAX_DEPTH        = 30
TEST_SIZE        = 0.2
RANDOM_STATE     = 42

# Tập tất cả feature có thể bị thiếu (union), dùng làm thứ tự chuẩn cho mean
ALL_MISSING_IDX = [16, 17, 19, 21, 23, 24, 25]
ALL_MISSING_NAMES = [
    "critical_score", "is_critical_ext", "url_penalty",
    "header_anomaly", "is_empty_probe", "extra_header_risk", "is_scanner_ua",
]

# Feature bị thiếu theo từng nguồn (chỉ những index này mới được impute)
#   httpparam: thiếu cả URL (16,17,19) + Header (21,23,24,25)
#   biblio   : chỉ thiếu Header (21,23,24,25); 3 feature URL có sẵn
MISSING_BY_SOURCE = {
    'httpparam': [16, 17, 19, 21, 23, 24, 25],
    'biblio':    [21, 23, 24, 25],
}


# ─────────────────────────────────────────────
# Load & normalize datasets
# ─────────────────────────────────────────────

def load_all():
    def _load(p): return json.load(open(p, encoding='utf-8'))

    csic   = _load(os.path.join(BASE, 'csic_training_data.json'))
    ecml   = _load(os.path.join(BASE, 'ecml_final.json'))
    http   = _load(os.path.join(BASE, 'httpparam_data.json'))
    biblio = _load(os.path.join(BASE, 'biblio_training_data.json'))

    for r in csic: r.setdefault('http_version', 'HTTP/1.1'); r['source'] = 'csic'
    for r in ecml: r['source'] = 'ecml'

    lmap = {0: 'normal', 1: 'attack'}
    norm_http = []
    for r in http:
        p = str(r.get('payload', ''))
        lid = int(r.get('label_id', 0))
        norm_http.append({
            'time': '2026-01-01T12:00:00+07:00', 'src_ip': '0.0.0.0',
            'http_version': 'HTTP/1.1', 'method': r.get('method', 'POST'),
            'url': '', 'payload': p, 'payload_length': str(len(p)),
            'headers': {'user_agent':'-','referer':'-','cookie':'-',
                        'content_type':'-','authorization':'-',
                        'x_forwarded_for':'-','host':'-','accept':'-'},
            'status': 0, 'label_id': lid, 'label': lmap[lid], 'source': 'httpparam',
        })

    norm_biblio = []
    for r in biblio:
        raw_label = r.get('label', r.get('label_id', 'normal'))
        if isinstance(raw_label, str):
            lid = 1 if raw_label.lower() == 'attack' else 0
        else:
            lid = int(raw_label)
        norm_biblio.append({
            'time':           r.get('time', '2017-01-01T00:00:00+00:00'),
            'src_ip':         r.get('src_ip', '0.0.0.0'),
            'http_version':   r.get('http_version', 'HTTP/1.1'),
            'method':         r.get('method', 'GET'),
            'url':            r.get('url', '/'),
            'payload':        r.get('payload', ''),
            'payload_length': str(r.get('payload_length', 0)),
            'headers': {
                'user_agent':    r.get('headers', {}).get('user_agent', '-'),
                'referer':       r.get('headers', {}).get('referer', '-'),
                'cookie':        r.get('headers', {}).get('cookie', '-'),
                'content_type':  r.get('headers', {}).get('content_type', '-'),
                'authorization': r.get('headers', {}).get('authorization', '-'),
                'x_forwarded_for': r.get('headers', {}).get('x_forwarded_for', '-'),
                'host':          r.get('headers', {}).get('host', '-'),
                'accept':        r.get('headers', {}).get('accept', '-'),
            },
            'status':    int(r.get('status', 0)),
            'label_id':  lid,
            'label':     lmap[lid],
            'source':    'biblio',
        })

    return csic + ecml + norm_http + norm_biblio


# ─────────────────────────────────────────────
# Imputation functions
# ─────────────────────────────────────────────

def compute_imputation_stats(X_train, y_train, src_train):
    """
    Tính mean của ALL_MISSING_IDX từ CSIC+ECML trong tập train.
    Trả về 3 dict {feature_index: mean_value}: global, class0 (normal), class1 (attack).
    Dùng dict để mỗi nguồn lấy đúng tập index bị thiếu của riêng nó.
    """
    mask_ref = (src_train == 'csic') | (src_train == 'ecml')
    X_ref    = X_train[mask_ref]
    y_ref    = y_train[mask_ref]

    feats = X_ref[:, ALL_MISSING_IDX]  # shape: (n_ref, len(ALL_MISSING_IDX))

    g  = feats.mean(axis=0)
    c0 = feats[y_ref == 0].mean(axis=0)
    c1 = feats[y_ref == 1].mean(axis=0)

    mean_global = dict(zip(ALL_MISSING_IDX, g))
    mean_class0 = dict(zip(ALL_MISSING_IDX, c0))
    mean_class1 = dict(zip(ALL_MISSING_IDX, c1))

    print(f"\n  Imputation stats (from CSIC+ECML train, n={mask_ref.sum():,}):")
    for i, name in zip(ALL_MISSING_IDX, ALL_MISSING_NAMES):
        print(f"    [{i:>2d}] {name:<18s}  global={mean_global[i]:.4f}  "
              f"normal={mean_class0[i]:.4f}  attack={mean_class1[i]:.4f}")

    return mean_global, mean_class0, mean_class1


def apply_mfi_mean(X, src, mean_global):
    """Impute feature thiếu bằng mean global, riêng cho từng nguồn (httpparam, biblio)."""
    X_new = X.copy()
    for source, idxs in MISSING_BY_SOURCE.items():
        vals = np.array([mean_global[i] for i in idxs], dtype=X_new.dtype)
        for row in np.where(src == source)[0]:
            X_new[row, idxs] = vals
    return X_new


def apply_mfi_class_conditional(X, y, src, mean_class0, mean_class1):
    """
    Impute feature thiếu bằng mean theo class, riêng cho từng nguồn.
    Mỗi nguồn chỉ impute đúng tập index bị thiếu của nó (MISSING_BY_SOURCE).
    """
    X_new = X.copy()
    for source, idxs in MISSING_BY_SOURCE.items():
        v0 = np.array([mean_class0[i] for i in idxs], dtype=X_new.dtype)
        v1 = np.array([mean_class1[i] for i in idxs], dtype=X_new.dtype)
        mask_src = src == source
        for row in np.where(mask_src & (y == 0))[0]:
            X_new[row, idxs] = v0
        for row in np.where(mask_src & (y == 1))[0]:
            X_new[row, idxs] = v1
    return X_new


# ─────────────────────────────────────────────
# Train + evaluate helper
# ─────────────────────────────────────────────

def train_evaluate(strategy_name, X_train, X_test, y_train, y_test, src_test):
    print(f"\n{'='*65}")
    print(f"  TRAINING: {strategy_name}")
    print(f"{'='*65}")

    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS, max_depth=MAX_DEPTH,
        random_state=RANDOM_STATE, class_weight=CLASS_WEIGHT, n_jobs=-1)
    model.fit(X_train, y_train)

    proba  = model.predict_proba(X_test)[:, 1]
    y_pred = (proba >= ATTACK_THRESHOLD).astype(int)

    results = {'strategy': strategy_name, 'overall': {}, 'per_source': {}}

    # Overall
    acc = accuracy_score(y_test, y_pred)
    f1  = f1_score(y_test, y_pred, average='macro', zero_division=0)
    auc = roc_auc_score(y_test, proba)
    print(f"\n  [OVERALL]  Accuracy={acc*100:.2f}%  F1-macro={f1:.4f}  AUC={auc:.4f}")
    print(classification_report(y_test, y_pred,
                                target_names=['normal','attack'], zero_division=0))
    results['overall'] = {'accuracy': acc, 'f1_macro': f1, 'auc_roc': auc}

    # Per-source
    for src in ['csic', 'ecml', 'httpparam', 'biblio']:
        mask = src_test == src
        if mask.sum() == 0: continue
        f1s  = f1_score(y_test[mask], y_pred[mask], average='macro', zero_division=0)
        accs = accuracy_score(y_test[mask], y_pred[mask])
        try: aucs = roc_auc_score(y_test[mask], proba[mask])
        except: aucs = float('nan')
        # missed attacks
        missed = int(((y_test[mask]==1) & (y_pred[mask]==0)).sum())
        total_atk = int((y_test[mask]==1).sum())
        fp = int(((y_test[mask]==0) & (y_pred[mask]==1)).sum())
        print(f"  [{src.upper():10s}]  F1={f1s:.4f}  Acc={accs*100:.2f}%  "
              f"AUC={aucs:.4f}  Missed={missed}/{total_atk}  FP={fp}")
        results['per_source'][src] = {
            'f1_macro': f1s, 'accuracy': accs, 'auc_roc': aucs,
            'missed': missed, 'total_attack': total_atk, 'false_positive': fp,
        }

    return results, model


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    print("=" * 65)
    print("BƯỚC 2 — MFI STRATEGIES (So sánh 3 chiến lược)")
    print("=" * 65)

    # 1. Load & extract
    print("\n[1] Load và extract features...")
    extractor = FeatureExtractor()
    merged = load_all()
    X, y, sources = [], [], []
    for r in merged:
        X.append(extractor.extract(r))
        y.append(int(r.get('label_id', 0)))
        sources.append(r['source'])
    X       = np.array(X, dtype=np.float32)
    y       = np.array(y)
    sources = np.array(sources)
    print(f"  Feature matrix: {X.shape}")

    # 2. Train/test split — CÙNG seed với baseline để so sánh công bằng
    idx = np.arange(len(X))
    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y, idx, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y)
    src_train = sources[idx_train]
    src_test  = sources[idx_test]
    print(f"  Train={len(X_train):,}  Test={len(X_test):,}")

    # 3. Tính imputation stats từ CSIC+ECML train set
    print("\n[2] Tính imputation stats...")
    mean_global, mean_class0, mean_class1 = compute_imputation_stats(
        X_train, y_train, src_train)

    all_results = []

    # ── Strategy A: Baseline (zeros, không impute) ──
    res_base, _ = train_evaluate(
        "Baseline — Direct Concat (zeros)",
        X_train, X_test, y_train, y_test, src_test)
    all_results.append(res_base)

    # ── Strategy B: MFI-Mean ──
    X_train_mean = apply_mfi_mean(X_train, src_train, mean_global)
    X_test_mean  = apply_mfi_mean(X_test,  src_test,  mean_global)
    res_mean, model_mean = train_evaluate(
        "MFI-Mean",
        X_train_mean, X_test_mean, y_train, y_test, src_test)
    all_results.append(res_mean)

    # ── Strategy C: MFI-Class-Conditional ──
    X_train_cc = apply_mfi_class_conditional(
        X_train, y_train, src_train, mean_class0, mean_class1)
    X_test_cc  = apply_mfi_class_conditional(
        X_test,  y_test,  src_test,  mean_class0, mean_class1)
    res_cc, model_cc = train_evaluate(
        "MFI-Class-Conditional",
        X_train_cc, X_test_cc, y_train, y_test, src_test)
    all_results.append(res_cc)

    # ── Lưu model MFI-CC (tốt nhất về mặt lý thuyết) ──
    pickle.dump(model_cc, open(os.path.join(BASE, 'waf_model_mfi_cc.pkl'), 'wb'))
    pickle.dump(model_mean, open(os.path.join(BASE, 'waf_model_mfi_mean.pkl'), 'wb'))

    # ── Bảng so sánh cuối ──
    print("\n" + "=" * 65)
    print("BẢNG SO SÁNH TỔNG HỢP")
    print("=" * 65)
    header = f"{'Strategy':<30s} {'F1-Overall':>10} {'AUC':>7} {'F1-CSIC':>9} {'F1-ECML':>9} {'F1-HTTP':>9} {'F1-BIBL':>9}"
    print(header)
    print("-" * 75)
    for r in all_results:
        ov = r['overall']
        ps = r['per_source']
        print(f"{r['strategy']:<30s}"
              f"  {ov['f1_macro']:.4f}  "
              f"{ov['auc_roc']:.4f}  "
              f"{ps.get('csic',{}).get('f1_macro',0):.4f}  "
              f"{ps.get('ecml',{}).get('f1_macro',0):.4f}  "
              f"{ps.get('httpparam',{}).get('f1_macro',0):.4f}  "
              f"{ps.get('biblio',{}).get('f1_macro',0):.4f}")

    print("\nMissed attacks (ECML — điểm yếu chính):")
    for r in all_results:
        ecml = r['per_source'].get('ecml', {})
        print(f"  {r['strategy']:<30s}  "
              f"missed={ecml.get('missed','?')}/{ecml.get('total_attack','?')}")

    # Lưu kết quả JSON
    json.dump(all_results, open(RESULTS_OUT, 'w', encoding='utf-8'),
              ensure_ascii=False, indent=2, default=str)
    print(f"\n✓ Kết quả lưu: mfi_results.json")
    print(f"✓ Model MFI-Mean:  waf_model_mfi_mean.pkl")
    print(f"✓ Model MFI-CC:    waf_model_mfi_cc.pkl")


if __name__ == "__main__":
    main()
