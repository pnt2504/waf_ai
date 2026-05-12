# =============================================================================
# mfi_train.py
# Bước 2 — So sánh 2 chiến lược MFI (Missing Feature Imputation):
#   - MFI-Mean            : thay thế feature thiếu = mean toàn bộ CSIC+ECML
#   - MFI-Class-Conditional: thay thế = mean theo class (normal/attack) CSIC+ECML
#
# Features bị thiếu trong HTTPParam (url="" và headers={}):
#   16  critical_score     (từ URL)
#   17  is_critical_ext    (từ URL)
#   19  url_penalty        (từ URL)
#   21  header_anomaly     (từ Headers)
#   23  is_empty_probe     (từ Headers)
#   24  extra_header_risk  (từ Headers)
#   25  is_scanner_ua      (từ Headers)
#
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

# Indices của features bị thiếu trong HTTPParam
MISSING_IDX = [16, 17, 19, 21, 23, 24, 25]
MISSING_NAMES = [
    "critical_score", "is_critical_ext", "url_penalty",
    "header_anomaly", "is_empty_probe", "extra_header_risk", "is_scanner_ua",
]


# ─────────────────────────────────────────────
# Load & normalize datasets
# ─────────────────────────────────────────────

def load_all():
    def _load(p): return json.load(open(p, encoding='utf-8'))

    csic = _load(os.path.join(BASE, 'csic_training_data.json'))
    ecml = _load(os.path.join(BASE, 'ecml_final.json'))
    http = _load(os.path.join(BASE, 'httpparam_data.json'))

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
    return csic + ecml + norm_http


# ─────────────────────────────────────────────
# Imputation functions
# ─────────────────────────────────────────────

def compute_imputation_stats(X_train, y_train, src_train):
    """
    Tính mean của MISSING_IDX từ CSIC+ECML trong tập train.
    Trả về: mean_global, mean_class0, mean_class1 (mỗi cái là array độ dài 7)
    """
    mask_ref = (src_train == 'csic') | (src_train == 'ecml')
    X_ref    = X_train[mask_ref]
    y_ref    = y_train[mask_ref]

    feats = X_ref[:, MISSING_IDX]  # shape: (n_ref, 7)

    mean_global = feats.mean(axis=0)
    mean_class0 = feats[y_ref == 0].mean(axis=0)
    mean_class1 = feats[y_ref == 1].mean(axis=0)

    print(f"\n  Imputation stats (from CSIC+ECML train, n={mask_ref.sum():,}):")
    for i, name in enumerate(MISSING_NAMES):
        print(f"    {name:<22s}  global={mean_global[i]:.4f}  "
              f"normal={mean_class0[i]:.4f}  attack={mean_class1[i]:.4f}")

    return mean_global, mean_class0, mean_class1


def apply_mfi_mean(X, src, mean_global):
    """Thay thế feature thiếu của HTTPParam bằng mean global."""
    X_new = X.copy()
    mask  = src == 'httpparam'
    X_new[mask][:, MISSING_IDX] = mean_global
    # Cập nhật inplace đúng cách
    httpparam_rows = np.where(mask)[0]
    for row in httpparam_rows:
        X_new[row, MISSING_IDX] = mean_global
    return X_new


def apply_mfi_class_conditional(X, y, src, mean_class0, mean_class1):
    """
    Thay thế feature thiếu của HTTPParam bằng mean theo class.
    Dùng được ở train (y có sẵn) và test (y có sẵn khi eval).
    """
    X_new = X.copy()
    mask_http    = src == 'httpparam'
    mask_normal  = mask_http & (y == 0)
    mask_attack  = mask_http & (y == 1)

    for row in np.where(mask_normal)[0]:
        X_new[row, MISSING_IDX] = mean_class0
    for row in np.where(mask_attack)[0]:
        X_new[row, MISSING_IDX] = mean_class1
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
    for src in ['csic', 'ecml', 'httpparam']:
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
    header = f"{'Strategy':<30s} {'F1-Overall':>10} {'AUC':>7} {'F1-CSIC':>9} {'F1-ECML':>9} {'F1-HTTP':>9}"
    print(header)
    print("-" * 65)
    for r in all_results:
        ov = r['overall']
        ps = r['per_source']
        print(f"{r['strategy']:<30s}"
              f"  {ov['f1_macro']:.4f}  "
              f"{ov['auc_roc']:.4f}  "
              f"{ps.get('csic',{}).get('f1_macro',0):.4f}  "
              f"{ps.get('ecml',{}).get('f1_macro',0):.4f}  "
              f"{ps.get('httpparam',{}).get('f1_macro',0):.4f}")

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
