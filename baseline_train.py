# =============================================================================
# baseline_train.py
# Bước 1 — Baseline: load 3 dataset trực tiếp, merge trong RAM, train & evaluate
# Không cần file merged trung gian.
# =============================================================================

import json, os, pickle
import numpy as np
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, classification_report,
    roc_auc_score, f1_score, confusion_matrix,
)
from sklearn.model_selection import train_test_split
from features.extractor import FeatureExtractor

BASE             = os.path.dirname(os.path.abspath(__file__))
MODEL_OUT        = os.path.join(BASE, "waf_model_baseline.pkl")
RESULTS_OUT      = os.path.join(BASE, "baseline_results.json")
ATTACK_THRESHOLD = 0.50
CLASS_WEIGHT     = {0: 1, 1: 2}
N_ESTIMATORS     = 300
MAX_DEPTH        = 30
TEST_SIZE        = 0.2
RANDOM_STATE     = 42


# ─────────────────────────────────────────────
# Normalize từng dataset về schema chung
# ─────────────────────────────────────────────

def load_csic(path):
    data = json.load(open(path, encoding='utf-8'))
    for r in data:
        r.setdefault('http_version', 'HTTP/1.1')
        r['source'] = 'csic'
    return data

def load_ecml(path):
    data = json.load(open(path, encoding='utf-8'))
    for r in data:
        r['source'] = 'ecml'
    return data

def load_httpparam(path):
    raw  = json.load(open(path, encoding='utf-8'))
    lmap = {0: 'normal', 1: 'attack'}
    out  = []
    for r in raw:
        p   = str(r.get('payload', ''))
        lid = int(r.get('label_id', 0))
        out.append({
            'time': '2026-01-01T12:00:00+07:00',
            'src_ip': '0.0.0.0',
            'http_version': 'HTTP/1.1',
            'method': r.get('method', 'POST'),
            'url': '',
            'payload': p,
            'payload_length': str(len(p)),
            'headers': {
                'user_agent': '-', 'referer': '-', 'cookie': '-',
                'content_type': '-', 'authorization': '-',
                'x_forwarded_for': '-', 'host': '-', 'accept': '-',
            },
            'status': 0,
            'label_id': lid,
            'label': lmap[lid],
            'source': 'httpparam',
        })
    return out


def load_biblio(path):
    raw  = json.load(open(path, encoding='utf-8'))
    lmap = {0: 'normal', 1: 'attack'}
    out  = []
    for r in raw:
        raw_label = r.get('label', r.get('label_id', 'normal'))
        lid = 1 if (isinstance(raw_label, str) and raw_label.lower() == 'attack') \
              else (int(raw_label) if not isinstance(raw_label, str) else 0)
        out.append({
            'time':           r.get('time', '2017-01-01T00:00:00+00:00'),
            'src_ip':         r.get('src_ip', '0.0.0.0'),
            'http_version':   r.get('http_version', 'HTTP/1.1'),
            'method':         r.get('method', 'GET'),
            'url':            r.get('url', '/'),
            'payload':        r.get('payload', ''),
            'payload_length': str(r.get('payload_length', 0)),
            'headers': {
                'user_agent': '-', 'referer': '-', 'cookie': '-',
                'content_type': '-', 'authorization': '-',
                'x_forwarded_for': '-', 'host': '-', 'accept': '-',
            },
            'status':   int(r.get('status', 0)),
            'label_id': lid,
            'label':    lmap[lid],
            'source':   'biblio',
        })
    return out


# ─────────────────────────────────────────────
# Evaluate helper
# ─────────────────────────────────────────────

def evaluate_subset(name, y_true, y_pred, y_proba):
    if len(y_true) == 0:
        return {}
    acc = accuracy_score(y_true, y_pred)
    f1  = f1_score(y_true, y_pred, average='macro', zero_division=0)
    try:
        auc = roc_auc_score(y_true, y_proba)
    except ValueError:
        auc = float('nan')
    cm = confusion_matrix(y_true, y_pred)
    print(f"\n  [{name}]  n={len(y_true):,}")
    print(f"    Accuracy : {acc*100:.2f}%  |  F1-macro: {f1:.4f}  |  AUC-ROC: {auc:.4f}")
    print(f"    Confusion matrix:\n{cm}")
    print(classification_report(y_true, y_pred,
                                target_names=['normal','attack'], zero_division=0))
    return {'accuracy': acc, 'f1_macro': f1, 'auc_roc': auc,
            'confusion_matrix': cm.tolist(), 'n_samples': int(len(y_true))}


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    print("=" * 65)
    print("BƯỚC 1 — BASELINE (Direct Concat, 4 datasets, no imputation)")
    print("=" * 65)

    # 1. Load
    print("\n[1] Load datasets...")
    csic      = load_csic     (os.path.join(BASE, 'csic_training_data.json'))
    ecml      = load_ecml     (os.path.join(BASE, 'ecml_final.json'))
    httpparam = load_httpparam(os.path.join(BASE, 'httpparam_data.json'))
    biblio    = load_biblio   (os.path.join(BASE, 'biblio_training_data.json'))
    merged    = csic + ecml + httpparam + biblio

    lc = Counter(r['label'] for r in merged)
    print(f"  CSIC={len(csic):,}  ECML={len(ecml):,}  HTTPParam={len(httpparam):,}  Biblio={len(biblio):,}")
    print(f"  TOTAL={len(merged):,} | normal={lc['normal']:,} attack={lc['attack']:,}")

    # 2. Extract features
    print("\n[2] Trích xuất features...")
    extractor = FeatureExtractor()
    X, y, sources = [], [], []
    for r in merged:
        X.append(extractor.extract(r))
        y.append(int(r.get('label_id', 0)))
        sources.append(r['source'])
    X       = np.array(X, dtype=np.float32)
    y       = np.array(y)
    sources = np.array(sources)
    print(f"  Feature matrix: {X.shape}")

    # 3. Split
    idx = np.arange(len(X))
    X_train, X_test, y_train, y_test, _, idx_test = train_test_split(
        X, y, idx, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y)
    src_test = sources[idx_test]
    print(f"\n[3] Train={len(X_train):,}  Test={len(X_test):,}")

    # 4. Train
    print(f"\n[4] Train Random Forest (n={N_ESTIMATORS}, depth={MAX_DEPTH})...")
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS, max_depth=MAX_DEPTH,
        random_state=RANDOM_STATE, class_weight=CLASS_WEIGHT, n_jobs=-1)
    model.fit(X_train, y_train)
    print("    Hoàn tất.")

    # 5. Predict
    proba  = model.predict_proba(X_test)[:, 1]
    y_pred = (proba >= ATTACK_THRESHOLD).astype(int)

    # 6. Evaluate
    print("\n" + "=" * 65)
    print("KẾT QUẢ — TỔNG THỂ")
    print("=" * 65)
    overall = evaluate_subset("OVERALL", y_test, y_pred, proba)

    print("\n" + "=" * 65)
    print("KẾT QUẢ — THEO TỪNG DATASET")
    print("=" * 65)
    per_source = {}
    for src in ['csic', 'ecml', 'httpparam', 'biblio']:
        mask = src_test == src
        per_source[src] = evaluate_subset(
            src.upper(), y_test[mask], y_pred[mask], proba[mask])

    # 7. Feature importance
    print("\n" + "=" * 65)
    print("TOP 10 FEATURE IMPORTANCE")
    print("=" * 65)
    feat_names  = extractor.feature_names
    importances = model.feature_importances_
    top_idx     = np.argsort(importances)[::-1][:10]
    feat_imp    = {}
    for rank, i in enumerate(top_idx, 1):
        print(f"  {rank:2d}. {feat_names[i]:<25s} {importances[i]:.4f}")
        feat_imp[feat_names[i]] = float(importances[i])

    # 8. Save
    results = {
        'strategy': 'baseline_direct_concat',
        'datasets': ['csic', 'ecml', 'httpparam', 'biblio'],
        'n_train': int(len(X_train)), 'n_test': int(len(X_test)),
        'threshold': ATTACK_THRESHOLD,
        'overall': overall,
        'per_source': per_source,
        'top10_features': feat_imp,
    }
    json.dump(results, open(RESULTS_OUT,'w',encoding='utf-8'), ensure_ascii=False, indent=2)
    pickle.dump(model, open(MODEL_OUT,'wb'))
    print(f"\n✓ baseline_results.json  ✓ waf_model_baseline.pkl")

    # 9. Summary
    print("\n" + "=" * 65)
    print("TÓM TẮT — dán vào bảng luận văn")
    print("=" * 65)
    print(f"  Strategy   : Baseline — Direct Concat (4 datasets)")
    print(f"  Samples    : {len(merged):,}  (train {len(X_train):,} / test {len(X_test):,})")
    print(f"  F1-macro   : {overall.get('f1_macro',0):.4f}")
    print(f"  AUC-ROC    : {overall.get('auc_roc',0):.4f}")
    print(f"  Accuracy   : {overall.get('accuracy',0)*100:.2f}%")
    for src in ['csic', 'ecml', 'httpparam', 'biblio']:
        ps = per_source.get(src, {})
        print(f"  F1 [{src:10s}]: {ps.get('f1_macro', float('nan')):.4f}")
    print("=" * 65)


if __name__ == "__main__":
    main()
