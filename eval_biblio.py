import json, pickle, sys, warnings, numpy as np
warnings.filterwarnings('ignore')

BASE = r'D:\Project 3\Code xử lí'
sys.path.insert(0, BASE)

from features.extractor import FeatureExtractor
from sklearn.metrics import (classification_report, confusion_matrix,
                             roc_auc_score, f1_score, accuracy_score)

print("Loading Biblio data...")
with open(BASE + r'\biblio_training_data.json') as f:
    data = json.load(f)

n_normal = sum(1 for d in data if d['label'] == 'normal')
n_attack = sum(1 for d in data if d['label'] == 'attack')
print(f"Biblio: {len(data)} records  |  normal={n_normal}  attack={n_attack}")

ext  = FeatureExtractor()
print("Extracting features (may take ~30s)...")
X    = np.array([ext.extract(d) for d in data], dtype=float)
y    = np.array([1 if d['label'] == 'attack' else 0 for d in data])
feat = ext.feature_names

# ── Feature-level insight ──────────────────────────────────────────────────
print("\n=== Features khác biệt rõ nhất (attack vs normal) ===")
diffs = [(feat[i], X[y==0,i].mean(), X[y==1,i].mean()) for i in range(len(feat))]
diffs.sort(key=lambda t: abs(t[2]-t[1]), reverse=True)
for name, mn, ma in diffs[:10]:
    print(f"  {name:<30} normal={mn:>9.3f}  attack={ma:>9.3f}  Δ={ma-mn:>+9.3f}")

# ── Model comparison ───────────────────────────────────────────────────────
models = [
    ('waf_model_baseline.pkl',    'Baseline-RF'),
    ('waf_model_final_v6.pkl',    'Final-v6-RF'),
    ('waf_model_xgboost_v2.pkl',  'XGBoost-v2'),
    ('waf_model_moe_v2_best.pkl', 'MoE-v2-Sparse'),
]

print(f"\n{'Model':<22} {'F1-macro':>8} {'AUC':>7} {'Acc':>8}  {'Missed':>12}  {'FP':>6}")
print("-" * 72)
best_result = None
for fname, name in models:
    try:
        with open(BASE + '\\' + fname, 'rb') as f:
            model = pickle.load(f)
        proba  = model.predict_proba(X)[:, 1]
        y_pred = (proba >= 0.5).astype(int)
        f1  = f1_score(y, y_pred, average='macro')
        auc = roc_auc_score(y, proba)
        acc = accuracy_score(y, y_pred)
        cm  = confusion_matrix(y, y_pred)
        tn, fp, fn, tp = cm.ravel()
        print(f"{name:<22} {f1:>8.4f} {auc:>7.4f} {acc*100:>7.2f}%  "
              f"{fn:>5}/{(y==1).sum()}  {fp:>6}")
        if best_result is None or f1 > best_result[0]:
            best_result = (f1, name, y_pred, proba, cm)
    except Exception as e:
        print(f"{name:<22} ERROR: {e}")

# ── Detail cho model tốt nhất ─────────────────────────────────────────────
print()
f1b, nb, yp, pr, cm = best_result
tn, fp, fn, tp = cm.ravel()
print(f"=== Chi tiết: {nb} ===")
print(classification_report(y, yp, target_names=['normal', 'attack']))
print(f"Confusion matrix:  TN={tn}  FP={fp}  FN={fn}  TP={tp}")
print(f"Recall attack : {tp/(tp+fn)*100:.2f}%  (bỏ lọt {fn}/{(y==1).sum()} attacks)")
print(f"Precision     : {tp/(tp+fp)*100:.2f}%  ({fp} false positives / {(y==0).sum()} normal)")

# ── Phân tích attacks bị bỏ lọt ──────────────────────────────────────────
missed_idx = np.argsort(pr * (y == 1) + (y == 0))  # low prob attacks first
missed_idx = [i for i in missed_idx if y[i] == 1 and yp[i] == 0][:8]

print(f"\n=== {len(missed_idx)} attacks bị bỏ lọt (p thấp nhất) ===")
for idx in missed_idx:
    d = data[idx]
    p = pr[idx]
    fv = ext.extract(d)
    active = {feat[i]: round(fv[i], 2) for i in range(len(feat)) if fv[i] != 0}
    print(f"  url : {d['url'][:80]}")
    print(f"  p   : {p:.4f}  |  feats≠0: {active}")
    print()
