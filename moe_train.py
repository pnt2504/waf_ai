# =============================================================================
# moe_train.py
# Bước 3 — Mixture of Experts (MoE)
#
# Kiến trúc:
#   ┌─────────────────────────────────────────┐
#   │           HTTP Request đến              │
#   └────────────────┬────────────────────────┘
#                    ▼
#           ┌── Router (rule-based) ──┐
#           │  has_url OR has_headers │
#           └─────┬──────────┬────────┘
#                 │          │
#          Yes (Full)     No (Payload-only)
#                 ▼          ▼
#         Expert_Full   Expert_Payload
#       (CSIC + ECML)   (HTTPParam)
#
# Ý tưởng cốt lõi:
#   - Expert_Full được train KHÔNG có HTTPParam → tránh noise từ zero-features
#     → kỳ vọng cải thiện ECML (vốn bị kéo xuống bởi zero-feature HTTPParam)
#   - Expert_Payload được train chuyên biệt trên HTTPParam (payload-only)
#   - Router đơn giản: kiểm tra url và headers có thực sự rỗng không
#
# So sánh 4 chiến lược:
#   1. Baseline    : 1 model, 3 datasets, không xử lý
#   2. MFI-Mean    : 1 model, impute bằng global mean
#   3. MoE-Hard    : 2 experts + rule router (hard gate)
#   4. MoE-Soft    : 2 experts + weighted combination từ cả 2 expert
# =============================================================================

import json, os, pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score, f1_score
from sklearn.model_selection import train_test_split
from features.extractor import FeatureExtractor

BASE             = os.path.dirname(os.path.abspath(__file__))
RESULTS_OUT      = os.path.join(BASE, "moe_results.json")
ATTACK_THRESHOLD = 0.50
CLASS_WEIGHT     = {0: 1, 1: 2}
N_ESTIMATORS     = 300
MAX_DEPTH        = 30
TEST_SIZE        = 0.2
RANDOM_STATE     = 42


# ─────────────────────────────────────────────
# Load & normalize
# ─────────────────────────────────────────────

def load_all():
    def _j(f): return json.load(open(os.path.join(BASE, f), encoding='utf-8'))
    csic = _j('csic_training_data.json')
    ecml = _j('ecml_final.json')
    http = _j('httpparam_data.json')

    for r in csic: r.setdefault('http_version','HTTP/1.1'); r['source']='csic'
    for r in ecml: r['source']='ecml'

    lmap = {0:'normal', 1:'attack'}
    norm_http = []
    for r in http:
        p = str(r.get('payload',''))
        lid = int(r.get('label_id', 0))
        norm_http.append({
            'time':'2026-01-01T12:00:00+07:00','src_ip':'0.0.0.0',
            'http_version':'HTTP/1.1','method':r.get('method','POST'),
            'url':'','payload':p,'payload_length':str(len(p)),
            'headers':{'user_agent':'-','referer':'-','cookie':'-',
                       'content_type':'-','authorization':'-',
                       'x_forwarded_for':'-','host':'-','accept':'-'},
            'status':0,'label_id':lid,'label':lmap[lid],'source':'httpparam',
        })
    return csic + ecml + norm_http


# ─────────────────────────────────────────────
# Router
# ─────────────────────────────────────────────

def route(entry: dict) -> str:
    """
    Trả về 'full' nếu request có URL hoặc headers thực sự.
    Trả về 'payload' nếu chỉ có payload (HTTPParam-style).
    """
    has_url = bool(str(entry.get('url', '')).strip())
    headers = entry.get('headers', {})
    has_real_header = any(
        v not in ('-', '', None) for v in headers.values()
    )
    return 'full' if (has_url or has_real_header) else 'payload'


# ─────────────────────────────────────────────
# Train helper
# ─────────────────────────────────────────────

def train_rf(X, y, name=""):
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS, max_depth=MAX_DEPTH,
        random_state=RANDOM_STATE, class_weight=CLASS_WEIGHT, n_jobs=-1)
    model.fit(X, y)
    if name:
        print(f"  Trained {name} on {len(X):,} samples "
              f"(attack={y.sum():,} / normal={(y==0).sum():,})")
    return model


def evaluate_subset(name, y_true, y_pred, y_proba):
    if len(y_true) == 0:
        return {}
    acc    = accuracy_score(y_true, y_pred)
    f1     = f1_score(y_true, y_pred, average='macro', zero_division=0)
    try:   auc = roc_auc_score(y_true, y_proba)
    except: auc = float('nan')
    missed = int(((y_true==1) & (y_pred==0)).sum())
    total_atk = int((y_true==1).sum())
    fp     = int(((y_true==0) & (y_pred==1)).sum())
    print(f"  [{name:10s}]  F1={f1:.4f}  Acc={acc*100:.2f}%  AUC={auc:.4f}"
          f"  Missed={missed}/{total_atk}  FP={fp}")
    return {'f1_macro':f1,'accuracy':acc,'auc_roc':auc,
            'missed':missed,'total_attack':total_atk,'false_positive':fp}


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    print("=" * 65)
    print("BƯỚC 3 — MIXTURE OF EXPERTS (MoE)")
    print("=" * 65)

    # 1. Load & extract
    print("\n[1] Load và extract features...")
    extractor = FeatureExtractor()
    merged = load_all()
    X, y, sources, routes_all = [], [], [], []
    for r in merged:
        X.append(extractor.extract(r))
        y.append(int(r.get('label_id', 0)))
        sources.append(r['source'])
        routes_all.append(route(r))

    X          = np.array(X, dtype=np.float32)
    y          = np.array(y)
    sources    = np.array(sources)
    routes_all = np.array(routes_all)
    print(f"  Feature matrix: {X.shape}")
    print(f"  Router: full={( routes_all=='full').sum():,}  "
          f"payload={(routes_all=='payload').sum():,}")

    # 2. Split — same seed
    idx = np.arange(len(X))
    X_train, X_test, y_train, y_test, idx_tr, idx_te = train_test_split(
        X, y, idx, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y)
    src_train  = sources[idx_tr];    src_test  = sources[idx_te]
    route_train = routes_all[idx_tr]; route_test = routes_all[idx_te]
    print(f"  Train={len(X_train):,}  Test={len(X_test):,}")

    all_results = []

    # ══════════════════════════════════════════
    # Strategy 1 — Baseline (reference)
    # ══════════════════════════════════════════
    print(f"\n{'='*65}")
    print("  BASELINE — Direct Concat (reference)")
    print(f"{'='*65}")
    model_base = train_rf(X_train, y_train, "Baseline")
    proba_base = model_base.predict_proba(X_test)[:, 1]
    pred_base  = (proba_base >= ATTACK_THRESHOLD).astype(int)
    res_base = {'strategy': 'Baseline', 'overall': {}, 'per_source': {}}
    print(f"\n  [OVERALL]  "
          f"F1={f1_score(y_test,pred_base,average='macro'):.4f}  "
          f"Acc={accuracy_score(y_test,pred_base)*100:.2f}%  "
          f"AUC={roc_auc_score(y_test,proba_base):.4f}")
    res_base['overall'] = {
        'f1_macro': f1_score(y_test,pred_base,average='macro'),
        'accuracy': accuracy_score(y_test,pred_base),
        'auc_roc':  roc_auc_score(y_test,proba_base),
    }
    for src in ['csic','ecml','httpparam']:
        m = src_test==src
        res_base['per_source'][src] = evaluate_subset(
            src.upper(), y_test[m], pred_base[m], proba_base[m])
    all_results.append(res_base)

    # ══════════════════════════════════════════
    # Train 2 Expert models
    # ══════════════════════════════════════════
    print(f"\n{'='*65}")
    print("  TRAINING EXPERTS")
    print(f"{'='*65}")

    # Expert_Full: chỉ CSIC + ECML
    mask_full  = (src_train == 'csic') | (src_train == 'ecml')
    model_full = train_rf(X_train[mask_full], y_train[mask_full], "Expert_Full (CSIC+ECML)")

    # Expert_Payload: chỉ HTTPParam
    mask_pay   = src_train == 'httpparam'
    model_pay  = train_rf(X_train[mask_pay],  y_train[mask_pay],  "Expert_Payload (HTTPParam)")

    # ══════════════════════════════════════════
    # Strategy 2 — MoE-Hard (hard routing)
    # ══════════════════════════════════════════
    print(f"\n{'='*65}")
    print("  MOE-HARD — Rule Router (hard gate)")
    print(f"{'='*65}")

    proba_hard = np.zeros(len(X_test))
    mask_full_test = route_test == 'full'
    mask_pay_test  = route_test == 'payload'

    if mask_full_test.sum() > 0:
        proba_hard[mask_full_test] = \
            model_full.predict_proba(X_test[mask_full_test])[:, 1]
    if mask_pay_test.sum() > 0:
        proba_hard[mask_pay_test] = \
            model_pay.predict_proba(X_test[mask_pay_test])[:, 1]

    pred_hard = (proba_hard >= ATTACK_THRESHOLD).astype(int)

    res_hard = {'strategy': 'MoE-Hard', 'overall': {}, 'per_source': {}}
    f1_h  = f1_score(y_test, pred_hard, average='macro')
    acc_h = accuracy_score(y_test, pred_hard)
    auc_h = roc_auc_score(y_test, proba_hard)
    print(f"\n  [OVERALL]  F1={f1_h:.4f}  Acc={acc_h*100:.2f}%  AUC={auc_h:.4f}")
    print(classification_report(y_test, pred_hard,
                                target_names=['normal','attack'], zero_division=0))
    res_hard['overall'] = {'f1_macro':f1_h,'accuracy':acc_h,'auc_roc':auc_h}
    for src in ['csic','ecml','httpparam']:
        m = src_test==src
        res_hard['per_source'][src] = evaluate_subset(
            src.upper(), y_test[m], pred_hard[m], proba_hard[m])
    all_results.append(res_hard)

    # ══════════════════════════════════════════
    # Strategy 3 — MoE-Soft (weighted combination)
    # ══════════════════════════════════════════
    print(f"\n{'='*65}")
    print("  MOE-SOFT — Weighted combination (cả 2 experts)")
    print(f"{'='*65}")
    print("  Trọng số: full=0.7 / payload=0.3 cho 'full' requests")
    print("            full=0.2 / payload=0.8 cho 'payload' requests")

    proba_full_all = model_full.predict_proba(X_test)[:, 1]
    proba_pay_all  = model_pay.predict_proba(X_test)[:, 1]

    proba_soft = np.zeros(len(X_test))
    # Full requests: weighted 70% full + 30% payload
    proba_soft[mask_full_test] = (
        0.7 * proba_full_all[mask_full_test] +
        0.3 * proba_pay_all[mask_full_test]
    )
    # Payload-only requests: weighted 20% full + 80% payload
    proba_soft[mask_pay_test] = (
        0.2 * proba_full_all[mask_pay_test] +
        0.8 * proba_pay_all[mask_pay_test]
    )

    pred_soft = (proba_soft >= ATTACK_THRESHOLD).astype(int)

    res_soft = {'strategy': 'MoE-Soft', 'overall': {}, 'per_source': {}}
    f1_s  = f1_score(y_test, pred_soft, average='macro')
    acc_s = accuracy_score(y_test, pred_soft)
    auc_s = roc_auc_score(y_test, proba_soft)
    print(f"\n  [OVERALL]  F1={f1_s:.4f}  Acc={acc_s*100:.2f}%  AUC={auc_s:.4f}")
    print(classification_report(y_test, pred_soft,
                                target_names=['normal','attack'], zero_division=0))
    res_soft['overall'] = {'f1_macro':f1_s,'accuracy':acc_s,'auc_roc':auc_s}
    for src in ['csic','ecml','httpparam']:
        m = src_test==src
        res_soft['per_source'][src] = evaluate_subset(
            src.upper(), y_test[m], pred_soft[m], proba_soft[m])
    all_results.append(res_soft)

    # ══════════════════════════════════════════
    # Bảng so sánh tổng hợp
    # ══════════════════════════════════════════
    print(f"\n{'='*65}")
    print("BẢNG SO SÁNH TỔNG HỢP (4 chiến lược)")
    print(f"{'='*65}")
    print(f"{'Strategy':<22} {'F1-Overall':>10} {'AUC':>7} "
          f"{'F1-CSIC':>8} {'F1-ECML':>8} {'F1-HTTP':>8}")
    print("-" * 65)
    for r in all_results:
        ov = r['overall']
        ps = r['per_source']
        print(f"{r['strategy']:<22}"
              f"  {ov['f1_macro']:.4f}  "
              f"{ov['auc_roc']:.4f}  "
              f"{ps.get('csic',{}).get('f1_macro',0):.4f}  "
              f"{ps.get('ecml',{}).get('f1_macro',0):.4f}  "
              f"{ps.get('httpparam',{}).get('f1_macro',0):.4f}")

    print(f"\nMissed attacks ECML:")
    for r in all_results:
        e = r['per_source'].get('ecml',{})
        print(f"  {r['strategy']:<22}  missed={e.get('missed','?')}/{e.get('total_attack','?')}"
              f"  FP={e.get('false_positive','?')}")

    print(f"\nMissed attacks CSIC:")
    for r in all_results:
        c = r['per_source'].get('csic',{})
        print(f"  {r['strategy']:<22}  missed={c.get('missed','?')}/{c.get('total_attack','?')}"
              f"  FP={c.get('false_positive','?')}")

    # Cải thiện so với baseline
    base_ecml_missed = all_results[0]['per_source']['ecml']['missed']
    print(f"\n[Cải thiện ECML missed attacks so với Baseline={base_ecml_missed}]")
    for r in all_results[1:]:
        e = r['per_source'].get('ecml',{})
        m = e.get('missed', base_ecml_missed)
        delta = base_ecml_missed - m
        pct   = delta / base_ecml_missed * 100
        print(f"  {r['strategy']:<22}  -{delta} attacks ({pct:.1f}%)")

    # Lưu
    pickle.dump(model_full, open(os.path.join(BASE,'waf_model_expert_full.pkl'),'wb'))
    pickle.dump(model_pay,  open(os.path.join(BASE,'waf_model_expert_payload.pkl'),'wb'))
    json.dump(all_results, open(RESULTS_OUT,'w',encoding='utf-8'),
              ensure_ascii=False, indent=2, default=str)

    print(f"\n✓ moe_results.json")
    print(f"✓ waf_model_expert_full.pkl")
    print(f"✓ waf_model_expert_payload.pkl")
    print("=" * 65)


if __name__ == "__main__":
    main()
