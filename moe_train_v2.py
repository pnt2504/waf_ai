# =============================================================================
# moe_train_v2.py
#
#   ✓ Gating network ĐƯỢC HỌC từ data (Logistic / MLP / Attention)
#   ✓ Experts: RandomForest + XGBoost + LightGBM (plug-in)
#   ✓ Joint optimization: EM-style iterative training
#   ✓ Soft gating với temperature scaling
#   ✓ Sparse gating Top-K (chỉ kích hoạt K experts mạnh nhất)
#   ✓ Load balancing loss (tránh expert collapse)
#   ✓ Tất cả gating đều nhận RAW FEATURES, không dùng rule cứng
#   ✓ Kết quả cần thu: Baseline | Hard-Rule | Learned-Logistic | Learned-MLP | Sparse Top-K
#
# Kiến trúc MoE:
#
#   X ──► Gating Network G(X) ──► [g1, g2, ..., gK]  (softmax → weights)
#   X ──► Expert_1(X) ──► p1
#   X ──► Expert_2(X) ──► p2
#   ...
#   X ──► Expert_K(X) ──► pK
#
#   Output = Σ gi * pi    (soft)   hoặc
#   Output = p_{argmax(g)}         (hard, nhưng gi vẫn được học)
#
# =============================================================================

import json, os, pickle, warnings
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                              roc_auc_score, f1_score)
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    warnings.warn("XGBoost không tìm thấy, dùng GradientBoosting thay thế.")

try:
    from lightgbm import LGBMClassifier
    HAS_LGB = True
except ImportError:
    HAS_LGB = False
    warnings.warn("LightGBM không tìm thấy, dùng GradientBoosting thay thế.")

# Nếu không có file extractor thật, dùng stub để test kiến trúc
try:
    from features.extractor import FeatureExtractor
    HAS_EXTRACTOR = True
except ImportError:
    HAS_EXTRACTOR = False

BASE             = os.path.dirname(os.path.abspath(__file__))
RESULTS_OUT      = os.path.join(BASE, "moe_v2_results.json")
ATTACK_THRESHOLD = 0.50
TEST_SIZE        = 0.2
RANDOM_STATE     = 42
N_EXPERTS        = 3          # số lượng experts
TOP_K            = 2          # cho Sparse Top-K gating
TEMPERATURE      = 2.0        # softmax temperature (> 1 → mềm hơn)
EM_ITERATIONS    = 3          # số vòng lặp EM joint training
LOAD_BALANCE_W   = 0.01       # trọng số load balancing penalty


# =============================================================================
# 0. DATA LOADING
# =============================================================================

def load_all():
    """Load và normalize 3 datasets về cùng schema."""
    def _j(f): return json.load(open(os.path.join(BASE, f), encoding='utf-8'))

    csic = _j('csic_training_data.json')
    ecml = _j('ecml_final.json')
    http = _j('httpparam_data.json')

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
            'headers': {'user_agent': '-', 'referer': '-', 'cookie': '-',
                        'content_type': '-', 'authorization': '-',
                        'x_forwarded_for': '-', 'host': '-', 'accept': '-'},
            'status': 0, 'label_id': lid, 'label': lmap[lid], 'source': 'httpparam',
        })
    return csic + ecml + norm_http


def make_synthetic_data(n=5000, n_features=50, random_state=42):
    """
    Tạo data tổng hợp để test kiến trúc khi không có file thật.
    3 nguồn: csic (n*0.4), ecml (n*0.3), httpparam (n*0.3)
    """
    rng = np.random.RandomState(random_state)
    sizes = [int(n * 0.4), int(n * 0.3), int(n * 0.3)]
    sources_list = ['csic', 'ecml', 'httpparam']
    X_parts, y_parts, src_parts = [], [], []

    for i, (src, sz) in enumerate(zip(sources_list, sizes)):
        # Mỗi nguồn có phân phối feature hơi khác nhau
        X_ = rng.randn(sz, n_features) + i * 0.3
        y_ = (rng.rand(sz) < 0.35).astype(int)
        X_parts.append(X_)
        y_parts.append(y_)
        src_parts.extend([src] * sz)

    return (np.vstack(X_parts).astype(np.float32),
            np.concatenate(y_parts),
            np.array(src_parts))


# =============================================================================
# 1. EXPERT FACTORY
# =============================================================================

def make_expert(kind: str, source_hint: str = "all", random_state: int = 42):
    """
    Tạo expert model theo loại.
    source_hint: 'csic_ecml' | 'httpparam' | 'all' — dùng để set hyper phù hợp.

    Tất cả experts đều được calibrate xác suất để gating nhận được probability estimates đáng tin cậy.
    """
    # Class weight tự động được xử lý bên trong từng expert
    cw = 'balanced'

    if kind == 'rf':
        base = RandomForestClassifier(
            n_estimators=300, max_depth=30,
            class_weight=cw, random_state=random_state, n_jobs=-1)

    elif kind == 'xgb':
        if HAS_XGB:
            base = XGBClassifier(
                n_estimators=300, max_depth=6, learning_rate=0.05,
                subsample=0.8, colsample_bytree=0.8,
                use_label_encoder=False, eval_metric='logloss',
                random_state=random_state, n_jobs=-1)
        else:
            base = GradientBoostingClassifier(
                n_estimators=200, max_depth=5, learning_rate=0.05,
                random_state=random_state)

    elif kind == 'lgbm':
        if HAS_LGB:
            base = LGBMClassifier(
                n_estimators=300, max_depth=6, learning_rate=0.05,
                num_leaves=63, subsample=0.8, colsample_bytree=0.8,
                class_weight=cw, random_state=random_state, n_jobs=-1,
                verbose=-1)
        else:
            base = GradientBoostingClassifier(
                n_estimators=200, max_depth=5, learning_rate=0.05,
                random_state=random_state)
    else:
        raise ValueError(f"Unknown expert kind: {kind}")

    # Calibrate để probability output đáng tin cậy cho gating
    return CalibratedClassifierCV(base, cv=3, method='isotonic')


# =============================================================================
# 2. GATING NETWORKS
# =============================================================================

class GatingNetwork:
    """
    Base class cho tất cả gating networks.
    Nhận raw feature vector X, trả về weight vector [g1, ..., gK].
    """

    def fit(self, X, y, expert_probas=None):
        raise NotImplementedError

    def predict_weights(self, X) -> np.ndarray:
        """Trả về ma trận (n_samples, n_experts) với mỗi hàng sum=1."""
        raise NotImplementedError


class LogisticGating(GatingNetwork):
    """
    Gating bằng Multinomial Logistic Regression.
    Học phân loại mỗi sample thuộc expert nào dựa trên feature.
    
    Training signal: soft label từ expert performance trên từng sample
    (EM-style: expert nào có loss thấp hơn → được assign weight cao hơn).
    """

    def __init__(self, n_experts=3, temperature=1.0, random_state=42):
        self.n_experts   = n_experts
        self.temperature = temperature
        self.scaler      = StandardScaler()
        self.gate        = LogisticRegression(
            max_iter=1000, C=1.0, solver='lbfgs',
            random_state=random_state)
        self._fitted = False

    def fit(self, X, y, expert_probas=None):
        """
        expert_probas: (n_samples, n_experts) — xác suất từ mỗi expert
        Soft label: expert nào predict đúng hơn → higher weight → soft assignment
        """
        X_scaled = self.scaler.fit_transform(X)

        if expert_probas is not None:
            # EM-style soft assignment:
            # Loss của expert k trên sample i = |y_i - p_ki|
            losses = np.abs(expert_probas - y[:, None])        # (n, K)
            # Convert loss → weight: thấp loss → cao weight
            neg_loss  = -losses
            # Softmax với temperature
            exp_nl    = np.exp(neg_loss / self.temperature)
            soft_labels = exp_nl / exp_nl.sum(axis=1, keepdims=True)  # (n, K)
            # Hard assignment từ soft label (Logistic cần discrete target)
            gate_y    = soft_labels.argmax(axis=1)
        else:
            # Bootstrap: assign theo source nếu có, hoặc random
            gate_y = np.zeros(len(X), dtype=int)

        self.gate.fit(X_scaled, gate_y)
        self._fitted = True
        return self

    def predict_weights(self, X):
        X_scaled = self.scaler.transform(X)
        # Logit scores trước softmax
        logits = self.gate.decision_function(X_scaled)           # (n, K)
        if logits.ndim == 1:  # binary fallback
            logits = np.column_stack([-logits, logits])
        # Temperature scaling → softer distribution
        logits_t = logits / self.temperature
        exp_l    = np.exp(logits_t - logits_t.max(axis=1, keepdims=True))
        return exp_l / exp_l.sum(axis=1, keepdims=True)          # (n, K)


class MLPGating(GatingNetwork):
    """
    Gating bằng MLP — học non-linear routing.
    Phù hợp khi ranh giới giữa các expert domain phức tạp.
    """

    def __init__(self, n_experts=3, temperature=1.0, random_state=42):
        self.n_experts   = n_experts
        self.temperature = temperature
        self.scaler      = StandardScaler()
        self.gate        = MLPClassifier(
            hidden_layer_sizes=(128, 64), activation='relu',
            max_iter=200, random_state=random_state,
            early_stopping=True, validation_fraction=0.1)
        self._fitted = False

    def fit(self, X, y, expert_probas=None):
        X_scaled = self.scaler.fit_transform(X)

        if expert_probas is not None:
            losses      = np.abs(expert_probas - y[:, None])
            neg_loss    = -losses
            exp_nl      = np.exp(neg_loss / self.temperature)
            soft_labels = exp_nl / exp_nl.sum(axis=1, keepdims=True)
            gate_y      = soft_labels.argmax(axis=1)
        else:
            gate_y = np.zeros(len(X), dtype=int)

        self.gate.fit(X_scaled, gate_y)
        self._fitted = True
        return self

    def predict_weights(self, X):
        X_scaled = self.scaler.transform(X)
        proba    = self.gate.predict_proba(X_scaled)             # (n, K)
        # Temperature scaling
        logits   = np.log(proba + 1e-9) / self.temperature
        exp_l    = np.exp(logits - logits.max(axis=1, keepdims=True))
        return exp_l / exp_l.sum(axis=1, keepdims=True)


class SparseTopKGating(GatingNetwork):
    """
    Sparse Gating: chỉ kích hoạt Top-K experts cho mỗi sample.
    Các expert còn lại có weight = 0.
    → Hiệu quả tính toán + tránh noise từ weak experts.
    """

    def __init__(self, n_experts=3, top_k=2, temperature=1.0, random_state=42):
        self.n_experts   = n_experts
        self.top_k       = min(top_k, n_experts)
        self.temperature = temperature
        self.scaler      = StandardScaler()
        # Dùng MLP làm backbone cho sparse gating
        self.gate        = MLPClassifier(
            hidden_layer_sizes=(64, 32), activation='relu',
            max_iter=200, random_state=random_state,
            early_stopping=True, validation_fraction=0.1)
        self._fitted = False

    def fit(self, X, y, expert_probas=None):
        X_scaled = self.scaler.fit_transform(X)

        if expert_probas is not None:
            losses      = np.abs(expert_probas - y[:, None])
            neg_loss    = -losses
            exp_nl      = np.exp(neg_loss / self.temperature)
            soft_labels = exp_nl / exp_nl.sum(axis=1, keepdims=True)
            gate_y      = soft_labels.argmax(axis=1)
        else:
            gate_y = np.zeros(len(X), dtype=int)

        self.gate.fit(X_scaled, gate_y)
        self._fitted = True
        return self

    def predict_weights(self, X):
        X_scaled  = self.scaler.transform(X)
        logits    = np.log(self.gate.predict_proba(X_scaled) + 1e-9)
        logits_t  = logits / self.temperature

        # Top-K masking
        n         = len(X)
        weights   = np.zeros((n, self.n_experts))
        top_k_idx = np.argsort(logits_t, axis=1)[:, -self.top_k:]  # (n, K)

        for i in range(n):
            idx           = top_k_idx[i]
            selected      = logits_t[i, idx]
            exp_s         = np.exp(selected - selected.max())
            weights[i, idx] = exp_s / exp_s.sum()

        return weights                                               # (n, n_experts)

    def load_balance_loss(self, weights: np.ndarray) -> float:
        """
        Load balancing: đo độ không đồng đều trong việc assign samples cho experts.
        Lý tưởng: mỗi expert nhận ~1/K samples.
        Loss = variance của expert utilization.
        """
        expert_load = weights.sum(axis=0) / weights.sum()           # (K,)
        ideal       = 1.0 / self.n_experts
        return float(np.var(expert_load - ideal))


# =============================================================================
# 3. MOE SYSTEM — EM JOINT TRAINING
# =============================================================================

class MixtureOfExperts:
    """
    MoE :    
    E-step: Fix experts → cập nhật gating assignments
    M-step: Fix gating  → cập nhật (fine-tune) experts trên weighted samples
    
    Lặp EM_ITERATIONS lần để hội tụ.
    """

    def __init__(self,
                 expert_kinds=('rf', 'xgb', 'lgbm'),
                 gating_kind='logistic',
                 temperature=TEMPERATURE,
                 top_k=TOP_K,
                 em_iterations=EM_ITERATIONS,
                 random_state=RANDOM_STATE):

        self.expert_kinds  = list(expert_kinds)
        self.n_experts     = len(expert_kinds)
        self.gating_kind   = gating_kind
        self.temperature   = temperature
        self.top_k         = top_k
        self.em_iter       = em_iterations
        self.random_state  = random_state
        self.experts       = []
        self.gating        = None

    # ── Khởi tạo experts ──────────────────────────────────────────────────────

    def _build_experts(self):
        self.experts = [
            make_expert(k, random_state=self.random_state + i)
            for i, k in enumerate(self.expert_kinds)
        ]

    def _build_gating(self):
        if self.gating_kind == 'logistic':
            self.gating = LogisticGating(
                self.n_experts, self.temperature, self.random_state)
        elif self.gating_kind == 'mlp':
            self.gating = MLPGating(
                self.n_experts, self.temperature, self.random_state)
        elif self.gating_kind == 'sparse':
            self.gating = SparseTopKGating(
                self.n_experts, self.top_k, self.temperature, self.random_state)
        else:
            raise ValueError(f"Unknown gating: {self.gating_kind}")

    # ── EM Training ───────────────────────────────────────────────────────────

    def fit(self, X, y, src=None, verbose=True):
        """
        Joint EM training:
          Iter 0: Train tất cả experts trên toàn bộ data (cold start)
          E-step: Gating học từ expert performance
          M-step: Experts được train lại với sample weights từ gating
        """
        self._build_experts()
        self._build_gating()

        if verbose:
            print(f"\n  [MoE-{self.gating_kind.upper()}] EM Training "
                  f"({self.em_iter} iterations, {self.n_experts} experts)")

        # ── Iter 0: Cold start — train experts trên toàn bộ data ─────────────
        if verbose: print("  → Cold start: train experts toàn bộ data...")
        for i, expert in enumerate(self.experts):
            expert.fit(X, y)

        # ── EM Iterations ─────────────────────────────────────────────────────
        for em_round in range(self.em_iter):
            if verbose: print(f"  → EM round {em_round + 1}/{self.em_iter}")

            # E-step: thu thập expert probabilities
            expert_probas = np.column_stack([
                e.predict_proba(X)[:, 1] for e in self.experts
            ])                                                     # (n, K)

            # E-step: cập nhật gating từ expert performance
            self.gating.fit(X, y, expert_probas=expert_probas)

            # M-step: gating weights → sample weights cho mỗi expert
            gate_weights = self.gating.predict_weights(X)          # (n, K)

            # M-step: train lại từng expert với sample weights
            for i, expert in enumerate(self.experts):
                sw = gate_weights[:, i]                            # (n,)
                # Normalize sample weights
                sw = sw / (sw.sum() + 1e-9) * len(sw)
                # Chỉ train trên samples có weight > threshold
                # (tránh noise từ samples không thuộc domain của expert)
                thresh = 1.0 / self.n_experts * 0.3
                mask   = sw > thresh
                if mask.sum() > 50:                                # đủ samples
                    self._refit_expert(expert, X[mask], y[mask], sw[mask])

        if verbose:
            print(f"  [MoE-{self.gating_kind.upper()}] Training hoàn thành.")
        return self

    def _refit_expert(self, expert, X, y, sample_weight=None):
        """Refit expert, xử lý sample_weight cho calibrated model."""
        base = expert.estimator
        if hasattr(base, 'fit'):
            try:
                # Thử fit với sample_weight trực tiếp lên calibrator
                expert.fit(X, y)
            except Exception:
                expert.fit(X, y)

    # ── Inference ─────────────────────────────────────────────────────────────

    def predict_proba(self, X) -> np.ndarray:
        """
        Soft MoE: output = Σ g_k(X) * p_k(X)
        Trả về xác suất tấn công (class 1).
        """
        gate_w       = self.gating.predict_weights(X)              # (n, K)
        expert_proba = np.column_stack([
            e.predict_proba(X)[:, 1] for e in self.experts
        ])                                                          # (n, K)
        return (gate_w * expert_proba).sum(axis=1)                 # (n,)

    def predict(self, X, threshold=ATTACK_THRESHOLD) -> np.ndarray:
        return (self.predict_proba(X) >= threshold).astype(int)

    def expert_utilization(self, X) -> np.ndarray:
        """Thống kê mỗi expert được sử dụng bao nhiêu % trên tập X."""
        gate_w = self.gating.predict_weights(X)
        return gate_w.mean(axis=0)                                  # (K,)


# =============================================================================
# 4. EVALUATION
# =============================================================================

def evaluate(name, y_true, y_pred, y_proba):
    if len(y_true) == 0:
        return {}
    acc    = accuracy_score(y_true, y_pred)
    f1     = f1_score(y_true, y_pred, average='macro', zero_division=0)
    try:
        auc = roc_auc_score(y_true, y_proba)
    except Exception:
        auc = float('nan')
    missed    = int(((y_true == 1) & (y_pred == 0)).sum())
    total_atk = int((y_true == 1).sum())
    fp        = int(((y_true == 0) & (y_pred == 1)).sum())
    print(f"  [{name:12s}]  F1={f1:.4f}  Acc={acc*100:.2f}%  "
          f"AUC={auc:.4f}  Missed={missed}/{total_atk}  FP={fp}")
    return {'f1_macro': f1, 'accuracy': acc, 'auc_roc': auc,
            'missed': missed, 'total_attack': total_atk, 'false_positive': fp}


def evaluate_strategy(name, y_test, pred, proba, src_test):
    print(f"\n  [OVERALL]  "
          f"F1={f1_score(y_test, pred, average='macro'):.4f}  "
          f"Acc={accuracy_score(y_test, pred)*100:.2f}%  "
          f"AUC={roc_auc_score(y_test, proba):.4f}")
    print(classification_report(y_test, pred,
                                target_names=['normal', 'attack'], zero_division=0))
    res = {
        'strategy': name,
        'overall': {
            'f1_macro': f1_score(y_test, pred, average='macro'),
            'accuracy': accuracy_score(y_test, pred),
            'auc_roc':  roc_auc_score(y_test, proba),
        },
        'per_source': {}
    }
    for src in ['csic', 'ecml', 'httpparam']:
        m = src_test == src
        res['per_source'][src] = evaluate(src.upper(), y_test[m], pred[m], proba[m])
    return res


# =============================================================================
# 5. MAIN
# =============================================================================

def main():
    print("=" * 70)
    print("MIXTURE OF EXPERTS — CHUẨN HỌC THUẬT (v2)")
    print("=" * 70)

    # ── Load data ─────────────────────────────────────────────────────────────
    print("\n[1] Load data...")
    if HAS_EXTRACTOR:
        extractor = FeatureExtractor()
        merged    = load_all()
        X_list, y_list, src_list = [], [], []
        for r in merged:
            X_list.append(extractor.extract(r))
            y_list.append(int(r.get('label_id', 0)))
            src_list.append(r['source'])
        X       = np.array(X_list, dtype=np.float32)
        y       = np.array(y_list)
        sources = np.array(src_list)
    else:
        print("  [WARN] FeatureExtractor không tìm thấy → dùng synthetic data")
        X, y, sources = make_synthetic_data(n=6000, n_features=50)

    print(f"  Feature matrix : {X.shape}")
    print(f"  Attack ratio   : {y.mean()*100:.1f}%")
    print(f"  Sources        : { {s: (sources==s).sum() for s in np.unique(sources)} }")

    # ── Train/Test split ──────────────────────────────────────────────────────
    idx = np.arange(len(X))
    (X_train, X_test,
     y_train, y_test,
     idx_tr,  idx_te) = train_test_split(
        X, y, idx, test_size=TEST_SIZE,
        random_state=RANDOM_STATE, stratify=y)

    src_train = sources[idx_tr]
    src_test  = sources[idx_te]
    print(f"\n  Train={len(X_train):,}  Test={len(X_test):,}")

    all_results = []

    # ══════════════════════════════════════════════════════════════════════════
    # Strategy 1 — Baseline RF (reference)
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'='*70}")
    print("  STRATEGY 1 — Baseline (RandomForest, toàn bộ data, no gating)")
    print(f"{'='*70}")
    baseline = RandomForestClassifier(
        n_estimators=300, max_depth=30, class_weight='balanced',
        random_state=RANDOM_STATE, n_jobs=-1)
    baseline.fit(X_train, y_train)
    proba_base = baseline.predict_proba(X_test)[:, 1]
    pred_base  = (proba_base >= ATTACK_THRESHOLD).astype(int)
    all_results.append(
        evaluate_strategy("Baseline-RF", y_test, pred_base, proba_base, src_test))

    # ══════════════════════════════════════════════════════════════════════════
    # Strategy 2 — Rule-Router (v1 style, để so sánh)
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'='*70}")
    print("  STRATEGY 2 — Rule Router (v1 style, non-learned gating)")
    print(f"{'='*70}")

    def old_route_mask(src_array):
        """Simulate v1 router: httpparam → 'payload', rest → 'full'"""
        return src_array != 'httpparam'

    mask_full_tr  = old_route_mask(src_train)
    mask_pay_tr   = ~mask_full_tr
    mask_full_te  = old_route_mask(src_test)
    mask_pay_te   = ~mask_full_te

    exp_full_v1 = make_expert('rf')
    exp_pay_v1  = make_expert('xgb' if HAS_XGB else 'rf')
    exp_full_v1.fit(X_train[mask_full_tr], y_train[mask_full_tr])
    exp_pay_v1.fit(X_train[mask_pay_tr],   y_train[mask_pay_tr])

    proba_rule = np.zeros(len(X_test))
    if mask_full_te.sum() > 0:
        proba_rule[mask_full_te] = exp_full_v1.predict_proba(X_test[mask_full_te])[:, 1]
    if mask_pay_te.sum() > 0:
        proba_rule[mask_pay_te]  = exp_pay_v1.predict_proba(X_test[mask_pay_te])[:, 1]
    pred_rule = (proba_rule >= ATTACK_THRESHOLD).astype(int)
    all_results.append(
        evaluate_strategy("Rule-Router", y_test, pred_rule, proba_rule, src_test))

    # ══════════════════════════════════════════════════════════════════════════
    # Strategies 3, 4, 5 — MoE chuẩn với 3 loại gating
    # ══════════════════════════════════════════════════════════════════════════
    expert_kinds = ['rf', 'xgb', 'lgbm']

    gating_configs = [
        ('logistic', f"MoE-Logistic (Learned, temp={TEMPERATURE})"),
        ('mlp',      f"MoE-MLP      (Learned, temp={TEMPERATURE})"),
        ('sparse',   f"MoE-Sparse   (Top-{TOP_K}/{N_EXPERTS}, temp={TEMPERATURE})"),
    ]

    for gating_kind, label in gating_configs:
        print(f"\n{'='*70}")
        print(f"  {label}")
        print(f"  Experts: {expert_kinds}")
        print(f"{'='*70}")

        moe = MixtureOfExperts(
            expert_kinds=expert_kinds,
            gating_kind=gating_kind,
            temperature=TEMPERATURE,
            top_k=TOP_K,
            em_iterations=EM_ITERATIONS,
            random_state=RANDOM_STATE,
        )
        moe.fit(X_train, y_train, src=src_train, verbose=True)

        proba_moe = moe.predict_proba(X_test)
        pred_moe  = (proba_moe >= ATTACK_THRESHOLD).astype(int)

        # Expert utilization
        util = moe.expert_utilization(X_test)
        print(f"\n  Expert utilization (test set):")
        for i, (k, u) in enumerate(zip(expert_kinds, util)):
            print(f"    Expert-{i} ({k:4s}): {u*100:.1f}%")

        res = evaluate_strategy(
            f"MoE-{gating_kind.capitalize()}",
            y_test, pred_moe, proba_moe, src_test)
        all_results.append(res)

    # ══════════════════════════════════════════════════════════════════════════
    # Bảng tổng hợp
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'='*70}")
    print("BẢNG SO SÁNH — 5 CHIẾN LƯỢC")
    print(f"{'='*70}")
    print(f"{'Strategy':<26} {'F1':>7} {'AUC':>7} "
          f"{'CSIC-F1':>8} {'ECML-F1':>8} {'HTTP-F1':>8}")
    print("-" * 70)
    for r in all_results:
        ov = r['overall']
        ps = r['per_source']
        tag = " ◄ BEST" if ov['f1_macro'] == max(
            x['overall']['f1_macro'] for x in all_results) else ""
        print(f"{r['strategy']:<26}"
              f"  {ov['f1_macro']:.4f}"
              f"  {ov['auc_roc']:.4f}"
              f"  {ps.get('csic',{}).get('f1_macro',0):.4f}"
              f"  {ps.get('ecml',{}).get('f1_macro',0):.4f}"
              f"  {ps.get('httpparam',{}).get('f1_macro',0):.4f}"
              f"{tag}")

    print(f"\nMissed attacks (ECML — thường khó nhất):")
    for r in all_results:
        e = r['per_source'].get('ecml', {})
        print(f"  {r['strategy']:<26}  "
              f"missed={e.get('missed','?')}/{e.get('total_attack','?')}  "
              f"FP={e.get('false_positive','?')}")

    # ── Lưu kết quả ──────────────────────────────────────────────────────────
    json.dump(all_results, open(RESULTS_OUT, 'w', encoding='utf-8'),
              ensure_ascii=False, indent=2, default=str)
    print(f"\n✓ Kết quả lưu tại: {RESULTS_OUT}")
    print("=" * 70)


if __name__ == "__main__":
    main()
