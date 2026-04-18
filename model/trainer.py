# =============================================================================
# model/trainer.py
# Class ModelTrainer — load data, train, evaluate, lưu model và missed attacks
# =============================================================================

import json
import pickle

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from features.extractor import FeatureExtractor

# Ngưỡng xác suất để kết luận là tấn công.
# 0.50: accuracy 84.10%, missed 467, FP 293 (precision 88.5%, recall 82.8%)
# 0.40: bắt thêm attack hơn nhưng FP tăng đáng kể
ATTACK_THRESHOLD = 0.50

# Trọng số class khi train.
# {0:1, 1:2}: buộc model phạt nặng hơn khi bỏ lọt attack
CLASS_WEIGHT = {0: 1, 1: 2}


class ModelTrainer:
    """
    Quản lý toàn bộ vòng đời huấn luyện mô hình WAF:
        1. load_data()           → đọc JSON, trích xuất feature
        2. train()               → train RandomForestClassifier
        3. evaluate()            → in báo cáo, trả về dict kết quả
        4. save_missed_attacks() → xuất các tấn công bị bỏ lọt
        5. save_false_positives()→ xuất request normal bị bắt nhầm
        6. save_model()          → lưu model .pkl
    """

    def __init__(
        self,
        extractor: FeatureExtractor,
        n_estimators: int = 300,
        max_depth: int = 30,
        test_size: float = 0.2,
        random_state: int = 42,
    ):
        self.extractor     = extractor
        self.n_estimators  = n_estimators
        self.max_depth     = max_depth
        self.test_size     = test_size
        self.random_state  = random_state

        self.X:           np.ndarray | None = None
        self.y:           np.ndarray | None = None
        self.raw_entries: list              = []

        self.model:    RandomForestClassifier | None = None
        self.X_train:  np.ndarray | None = None
        self.X_test:   np.ndarray | None = None
        self.y_train:  np.ndarray | None = None
        self.y_test:   np.ndarray | None = None
        self.idx_test: np.ndarray | None = None
        self.y_pred:   np.ndarray | None = None

    # ------------------------------------------------------------------
    # 1. Load & trích xuất feature
    # ------------------------------------------------------------------

    def load_data(self, json_path: str) -> None:
        print(f"Đang đọc dữ liệu từ '{json_path}'...")
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        X, y, raw_entries = [], [], []
        for entry in data:
            features = self.extractor.extract(entry)
            X.append(features)
            y.append(self._get_label(entry))
            raw_entries.append(entry)

        self.X           = np.array(X)
        self.y           = np.array(y)
        self.raw_entries = raw_entries

        total   = len(self.y)
        attacks = int(self.y.sum())
        normals = total - attacks
        print(f"Đã load {total:,} records  |  attack: {attacks:,}  |  normal: {normals:,}")

    # ------------------------------------------------------------------
    # 2. Train
    # ------------------------------------------------------------------

    def train(self) -> None:
        self._check_data_loaded()

        indices = np.arange(len(self.X))
        (
            self.X_train, self.X_test,
            self.y_train, self.y_test,
            _,            self.idx_test,
        ) = train_test_split(
            self.X, self.y, indices,
            test_size    = self.test_size,
            random_state = self.random_state,
            stratify     = self.y,
        )

        print(
            f"\n--- HUẤN LUYỆN RANDOM FOREST  "
            f"(estimators={self.n_estimators}, max_depth={self.max_depth}) ---"
        )
        self.model = RandomForestClassifier(
            n_estimators = self.n_estimators,
            max_depth    = self.max_depth,
            random_state = self.random_state,
            class_weight = CLASS_WEIGHT,
        )
        self.model.fit(self.X_train, self.y_train)
        print("Huấn luyện hoàn tất.")

    # ------------------------------------------------------------------
    # 3. Evaluate
    # ------------------------------------------------------------------

    def evaluate(self) -> dict:
        self._check_trained()

        proba       = self.model.predict_proba(self.X_test)[:, 1]
        self.y_pred = (proba >= ATTACK_THRESHOLD).astype(int)
        acc         = accuracy_score(self.y_test, self.y_pred)

        print(f"\nRandom Forest Accuracy (threshold={ATTACK_THRESHOLD}): {acc * 100:.2f}%")
        print(classification_report(self.y_test, self.y_pred))

        return {
            'accuracy':  acc,
            'threshold': ATTACK_THRESHOLD,
            'report':    classification_report(self.y_test, self.y_pred, output_dict=True),
        }

    # ------------------------------------------------------------------
    # 4. Lưu tấn công bị bỏ lọt
    # ------------------------------------------------------------------

    def save_missed_attacks(self, output_path: str) -> int:
        self._check_trained()
        if self.y_pred is None:
            self.evaluate()

        missed        = []
        feature_names = self.extractor.feature_names

        for i in range(len(self.y_test)):
            if self.y_test[i] == 1 and self.y_pred[i] == 0:
                original_idx = self.idx_test[i]
                missed.append({
                    'raw_request':        self.raw_entries[original_idx],
                    'extracted_features': dict(
                        zip(feature_names, self.X_test[i].tolist())
                    ),
                })

        total_attacks = int((self.y_test == 1).sum())
        count         = len(missed)
        print(f"\nTổng tấn công bị bỏ lọt: {count} / {total_attacks}")

        if count > 0:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(missed, f, ensure_ascii=False, indent=4)
            print(f"Đã xuất file: '{output_path}'")

        return count

    # ------------------------------------------------------------------
    # 5. Lưu request bắt nhầm (False Positive)
    # ------------------------------------------------------------------

    def save_false_positives(self, output_path: str) -> int:
        self._check_trained()
        if self.y_pred is None:
            self.evaluate()

        false_positives = []
        feature_names   = self.extractor.feature_names

        for i in range(len(self.y_test)):
            if self.y_test[i] == 0 and self.y_pred[i] == 1:
                original_idx = self.idx_test[i]
                false_positives.append({
                    'raw_request':        self.raw_entries[original_idx],
                    'extracted_features': dict(
                        zip(feature_names, self.X_test[i].tolist())
                    ),
                })

        total_normals = int((self.y_test == 0).sum())
        count         = len(false_positives)
        print(f"Tổng request normal bị bắt nhầm: {count} / {total_normals}")

        if count > 0:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(false_positives, f, ensure_ascii=False, indent=4)
            print(f"Đã xuất file: '{output_path}'")

        return count

    # ------------------------------------------------------------------
    # 6. Lưu model
    # ------------------------------------------------------------------

    def save_model(self, model_path: str) -> None:
        self._check_trained()
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"Đã lưu model: '{model_path}'")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_label(entry: dict) -> int:
        if 'label_id' in entry:
            return int(entry['label_id'])
        if 'classification' in entry:
            return int(entry['classification'])
        return 0

    def _check_data_loaded(self) -> None:
        if self.X is None or self.y is None:
            raise RuntimeError("Chưa load dữ liệu. Gọi load_data() trước.")

    def _check_trained(self) -> None:
        self._check_data_loaded()
        if self.model is None:
            raise RuntimeError("Model chưa được train. Gọi train() trước.")
