# =============================================================================
# main.py
# Entry point — chạy toàn bộ pipeline: load → train → evaluate → lưu
# =============================================================================

from features.extractor import FeatureExtractor
from model.trainer import ModelTrainer

# --- Cấu hình đường dẫn ---
DATA_PATH    = 'csic_training_data.json'
# DATA_PATH    = 'csic_ecml_features.json'
# DATA_PATH    = 'ecml_final.json'
# DATA_PATH    = 'converted_httpparam_data.json'
# DATA_PATH    = 'csic+ecml+httparam.json'
# DATA_PATH    = 'biblio_sample.json'
MISSED_PATH  = 'missed_attacks.json'
FALSE_POS_PATH = 'false_positives.json'
MODEL_PATH   = 'waf_model_final_v6.pkl'


def main():
    # 1. Khởi tạo
    extractor = FeatureExtractor()
    trainer   = ModelTrainer(
        extractor    = extractor,
        n_estimators = 300,
        max_depth    = 30,
        test_size    = 0.2,
        random_state = 42,
    )

    # 2. Load dữ liệu
    trainer.load_data(DATA_PATH)

    # 3. Huấn luyện
    trainer.train()

    # 4. Đánh giá
    trainer.evaluate()

    # 5. Xuất tấn công bị bỏ lọt
    trainer.save_missed_attacks(MISSED_PATH)

    # 6. Xuất request bắt nhầm (False Positive)
    trainer.save_false_positives(FALSE_POS_PATH)

    # 7. Lưu model
    trainer.save_model(MODEL_PATH)


if __name__ == '__main__':
    main()