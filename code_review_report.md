# Báo cáo review source code đồ án WAF dùng Machine Learning và Mixture of Experts

> Đề tài: **“Nghiên cứu và xây dựng hệ thống Web Application Firewall sử dụng Machine Learning và kiến trúc Mixture of Experts để phát hiện tấn công ứng dụng web”.**
>
> Phạm vi review: các file source code/config/script trực tiếp liên quan đến xử lý dữ liệu, trích xuất đặc trưng, huấn luyện, đánh giá, MoE, API WAF và demo Nginx. Không review nội dung chi tiết của các file `.pkl`, dataset JSON lớn, `.docx`, `.pptx`, `.pdf` vì đây không phải source code thực thi. Không thấy `README.md` ở root project tại thời điểm đọc code.

---

## 1. Tóm tắt ngắn gọn project

Project là một hệ thống kết hợp nhiều phần:

1. **Xử lý và chuẩn hóa dữ liệu HTTP request** từ nhiều nguồn dataset như CSIC, ECML, HTTPParam, Biblio-US17.
2. **Trích xuất đặc trưng bảo mật** từ URL, method, query string, payload/body và headers.
3. **Huấn luyện mô hình Machine Learning** như Random Forest, XGBoost/LightGBM fallback, Logistic Regression, MLP.
4. **Thử nghiệm Missing Feature Imputation (MFI)** để xử lý trường hợp dataset thiếu URL/header.
5. **Xây dựng Mixture of Experts (MoE)** gồm nhiều expert model và gating network để kết hợp kết quả.
6. **Demo WAF thực tế** bằng FastAPI server và Nginx `auth_request`: request đi qua Nginx, được WAF model kiểm tra, rồi cho qua hoặc chặn.
7. **Đánh giá mô hình** bằng Accuracy, F1-macro, AUC, confusion matrix, missed attacks, false positives và benchmark latency.

---

## 2. Cấu trúc thư mục/file chính

| Đường dẫn | Vai trò |
|---|---|
| `config/keywords.py` | Khai báo từ khóa tấn công, extension nguy hiểm, trọng số feature. |
| `features/helpers.py` | Các hàm tiện ích: entropy, đếm keyword, điểm bất thường header, kiểm tra extension/file upload. |
| `features/extractor.py` | Module quan trọng nhất để chuyển một HTTP request thành vector đặc trưng số. |
| `model/trainer.py` | Class `ModelTrainer` cho pipeline Random Forest cơ bản: load data, train, evaluate, lưu model. |
| `main.py` | Entry point cũ/đơn giản: dùng `ModelTrainer` train trên một file dataset. |
| `merge_datasets.py` | Script chuẩn hóa và gộp CSIC + ECML + HTTPParam thành dataset trung gian. |
| `convert_biblio.py` | Chuyển Biblio-US17 từ log raw sang JSON format phù hợp extractor. |
| `baseline_train.py` | Script baseline Random Forest, dự kiến load 4 dataset, extract feature, train/evaluate/lưu model. |
| `mfi_train.py` | So sánh baseline vs MFI-Mean vs MFI-Class-Conditional. |
| `moe_train.py` | MoE phiên bản rule-based gồm 2 expert: full request và payload-only. |
| `moe_train_v2.py` | MoE phiên bản học thuật hơn: expert RF/XGB/LGBM + Logistic/MLP/Sparse gating. |
| `test_datasets.py` | Script đánh giá model trực tiếp, qua FastAPI `/predict`, hoặc qua Nginx thật. |
| `eval_biblio.py` | Script đánh giá riêng trên Biblio-US17 và phân tích feature/missed attacks. |
| `waf_training_best.py` | Script training cũ/tập trung một file, chứa extractor v5 inline và train RF. Có tính lịch sử/prototype. |
| `waf_server/app.py` | FastAPI WAF server: load `.pkl`, extract feature, predict, cung cấp `/auth`, `/predict`, `/benchmark`, `/scan`. |
| `waf_server/test_payloads.py` | CLI test server với `sample_payloads.json`. |
| `waf_server/templates/index.html` | UI web đơn giản để test một request và benchmark payload mẫu. |
| `waf_server/templates/blocked.html` | Trang 403 khi request bị WAF chặn. |
| `waf_server/Dockerfile` | Dockerfile cho WAF server. |
| `lab/docker-compose.yml` | Chạy Nginx + WAF + backend demo bằng Docker Compose. |
| `lab/nginx/waf.conf` | Nginx config tích hợp WAF qua `auth_request`. |
| `lab/backend/app.py` | Backend Flask demo đứng sau WAF. |
| `lab/test_waf_ml.sh` | Test suite shell: test normal, SQLi, XSS, LFI, command injection, Nginx E2E. |
| `lab/waf_server/*` | Bản WAF server duplicate/cũ trong thư mục lab. Docker compose hiện trỏ về `waf_server/Dockerfile` ở root, nên cần kiểm tra trước khi dùng. |

### Điểm bắt đầu chương trình

Có nhiều điểm bắt đầu tùy mục đích:

- Training đơn giản: `python main.py`.
- Training baseline: `python baseline_train.py`.
- Training MFI: `python mfi_train.py`.
- Training MoE v1: `python moe_train.py`.
- Training MoE v2: `python moe_train_v2.py`.
- Đánh giá model: `python test_datasets.py`.
- Chạy WAF server: `uvicorn waf_server.app:app --host 0.0.0.0 --port 8000` hoặc Docker.
- Demo đầy đủ: `cd lab && docker compose up -d --build`.

---

## 3. Pipeline tổng thể của hệ thống

### Pipeline huấn luyện

```text
Dataset HTTP request
  ├─ CSIC / ECML: gần đầy đủ URL, payload, headers
  ├─ HTTPParam: chủ yếu method + payload + label
  └─ Biblio-US17: URI/log, không có headers đầy đủ
        ↓
Normalize schema
  - method, url, payload, headers, label_id, source
        ↓
FeatureExtractor.extract(entry)
  - xử lý method GET/POST
  - lấy query string hoặc body làm effective_payload
  - decode URL nhiều tầng
  - tính thống kê ký tự, entropy, keyword attack, header anomaly
        ↓
Vector đặc trưng số
        ↓
Chia train/test bằng train_test_split(stratify=y)
        ↓
Train mô hình
  - RandomForest baseline
  - MFI RandomForest
  - MoE experts + gating
        ↓
Predict probability attack
        ↓
Evaluate
  - Accuracy
  - F1-macro
  - AUC-ROC
  - confusion matrix
  - missed attacks / false positives
        ↓
Lưu model .pkl và kết quả .json
```

### Pipeline demo/API WAF

```text
Client HTTP request
        ↓
Nginx port 8080/80
        ↓ auth_request /waf-check
FastAPI WAF server /auth
        ↓
Build entry: method + original URI + body + headers
        ↓
FeatureExtractor.extract(entry)
        ↓
MODEL.predict_proba(X)
        ↓
Nếu probability >= threshold: ATTACK → HTTP 403
Ngược lại: NORMAL → HTTP 200
        ↓
Nginx chặn request hoặc proxy sang backend Flask
```

---

## 4. Review từng file quan trọng

### 4.1 `config/keywords.py`

- **Vai trò:** chứa hằng số bảo mật: danh sách extension nguy hiểm, keyword SQLi/XSS/path traversal/command/PHP/probing, trọng số feature, pattern scanner UA.
- **Import:** không import thư viện ngoài.
- **Biến quan trọng:**
  - `CRITICAL_EXTENSIONS` tại `config/keywords.py:6`: các đuôi file nhạy cảm như `.bak`, `.env`, `.sql`, `.git`.
  - `MALICIOUS_UPLOAD_EXTS` tại `config/keywords.py:15`: đuôi file upload nguy hiểm như `.php`, `.exe`, `.jsp`.
  - `SQLI_BOUNDARY_KEYWORDS`, `SQLI_LITERAL_KEYWORDS` tại `config/keywords.py:22-35`.
  - `ATTACK_KEYWORDS` tại `config/keywords.py:38`.
  - `WEIGHTS` tại `config/keywords.py:104`.
  - `SCANNER_UA_PATTERNS` tại `config/keywords.py:140`.
- **Liên kết:** được import bởi `features/helpers.py` và `features/extractor.py`.
- **Điểm báo cáo:** file này đóng vai trò “tri thức bảo mật thủ công” hỗ trợ mô hình học máy. Nó không trực tiếp phân loại, nhưng tạo ra các tín hiệu đầu vào cho model.
- **Rủi ro:** keyword-based feature có thể gây false positive nếu keyword xuất hiện trong ngữ cảnh bình thường. Code có cố gắng giảm false positive bằng boundary matching cho SQLi.

### 4.2 `features/helpers.py`

- **Vai trò:** tập hợp các hàm thuần túy, không giữ state, dùng để tính feature.
- **Import:** `math`, `re`, `urllib.parse`, và các hằng số từ `config.keywords`.
- **Hàm chính:**
  - `calculate_param_name_entropy(payload)` tại `features/helpers.py:21`.
  - `calculate_entropy(text)` tại `features/helpers.py:44`.
  - `count_keywords(text, keyword_list)` tại `features/helpers.py:59`.
  - `count_sqli_keywords(text)` tại `features/helpers.py:70`.
  - `header_anomaly_score(headers)` tại `features/helpers.py:93`.
  - `check_critical_extension(url)` tại `features/helpers.py:165`.
  - `calculate_files_weight(payload)` tại `features/helpers.py:184`.
- **Luồng xử lý:** các hàm này được `FeatureExtractor` gọi để tạo feature vector.
- **Điểm báo cáo:** helper giúp tách logic nhỏ, dễ giải thích: entropy đo độ ngẫu nhiên, keyword count đo dấu hiệu tấn công, header anomaly đo dấu hiệu scanner/bot.
- **Rủi ro:** `count_keywords` dùng substring matching nên vẫn có khả năng bắt nhầm. `header_anomaly_score` dựa vào rule thủ công, cần nói đây là feature hỗ trợ chứ không phải quyết định cuối cùng.

### 4.3 `features/extractor.py`

- **Vai trò:** file quan trọng nhất trong hệ thống. `FeatureExtractor` chuyển một HTTP request dạng dict thành vector đặc trưng số.
- **Import:** `re`, `urllib.parse`, các keyword/config và helper.
- **Class chính:** `FeatureExtractor` tại `features/extractor.py:30`.
- **Biến quan trọng:** `_MAX_DECODE_DEPTH = 15` tại `features/extractor.py:27` để tránh decode vô hạn.
- **Luồng xử lý trong `extract(entry)`:**
  1. Lấy `method`, `url`, `payload`, `headers` tại `features/extractor.py:89-92`.
  2. Decode URL nhiều tầng bằng `_full_decode` tại `features/extractor.py:95`.
  3. Xác định `effective_payload`: GET lấy query string, POST/PUT lấy body tại `features/extractor.py:97` và helper `_get_effective_payload` tại `features/extractor.py:241-251`.
  4. Ghép `url_decoded` và `effective_payload` thành `injection_text` tại `features/extractor.py:103`.
  5. Tính thống kê ký tự, keyword attack, entropy, header anomaly, URL penalty, file upload risk, method bất thường.
  6. Tính `z_score` tổng hợp tại `features/extractor.py:172-192`.
  7. Trả về list feature tại `features/extractor.py:194-207`.
- **Số feature:** code trả về 32 feature: 27 feature cũ + 5 feature URL-based mới tại `features/extractor.py:72-78` và `features/extractor.py:204-206`.
- **Liên kết:** được dùng trong `main.py`, `baseline_train.py`, `mfi_train.py`, `moe_train.py`, `moe_train_v2.py`, `test_datasets.py`, `waf_server/app.py`.
- **Điểm báo cáo:** đây là cầu nối giữa dữ liệu HTTP dạng text và mô hình ML dạng vector số.
- **Rủi ro:** model đã train bằng số lượng feature nào thì khi chạy server phải dùng đúng extractor tương ứng. Một số docs/comment còn ghi 27 features, trong khi extractor hiện tại là 32 features.

#### Code quan trọng

```python
url_decoded, url_enc_depth = self._full_decode(url)
effective_payload = self._get_effective_payload(method, url, body)
injection_text = f"{url_decoded} {effective_payload}"
```

Ý nghĩa: hệ thống không chỉ dùng body, mà kết hợp URL đã decode với payload/query để bắt các kỹ thuật bypass bằng URL encoding.

### 4.4 `model/trainer.py`

- **Vai trò:** đóng gói pipeline Random Forest cơ bản trong class `ModelTrainer`.
- **Import:** `json`, `pickle`, `numpy`, `RandomForestClassifier`, `accuracy_score`, `classification_report`, `train_test_split`, `FeatureExtractor`.
- **Cấu hình:**
  - `ATTACK_THRESHOLD = 0.50` tại `model/trainer.py:18`.
  - `CLASS_WEIGHT = {0: 1, 1: 2}` tại `model/trainer.py:22`.
- **Class chính:** `ModelTrainer` tại `model/trainer.py:25`.
- **Hàm chính:**
  - `load_data()` tại `model/trainer.py:66`.
  - `train()` tại `model/trainer.py:91`.
  - `evaluate()` tại `model/trainer.py:123`.
  - `save_missed_attacks()` tại `model/trainer.py:143`.
  - `save_false_positives()` tại `model/trainer.py:176`.
  - `save_model()` tại `model/trainer.py:209`.
- **Luồng xử lý:** load JSON → extract feature → train/test split stratify → train RandomForest → predict probability → threshold → report/lưu lỗi/lưu model.
- **Điểm báo cáo:** class này thể hiện pipeline ML truyền thống, dễ dùng để giải thích baseline.
- **Rủi ro:** chỉ tính Accuracy và classification report trong `evaluate`, chưa lưu đầy đủ F1/AUC/confusion matrix như các script mới.

### 4.5 `main.py`

- **Vai trò:** entry point đơn giản dùng `FeatureExtractor` + `ModelTrainer`.
- **Cấu hình:**
  - `DATA_PATH = 'csic_training_data.json'` tại `main.py:9`.
  - `MODEL_PATH = 'waf_model_final_v6.pkl'` tại `main.py:17`.
- **Luồng xử lý:** khởi tạo extractor/trainer → load data → train → evaluate → save missed attacks → save false positives → save model tại `main.py:20-47`.
- **Điểm báo cáo:** đây là pipeline cơ bản, nhưng nếu báo cáo kết quả 4 dataset/MoE thì nên nói các script mới hơn (`baseline_train.py`, `mfi_train.py`, `moe_train_v2.py`) là pipeline chính.
- **Rủi ro:** mặc định chỉ dùng `csic_training_data.json`, không đại diện toàn bộ thực nghiệm 4 dataset.

### 4.6 `merge_datasets.py`

- **Vai trò:** chuẩn hóa và gộp CSIC, ECML, HTTPParam thành `merged_baseline.json`.
- **Hàm chính:** `load_json`, `normalize_csic`, `normalize_ecml`, `normalize_httpparam`, `print_stats`, `main`.
- **Luồng xử lý:** đọc dataset → điền field thiếu cho HTTPParam → thêm `source` → gộp list → lưu JSON.
- **Điểm báo cáo:** dùng để giải thích bước chuẩn hóa schema giữa các dataset không đồng nhất.
- **Rủi ro:** comment nói `converted_httpparam_data.json` nhưng code dùng `httpparam_data.json` tại `merge_datasets.py:112`; cần cập nhật comment nếu báo cáo.

### 4.7 `convert_biblio.py`

- **Vai trò:** chuyển Biblio-US17 log format sang JSON.
- **Hàm chính:**
  - `parse_line(line)` tại `convert_biblio.py:28`.
  - `load_files(directory, label, max_records, shuffle=True)` tại `convert_biblio.py:58`.
  - `main()` tại `convert_biblio.py:91`.
- **Luồng xử lý:** parse dòng log → tách URI/query thành URL/payload → gán label normal/attack → shuffle → lưu JSON.
- **Điểm báo cáo:** Biblio không có headers, nên hệ thống phải dựa nhiều hơn vào URL/query feature; code cũng in lưu ý này tại `convert_biblio.py:120-122`.
- **Rủi ro:** regex `LINE_RE` chỉ parse được format khớp mẫu; dòng không khớp bị bỏ qua. Chưa thấy code thống kê tỷ lệ dòng bị bỏ qua.

### 4.8 `baseline_train.py`

- **Vai trò:** train baseline RandomForest trên dataset chuẩn hóa.
- **Import:** `json`, `os`, `pickle`, `numpy`, `Counter`, `RandomForestClassifier`, metrics sklearn, `train_test_split`, `FeatureExtractor`.
- **Cấu hình:**
  - `ATTACK_THRESHOLD = 0.50` tại `baseline_train.py:20`.
  - `CLASS_WEIGHT = {0: 1, 1: 2}` tại `baseline_train.py:21`.
  - `N_ESTIMATORS = 300`, `MAX_DEPTH = 30`, `TEST_SIZE = 0.2`, `RANDOM_STATE = 42` tại `baseline_train.py:22-25`.
- **Hàm chính:** `load_csic`, `load_ecml`, `load_httpparam`, `load_biblio`, `evaluate_subset`, `main`.
- **Luồng xử lý:** load dataset → extract feature → split → train RF → predict proba → evaluate overall/per-source → feature importance → save result/model.
- **Lỗi logic quan trọng:** tại `baseline_train.py:136-140`, code load đủ 4 dataset nhưng `merged = csic`, nghĩa là baseline thực tế chỉ train CSIC. Trong khi log/result ghi 4 datasets. Cần sửa thành:

```python
merged = csic + ecml + httpparam + biblio
```

- **Điểm báo cáo:** không nên dùng kết quả baseline hiện tại để so sánh 4 dataset nếu chưa sửa lỗi này.

### 4.9 `mfi_train.py`

- **Vai trò:** thử Missing Feature Imputation cho dataset thiếu URL/header.
- **Ý tưởng:** HTTPParam thiếu nhiều feature URL/header; Biblio thiếu header. Code định nghĩa index feature thiếu tại `mfi_train.py:35-47`.
- **Hàm chính:**
  - `load_all()` tại `mfi_train.py:54`.
  - `compute_imputation_stats()` tại `mfi_train.py:118`.
  - `apply_mfi_mean()` tại `mfi_train.py:146`.
  - `apply_mfi_class_conditional()` tại `mfi_train.py:156`.
  - `train_evaluate()` tại `mfi_train.py:177`.
  - `main()` tại `mfi_train.py:227`.
- **Luồng xử lý:** load 4 dataset → extract feature → split → tính mean từ CSIC+ECML train → train baseline/MFI-Mean/MFI-Class-Conditional → evaluate → lưu model/results.
- **Rủi ro data leakage:** tại `mfi_train.py:277-280`, code dùng `y_test` để impute test set trong MFI-Class-Conditional. Khi deploy thật không biết nhãn trước, nên đây là rò rỉ nhãn. Nếu báo cáo, cần nói đây là upper-bound/oracle hoặc sửa lại bằng nhãn dự đoán sơ bộ.

### 4.10 `moe_train.py`

- **Vai trò:** MoE phiên bản 1, dùng rule router thay vì gating network học được.
- **Mô hình:** 2 expert RandomForest:
  - `Expert_Full`: train trên CSIC + ECML tại `moe_train.py:197-199`.
  - `Expert_Payload`: train trên HTTPParam tại `moe_train.py:201-203`.
- **Router:** `route(entry)` tại `moe_train.py:82`, trả về `full` nếu có URL hoặc header thật, ngược lại `payload`.
- **Chiến lược predict:**
  - MoE-Hard: request route nào thì dùng expert đó tại `moe_train.py:212-223`.
  - MoE-Soft: kết hợp xác suất 2 expert bằng trọng số cố định 0.7/0.3 hoặc 0.2/0.8 tại `moe_train.py:248-263`.
- **Output:** lưu `waf_model_expert_full.pkl`, `waf_model_expert_payload.pkl`, `moe_results.json` tại `moe_train.py:320-324`.
- **Điểm báo cáo:** đây là MoE đơn giản, dễ giải thích: chia miền dữ liệu theo độ đầy đủ của request.
- **Rủi ro:** router là rule thủ công, chưa phải gating network học từ dữ liệu.

### 4.11 `moe_train_v2.py`

- **Vai trò:** MoE phiên bản nâng cao hơn, có gating network học từ dữ liệu.
- **Import/mô hình:**
  - RandomForest, GradientBoosting.
  - LogisticRegression tại `moe_train_v2.py:28`.
  - MLPClassifier tại `moe_train_v2.py:29`.
  - XGBoost optional tại `moe_train_v2.py:36-42`.
  - LightGBM optional tại `moe_train_v2.py:43-49`.
  - CalibratedClassifierCV tại `moe_train_v2.py:34`.
- **Cấu hình:** `N_EXPERTS=3`, `TOP_K=2`, `TEMPERATURE=2.0`, `EM_ITERATIONS=2` tại `moe_train_v2.py:62-66`.
- **Expert factory:** `make_expert(kind)` tại `moe_train_v2.py:163`, tạo expert RF/XGB/LGBM hoặc fallback GradientBoosting, sau đó calibrate xác suất.
- **Gating:**
  - `LogisticGating` tại `moe_train_v2.py:227`.
  - `MLPGating` tại `moe_train_v2.py:283`.
  - `SparseTopKGating` tại `moe_train_v2.py:324`.
- **Class MoE:** `MixtureOfExperts` tại `moe_train_v2.py:392`.
- **Luồng fit:**
  1. Build experts/gating.
  2. Cold start: train tất cả experts trên toàn bộ data tại `moe_train_v2.py:456-460`.
  3. E-step: lấy xác suất từng expert tại `moe_train_v2.py:465-468`.
  4. Gating học routing từ expert performance tại `moe_train_v2.py:470-471`.
  5. M-step: tính gate weights và refit từng expert trên subset weight cao tại `moe_train_v2.py:473-486`.
- **Predict cuối:** `predict_proba()` lấy trọng số gating nhân với xác suất từng expert, rồi cộng tổng tại `moe_train_v2.py:507-516`.
- **Rủi ro/lưu ý:**
  - `_refit_expert(expert, X, y, sample_weight=None)` nhận `sample_weight` nhưng khi gọi `expert.fit(X, y)` tại `moe_train_v2.py:501` không truyền `sample_weight`. Vì vậy M-step chưa thật sự weighted.
  - `--fast` ở `moe_train_v2.py:763-770` chỉ đổi biến toàn cục, chưa thấy giảm data/cây như comment nói.
  - Gating học `gate_y` bằng `argmax` từ soft labels, nên thực chất training gate là hard assignment sau khi tính soft score.
- **Điểm báo cáo:** đây là phần phù hợp nhất với tên đề tài MoE, nhưng cần trình bày trung thực: code có gating học được và kết hợp soft probability; phần tối ưu EM còn đơn giản/prototype.

### 4.12 `test_datasets.py`

- **Vai trò:** đánh giá model ở 3 chế độ: trực tiếp `.pkl`, qua WAF API `/predict`, hoặc qua Nginx pipeline đầy đủ.
- **Hàm chính:**
  - Load dataset: `load_csic`, `load_ecml`, `load_httpparam`, `load_biblio` tại `test_datasets.py:68-139`.
  - Tái tạo test split: `load_test_split()` tại `test_datasets.py:142-191`.
  - Predict trực tiếp: `predict_direct()` tại `test_datasets.py:198-211`.
  - Predict qua API: `predict_http()` tại `test_datasets.py:219-257`.
  - Predict qua Nginx: `_send_nginx_one()` và `predict_nginx()` tại `test_datasets.py:264-345`.
  - In metric: `print_metrics()` tại `test_datasets.py:352-395`.
- **Metric:** Accuracy, F1-macro, AUC, TP/TN/FP/FN, precision attack, recall attack, latency ms/req.
- **Điểm báo cáo:** file này chứng minh hệ thống không chỉ đánh giá offline mà còn có thể đánh giá pipeline thực tế qua Nginx.
- **Rủi ro:** khi lỗi HTTP/Nginx, code có trường hợp coi là normal (`pred=0`), điều này có thể làm lệch metric nếu server lỗi nhiều.

### 4.13 `eval_biblio.py`

- **Vai trò:** đánh giá riêng dataset Biblio-US17 với nhiều model `.pkl`.
- **Luồng xử lý:** load Biblio → extract features → phân tích feature khác biệt attack/normal → test các model → in F1/AUC/Accuracy/missed/FP → phân tích missed attacks.
- **Điểm báo cáo:** dùng để giải thích vì sao cần thêm URL decoding feature cho Biblio.
- **Rủi ro:** đường dẫn `BASE = r'D:\Project 3\Code xử lí'` hard-code tại `eval_biblio.py:3`, không portable.

### 4.14 `waf_training_best.py`

- **Vai trò:** script training cũ/prototype có extractor v5 inline.
- **Đặc điểm:** nhiều logic hiện đã được tách sang `config/`, `features/`, `model/`.
- **Điểm báo cáo:** có thể nói đây là phiên bản thực nghiệm trước khi refactor module.
- **Rủi ro:** duplicate logic với `features/extractor.py`; số feature trong script này là 23 feature tại `waf_training_best.py:250-255`, khác extractor hiện tại 32 feature. Không nên trộn model từ phiên bản này với extractor hiện tại nếu số feature không khớp.

### 4.15 `waf_server/app.py`

- **Vai trò:** FastAPI inference server cho WAF.
- **Config:**
  - `MODEL_PATH` đọc từ env `WAF_MODEL_PATH`, mặc định `waf_model_final_v6.pkl` tại `waf_server/app.py:48-51`.
  - `ATTACK_THRESHOLD` đọc từ env `WAF_THRESHOLD` tại `waf_server/app.py:52`.
  - IP whitelist/blacklist tại `waf_server/app.py:63-68`.
- **Load model:** dùng `pickle.load` tại `waf_server/app.py:115-117`.
- **Class schema:** `RequestEntry`, `PredictResponse` tại `waf_server/app.py:138-157`.
- **Hàm core:** `predict_entry(entry)` tại `waf_server/app.py:163`. Hàm này extract feature, gọi `MODEL.predict_proba`, lấy probability attack và trả verdict.
- **Endpoint chính:**
  - `/health` tại `waf_server/app.py:278`.
  - `/predict` tại `waf_server/app.py:302`.
  - `/benchmark` tại `waf_server/app.py:329`.
  - `/auth` dành cho Nginx tại `waf_server/app.py:413`.
  - `/scan/{full_path}` tại `waf_server/app.py:543`.
- **Điểm báo cáo:** file này biến mô hình ML thành WAF service thực tế.
- **Rủi ro bảo mật:**
  - Dùng `pickle.load`; chỉ load model tin cậy, không load file lạ.
  - Log input request có thể chứa cookie/authorization/payload nhạy cảm tại `waf_server/app.py:310-318` và `waf_server/app.py:512-521`.
  - Cần đảm bảo model `.pkl` khớp đúng số feature của `FeatureExtractor`.

### 4.16 `lab/nginx/waf.conf`

- **Vai trò:** Nginx reverse proxy tích hợp WAF qua `auth_request`.
- **Luồng:** request vào Nginx → subrequest `/waf-check` → WAF `/auth` → 200 cho qua, 403 chặn.
- **Config quan trọng:**
  - upstream `waf_server` và `app_backend` tại `lab/nginx/waf.conf:11-12`.
  - `/waf-check` tại `lab/nginx/waf.conf:28-43`.
  - location `/` có `auth_request /waf-check` tại `lab/nginx/waf.conf:57-72`.
  - fail-open tại `lab/nginx/waf.conf:84-89`.
- **Điểm báo cáo:** chứng minh đồ án có demo triển khai WAF trước backend.
- **Rủi ro:** fail-open nghĩa là nếu WAF server lỗi thì request vẫn qua backend. Đây là trade-off availability vs security.

### 4.17 `lab/docker-compose.yml`

- **Vai trò:** dựng 3 service: Nginx, WAF, backend demo.
- **Điểm quan trọng:** service WAF build từ project root và dùng `waf_server/Dockerfile` tại `lab/docker-compose.yml:32-35`.
- **Model mount:** mount các file `.pkl` từ root vào container tại `lab/docker-compose.yml:49-58`.
- **Rủi ro:** mặc định `WAF_MODEL_PATH` là `/app/waf_model_baseline.pkl` tại `lab/docker-compose.yml:44`, trong khi `waf_server/app.py` mặc định là `waf_model_final_v6.pkl`. Cần nói rõ model nào dùng khi demo.

### 4.18 `lab/backend/app.py`

- **Vai trò:** backend Flask demo đứng sau WAF.
- **Luồng:** nếu WAF cho qua, request tới backend; backend hiển thị method/path và các `X-WAF-*` headers.
- **Điểm báo cáo:** backend không tự chặn attack; WAF là lớp bảo vệ phía trước.

### 4.19 `lab/test_waf_ml.sh`

- **Vai trò:** test end-to-end nhiều loại request.
- **Nhóm test:** normal, SQLi, XSS, path traversal/LFI, command injection, PHP/RCE, scanner/probing, Nginx E2E, benchmark sample payloads, direct bypass backend.
- **Điểm báo cáo:** có thể dùng làm demo nhanh khi bảo vệ.

---

## 5. Review class/hàm quan trọng

### `FeatureExtractor.extract(entry)`

- **File:** `features/extractor.py`.
- **Mục đích:** biến HTTP request thành vector 32 feature.
- **Input:** dict có `method`, `url`, `payload`, `headers`.
- **Output:** list số thực/số nguyên.
- **Các bước chính:** lấy field → decode URL → xác định payload hiệu lực → tính char stats → đếm keyword → tính header anomaly → tính z_score → trả vector.
- **Ý nghĩa:** là đầu vào chung cho tất cả model train/predict.
- **Cách nói khi báo cáo:** “Em không đưa trực tiếp chuỗi HTTP vào mô hình, mà chuyển request thành vector đặc trưng gồm độ dài, entropy, số keyword SQLi/XSS, điểm bất thường header, độ sâu encoding URL…”

### `FeatureExtractor._full_decode(text)`

- **File:** `features/extractor.py:213-238`.
- **Mục đích:** decode URL encoding nhiều tầng.
- **Input:** URL/string.
- **Output:** `(decoded_text, depth)`.
- **Ý nghĩa:** phát hiện bypass kiểu `%252e%252e%252f`.
- **Cách nói:** “Hàm này lặp decode đến khi chuỗi không đổi hoặc đạt giới hạn 15 tầng, giúp phát hiện payload bị mã hóa nhiều lớp.”

### `header_anomaly_score(headers)`

- **File:** `features/helpers.py:93-162`.
- **Mục đích:** tính điểm bất thường của HTTP headers.
- **Input:** dict headers.
- **Output:** integer score.
- **Dấu hiệu:** UA quá ngắn, scanner UA, Mozilla version giả, accept-language/cache-control bất thường.
- **Cách nói:** “Header anomaly không quyết định trực tiếp request là attack, mà là một feature để mô hình học.”

### `ModelTrainer`

- **File:** `model/trainer.py:25`.
- **Mục đích:** đóng gói pipeline Random Forest cơ bản.
- **Input:** `FeatureExtractor`, hyperparameters.
- **Output:** model đã train, report, file `.pkl`.
- **Cách nói:** “Đây là pipeline baseline để kiểm chứng feature extractor và mô hình RF trước khi mở rộng sang MFI/MoE.”

### `compute_imputation_stats()` và `apply_mfi_mean()`

- **File:** `mfi_train.py:118`, `mfi_train.py:146`.
- **Mục đích:** tính mean feature từ nguồn đầy đủ CSIC+ECML và dùng để điền feature thiếu cho HTTPParam/Biblio.
- **Ý nghĩa:** xử lý sự không đồng nhất giữa dataset.
- **Cách nói:** “HTTPParam không có URL/header nên một số feature bị mất ý nghĩa. MFI giúp thay zero bằng giá trị thống kê từ nguồn đầy đủ.”

### `LogisticGating`, `MLPGating`, `SparseTopKGating`

- **File:** `moe_train_v2.py`.
- **Mục đích:** học trọng số phân phối sample cho các expert.
- **Input:** feature matrix `X`, label `y`, xác suất từ expert `expert_probas`.
- **Output:** matrix trọng số `(n_samples, n_experts)`.
- **Cách nói:** “Gating network nhận cùng feature vector với expert, sau đó quyết định expert nào đáng tin hơn cho từng request.”

### `MixtureOfExperts.predict_proba(X)`

- **File:** `moe_train_v2.py:507-516`.
- **Mục đích:** tính xác suất attack cuối cùng.
- **Công thức theo code:**

```python
gate_w = self.gating.predict_weights(X)
expert_proba = np.column_stack([e.predict_proba(X)[:, 1] for e in self.experts])
return (gate_w * expert_proba).sum(axis=1)
```

- **Cách nói:** “Mỗi expert trả một xác suất attack; gating trả trọng số; xác suất cuối là tổng có trọng số.”

### `predict_entry(entry)`

- **File:** `waf_server/app.py:163-187`.
- **Mục đích:** inference một request.
- **Input:** dict request.
- **Output:** verdict, probability, features, timing.
- **Ý nghĩa:** là lõi runtime của WAF server.
- **Cách nói:** “Ở runtime, mỗi request được extract feature và đưa vào model đã load từ file `.pkl`; nếu xác suất vượt threshold thì chặn.”

### `nginx_auth(request)`

- **File:** `waf_server/app.py:413-540`.
- **Mục đích:** endpoint dành cho Nginx `auth_request`.
- **Input:** subrequest từ Nginx kèm header `X-Original-*`.
- **Output:** HTTP 200 nếu normal, 403 nếu attack.
- **Cách nói:** “Nginx không tự chạy ML; nó hỏi FastAPI WAF qua `/auth`. WAF trả 200/403 để Nginx quyết định proxy hoặc block.”

---

## 6. Giải thích mô hình Machine Learning trong code

### Random Forest

- **Khai báo:** `baseline_train.py:168-170`, `model/trainer.py:110-115`, `mfi_train.py:182-184`, `moe_train.py:99-103`, `moe_train_v2.py:173-176`.
- **Tham số:** `n_estimators=300` hoặc 150 trong MoE v2, `max_depth=30`, `class_weight` để xử lý mất cân bằng.
- **Input:** ma trận feature `X` từ `FeatureExtractor`.
- **Output:** xác suất attack qua `predict_proba(X)[:, 1]`.
- **Evaluate:** Accuracy, F1-macro, AUC, confusion matrix/missed/FP.

### XGBoost và LightGBM

- **Khai báo optional:** `moe_train_v2.py:36-49`.
- **Dùng trong:** `make_expert(kind)` tại `moe_train_v2.py:163-205`.
- **Fallback:** nếu không cài XGBoost/LightGBM thì dùng `GradientBoostingClassifier`.
- **Vai trò:** làm expert đa dạng trong MoE.

### Logistic Regression / MLP / Sparse Gating

- **Logistic:** tuyến tính, dễ giải thích.
- **MLP:** học quan hệ phi tuyến.
- **Sparse Top-K:** chỉ giữ top K expert có trọng số cao nhất, tránh nhiễu từ expert yếu.
- **Output:** trọng số expert, không trực tiếp là verdict.

---

## 7. Giải thích bằng văn phong báo cáo

Trong hệ thống, dữ liệu HTTP request ban đầu được chuẩn hóa về cùng một cấu trúc gồm method, URL, payload, headers và nhãn. Do các bộ dữ liệu có mức độ đầy đủ khác nhau, ví dụ HTTPParam thiếu URL và header, hệ thống bổ sung các trường mặc định và lưu lại nguồn dữ liệu để đánh giá riêng theo từng dataset.

Sau khi chuẩn hóa, mỗi request được đưa vào module trích xuất đặc trưng. Module này phân tích query string, body, URL đã decode nhiều tầng và HTTP headers để tạo ra vector đặc trưng số. Các đặc trưng bao gồm độ dài payload, tỷ lệ ký tự đặc biệt, entropy, số lượng từ khóa SQL Injection, XSS, path traversal, command injection, dấu hiệu upload file nguy hiểm, điểm bất thường của header và các đặc trưng liên quan đến URL encoding.

Vector đặc trưng sau đó được dùng để huấn luyện các mô hình học máy. Baseline của hệ thống là Random Forest, vì mô hình này phù hợp với dữ liệu dạng bảng, dễ huấn luyện và có thể đánh giá feature importance. Để xử lý sự khác biệt giữa các nguồn dữ liệu, đồ án thử nghiệm Missing Feature Imputation nhằm thay thế các feature thiếu bằng giá trị thống kê từ các dataset đầy đủ hơn.

Đối với kiến trúc Mixture of Experts, hệ thống xây dựng nhiều mô hình expert khác nhau như Random Forest, XGBoost và LightGBM. Mỗi expert đưa ra một xác suất request là tấn công. Gating network như Logistic Regression, MLP hoặc Sparse Top-K nhận feature đầu vào và sinh ra trọng số cho từng expert. Xác suất cuối cùng được tính bằng tổng có trọng số giữa xác suất của các expert. Nếu xác suất cuối cùng vượt ngưỡng, request được phân loại là tấn công.

Trong phần demo triển khai, mô hình đã huấn luyện được lưu thành file `.pkl` và được FastAPI WAF server load khi khởi động. Nginx đóng vai trò reverse proxy, sử dụng `auth_request` để gửi subrequest đến WAF server trước khi chuyển request đến backend. Nếu WAF trả về HTTP 403, Nginx chặn request; nếu WAF trả về HTTP 200, request được proxy đến backend.

---

## 8. Câu hỏi phản biện có thể gặp

| Câu hỏi | Trả lời ngắn gọn dựa trên code |
|---|---|
| Vì sao chọn Random Forest? | Code dùng dữ liệu dạng vector/tabular; Random Forest dễ huấn luyện, hỗ trợ `feature_importances_`, xử lý non-linear tốt và có `class_weight`. |
| Vì sao cần Mixture of Experts? | Các dataset có đặc điểm khác nhau: có request đầy đủ URL/header và có request payload-only. MoE cho phép nhiều expert chuyên biệt và gating chọn/kết hợp expert phù hợp. |
| Gating network hoạt động như thế nào? | Trong `moe_train_v2.py`, gating nhận feature `X`, học assignment dựa trên lỗi của expert, rồi trả trọng số cho từng expert. |
| Một sample có thể được nhiều expert học không? | Trong MoE v2, ban đầu tất cả expert train trên toàn data; sau đó gating weight được dùng để chọn subset cho từng expert. Trong predict, sample được kết hợp nhiều expert theo trọng số. |
| Vì sao cần xử lý missing feature? | HTTPParam/Biblio thiếu URL/header, khiến một số feature bằng 0 hoặc không có ý nghĩa. MFI thử điền bằng mean từ CSIC+ECML. |
| F1-score quan trọng hơn Accuracy vì sao? | Bài toán attack/normal có thể mất cân bằng; Accuracy cao vẫn có thể bỏ lọt nhiều attack. F1 cân bằng precision và recall. |
| Code phát hiện tấn công kiểu gì? | Dựa trên keyword/feature cho SQLi, XSS, path traversal, command injection, PHP injection, probing/scanner, file upload nguy hiểm. |
| Có phát hiện được tấn công mới không? | Chưa đủ dữ liệu để kết luận. Model có thể tổng quát từ feature, nhưng code không có đánh giá zero-day/adversarial riêng. |
| Có xử lý URL encoding không? | Có. `FeatureExtractor._full_decode` decode nhiều tầng và thêm feature URL encoding depth/double encoding. |
| Có nguy cơ data leakage không? | Có trong MFI-Class-Conditional: test set được impute bằng `y_test` tại `mfi_train.py:277-280`. |
| WAF chạy thật như thế nào? | Nginx gọi FastAPI `/auth`; WAF extract feature, model predict, trả 200/403. |
| Nếu WAF server chết thì sao? | Theo `lab/nginx/waf.conf`, cấu hình hiện tại fail-open: request vẫn được proxy sang backend. |
| Model được lưu/load thế nào? | Train script dùng `pickle.dump`; server dùng `pickle.load`. |
| Có log request không? | Có log request/prediction vào file log/jsonl trong `waf_server/app.py`. |
| Hạn chế chính là gì? | Duplicate code, baseline có lỗi merge, MFI có leakage, docs feature count chưa đồng nhất, log có thể chứa dữ liệu nhạy cảm. |

---

## 9. Đánh giá chất lượng code

### Điểm mạnh

- Chia module khá rõ: config, helpers, extractor, trainer, server, lab.
- Có nhiều comment tiếng Việt, phù hợp để trình bày đồ án.
- Có cả offline evaluation và demo runtime qua Nginx/FastAPI.
- Có nhiều metric hơn Accuracy: F1, AUC, confusion matrix, missed attacks, false positives, latency.
- Có thử nghiệm từ baseline đến MFI và MoE.

### Điểm yếu/rủi ro

1. **Lỗi baseline:** `baseline_train.py` chỉ dùng CSIC do `merged = csic`.
2. **Data leakage:** `mfi_train.py` dùng `y_test` để impute MFI-Class-Conditional.
3. **Duplicate code:** load/normalize dataset bị lặp trong nhiều file.
4. **Duplicate server:** `lab/waf_server/app.py` và `waf_server/app.py` gần giống nhau.
5. **Feature count không đồng nhất:** extractor hiện trả 32 feature nhưng docs/comment còn ghi 27 feature.
6. **MoE v2 chưa hoàn chỉnh weighted refit:** `sample_weight` không được truyền vào `fit`.
7. **Hard-code path:** `eval_biblio.py` hard-code `D:\Project 3\Code xử lí`.
8. **Security logging:** log cookie/authorization/payload nếu request có dữ liệu nhạy cảm.
9. **Pickle risk:** chỉ nên load model tin cậy.
10. **Fail-open:** WAF lỗi thì Nginx vẫn cho qua.

---

## 10. Đề xuất cải thiện

### Mức 1 — nhỏ, dễ làm trước báo cáo

1. Sửa `baseline_train.py`: `merged = csic + ecml + httpparam + biblio`.
2. Cập nhật docs/comment từ 27 features thành 32 features.
3. Ghi rõ model chính dùng khi demo: baseline, final_v6 hay MoE best.
4. Thêm `README.md` ở root với cách train/test/demo.
5. Không trình bày MFI-Class-Conditional như kết quả deploy thực tế nếu chưa sửa leakage.
6. Xóa hoặc không nộp cache/log/LaTeX build artifact.

### Mức 2 — trung bình, giúp code rõ hơn

1. Tách `data_loader.py` dùng chung cho baseline/MFI/MoE/test.
2. Tách `metrics.py` để in Accuracy/F1/AUC/confusion matrix thống nhất.
3. Tạo `requirements.txt` root cho training và server.
4. Gộp hoặc xóa duplicate `lab/waf_server` nếu không dùng.
5. Thêm unit test nhỏ cho `FeatureExtractor` với SQLi/XSS/normal samples.
6. Mask cookie/authorization trước khi ghi log.

### Mức 3 — lớn, hướng phát triển

1. Hoàn thiện MoE weighted training: truyền `sample_weight` đúng cách hoặc dùng estimator hỗ trợ.
2. Thêm validation set riêng và cross-validation để chọn threshold.
3. Đánh giá generalization trên dataset chưa từng train.
4. Thử fail-closed mode cho Nginx trong môi trường bảo mật cao.
5. Triển khai model registry/versioning để tránh mismatch feature count.
6. Thêm dashboard giám sát: số request, số block, latency, top attack type.

---

## 11. Những phần code quan trọng nhất để báo cáo

1. `features/extractor.py` — cách biến HTTP request thành 32 feature.
2. `config/keywords.py` + `features/helpers.py` — tri thức bảo mật và hàm tính feature.
3. `baseline_train.py` — baseline Random Forest, nhưng cần sửa lỗi `merged` trước khi dùng kết quả.
4. `mfi_train.py` — xử lý missing feature, lưu ý leakage ở class-conditional.
5. `moe_train_v2.py` — kiến trúc MoE với experts và gating.
6. `waf_server/app.py` — inference server, endpoint `/auth` và `/predict`.
7. `lab/nginx/waf.conf` — WAF tích hợp Nginx.
8. `test_datasets.py` — đánh giá offline/API/Nginx.

---

## 12. Những điểm yếu cần lưu ý khi bị hỏi

- Baseline hiện có lỗi chỉ train CSIC nếu chưa sửa.
- MFI-Class-Conditional có data leakage.
- MoE v2 là implementation prototype; weighted refit chưa truyền `sample_weight`.
- Chưa thấy test tự động/unit test chính thức cho từng feature.
- Chưa đủ dữ liệu trong code để kết luận khả năng phát hiện zero-day.
- Demo Nginx hiện fail-open.
- Log có thể chứa dữ liệu nhạy cảm.
- Cần đảm bảo model `.pkl` tương thích đúng số feature với extractor hiện tại.
