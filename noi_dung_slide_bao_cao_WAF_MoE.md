# Nội dung slide báo cáo: WAF học máy với kiến trúc Mixture of Experts

Đối tượng trình bày: giảng viên/lớp. Độ dài đề xuất: 28 slide. Mục tiêu của bộ nội dung này là giúp trình bày đầy đủ bối cảnh, bài toán, dữ liệu, phương pháp, thực nghiệm, triển khai và kết luận của đề tài “Xây dựng hệ thống tường lửa ứng dụng web dựa trên học máy với kiến trúc Mixture of Experts”.

---

## Slide 1. Trang bìa

**Nội dung trên slide**

- Đề tài: Xây dựng hệ thống tường lửa ứng dụng web dựa trên học máy với kiến trúc Mixture of Experts
- Sinh viên: Phan Nhật Trường
- Giảng viên hướng dẫn: Lê Xuân Thành
- Trường Công nghệ Thông tin và Truyền thông, Đại học Bách Khoa Hà Nội
- Thời gian: 06/2026

**Gợi ý hình minh họa**

Sơ đồ biểu tượng Client → WAF ML → Web Server, kèm hình khiên bảo mật hoặc firewall.

**Ghi chú thuyết trình**

Em xin trình bày đề tài xây dựng hệ thống WAF thông minh dựa trên học máy. Trọng tâm của đề tài là phát hiện request HTTP độc hại, xử lý dữ liệu đa nguồn và thử nghiệm kiến trúc Mixture of Experts.

---

## Slide 2. Mục lục báo cáo

**Nội dung trên slide**

- Bối cảnh và bài toán
- Dữ liệu và tiền xử lý
- Bộ đặc trưng 32 chiều
- Baseline Random Forest, Missing Feature Imputation và Mixture of Experts
- Kết quả thực nghiệm
- Thiết kế triển khai production
- Kết luận và hướng phát triển

**Gợi ý hình minh họa**

Timeline ngang gồm 7 chặng: Problem → Data → Features → Models → Experiments → Deployment → Conclusion.

**Ghi chú thuyết trình**

Bài trình bày sẽ đi từ lý do chọn đề tài, sau đó là cách xây dựng pipeline, cách đánh giá mô hình và cuối cùng là khả năng triển khai thực tế.

---

## Slide 3. Bối cảnh: tấn công ứng dụng web ngày càng phổ biến

**Nội dung trên slide**

- Ứng dụng web là nền tảng của nhiều dịch vụ số như thương mại điện tử, tài chính, giáo dục và y tế.
- Tầng ứng dụng là mục tiêu phổ biến của các cuộc tấn công như SQL Injection, Cross-Site Scripting, Path Traversal và Command Injection.
- Request HTTP có nhiều bề mặt tấn công: method, URL, query string, body/payload và headers.
- WAF là lớp phòng thủ đặt trước web server để kiểm tra, chặn hoặc cảnh báo request nguy hiểm.

**Gợi ý hình minh họa**

Minh họa request đi từ client đến web server, ở giữa có WAF kiểm tra các thành phần method, URL, payload và headers.

**Ghi chú thuyết trình**

Với ứng dụng web, kẻ tấn công không nhất thiết phải xâm nhập vào hạ tầng mạng mà có thể khai thác trực tiếp thông qua tham số HTTP. Vì vậy WAF cần hoạt động ở tầng ứng dụng và hiểu được nội dung request.

---

## Slide 4. Hạn chế của WAF truyền thống

**Nội dung trên slide**

- WAF truyền thống thường dựa vào rule hoặc signature, ví dụ so khớp biểu thức chính quy.
- Rule-based WAF khó bao phủ các biến thể tấn công mới chưa có trong tập luật.
- Payload có thể bị che giấu bằng URL encoding nhiều tầng, ví dụ `%2527 → %27 → '`, khiến rule đơn giản bị bypass.
- Nếu luật quá chặt có thể gây false positive; nếu luật quá lỏng có thể bỏ lọt tấn công.
- Cần hướng tiếp cận có khả năng học mẫu bất thường từ dữ liệu.

**Gợi ý hình minh họa**

So sánh hai cột: WAF rule-based và WAF học máy. Bên rule-based có biểu tượng danh sách luật, bên học máy có feature vector và classifier.

**Ghi chú thuyết trình**

Hạn chế chính của rule-based WAF là phụ thuộc vào tri thức thủ công. Khi payload bị biến đổi hoặc encode nhiều tầng, cùng một bản chất tấn công có thể có rất nhiều biểu diễn khác nhau.

---

## Slide 5. Vấn đề nghiên cứu của đề tài

**Nội dung trên slide**

- Mục tiêu là phân loại HTTP request thành hai lớp: normal và attack.
- Dữ liệu HTTP đến từ nhiều nguồn khác nhau nên không đồng nhất về schema, trường thông tin và phân phối tấn công.
- Một số dataset thiếu URL đầy đủ, payload hoặc headers, dẫn đến nhiều đặc trưng không có giá trị.
- Một mô hình duy nhất có thể khó tối ưu cho mọi nguồn dữ liệu.
- Câu hỏi nghiên cứu: làm thế nào xây dựng WAF học máy hiệu quả trên nhiều bộ dữ liệu HTTP không đồng nhất?

**Gợi ý hình minh họa**

Sơ đồ nhiều dataset với cấu trúc khác nhau cùng đi vào một pipeline chung, kèm các nhãn “missing features”, “distribution shift”, “multi-source data”.

**Ghi chú thuyết trình**

Điểm khó của đề tài không chỉ là chọn classifier, mà còn là xử lý dữ liệu đa nguồn. Đây là lý do đề tài kết hợp feature engineering, Missing Feature Imputation và Mixture of Experts.

---

## Slide 6. Mục tiêu và đóng góp chính

**Nội dung trên slide**

- Xây dựng pipeline chuẩn hóa HTTP request và trích xuất đặc trưng phục vụ phát hiện tấn công.
- Đề xuất bộ đặc trưng 32 chiều, gồm 27 đặc trưng gốc và 5 đặc trưng URL-based mới cho obfuscation nhiều tầng.
- So sánh các chiến lược Baseline Random Forest, Missing Feature Imputation và Mixture of Experts.
- Đánh giá trên 4 bộ dữ liệu với tổng cộng 177.024 HTTP requests.
- Thiết kế hệ thống triển khai production bằng FastAPI, Nginx và Docker Compose.

**Gợi ý hình minh họa**

Bốn khối đóng góp: Features, MFI, MoE, Deployment.

**Ghi chú thuyết trình**

Đề tài có hai phần chính: phần thực nghiệm học máy trên dữ liệu đa nguồn và phần thiết kế triển khai để chứng minh hệ thống có thể chạy như một WAF thực tế.

---

## Slide 7. Tổng quan kiến trúc hệ thống

**Nội dung trên slide**

- Input: HTTP request từ client hoặc log dữ liệu.
- Chuẩn hóa các trường: method, URL, payload/body, headers và label.
- Trích xuất vector đặc trưng 32 chiều.
- Mô hình học máy dự đoán xác suất request là attack.
- Output: allow, block hoặc alert dựa trên ngưỡng quyết định.

**Gợi ý hình minh họa**

Pipeline: HTTP Request → Normalization → Feature Extractor → ML Model → Verdict → Web Server.

**Ghi chú thuyết trình**

Hệ thống tách phần xử lý request thành các bước rõ ràng. Cách thiết kế này giúp dễ thay mô hình, dễ bổ sung đặc trưng và dễ tích hợp vào reverse proxy.

---

## Slide 8. HTTP request và bề mặt tấn công

**Nội dung trên slide**

- Method: GET, POST, PUT, DELETE, TRACE hoặc các method ít gặp.
- URL và query string: chứa đường dẫn, tham số và có thể chứa payload tấn công.
- Body/payload: thường xuất hiện trong POST/PUT, là nơi chứa dữ liệu form hoặc JSON.
- Headers: User-Agent, Cookie, Content-Type, Referer, Authorization.
- WAF cần phân tích đồng thời nhiều thành phần vì tấn công có thể ẩn ở bất kỳ vị trí nào.

**Gợi ý hình minh họa**

Một HTTP request mẫu được annotate bằng màu: method, URL, query, body, headers.

**Ghi chú thuyết trình**

Ví dụ SQL Injection thường xuất hiện trong query hoặc body, trong khi scanner có thể lộ dấu hiệu qua User-Agent. Vì vậy feature extractor cần khai thác cả nội dung và metadata.

---

## Slide 9. Các nhóm tấn công được xét

**Nội dung trên slide**

- SQL Injection: chèn mã SQL như `' OR '1'='1`, `UNION SELECT`, `DROP TABLE`.
- Cross-Site Scripting: chèn JavaScript như `<script>`, `onerror=`, `javascript:`.
- Path Traversal: truy cập file ngoài thư mục cho phép bằng `../`, `%2e%2e%2f`, `/etc/passwd`.
- Command Injection: chèn lệnh hệ điều hành qua `;`, `&&`, `|`, `whoami`, `cat`.
- Probing/Scanner: request dò quét hệ thống, user-agent như sqlmap, nikto hoặc các đường dẫn admin/config.

**Gợi ý hình minh họa**

Bảng 5 nhóm tấn công, mỗi nhóm có một icon và ví dụ payload ngắn.

**Ghi chú thuyết trình**

Các loại tấn công này có đặc điểm ký tự và từ khóa khác nhau. Đây là cơ sở để thiết kế nhóm feature thống kê, từ khóa và hành vi HTTP.

---

## Slide 10. Bốn bộ dữ liệu sử dụng

**Nội dung trên slide**

| Bộ dữ liệu | Loại | Tổng mẫu | Normal | Attack | Tỉ lệ attack |
|---|---:|---:|---:|---:|---:|
| CSIC 2010 | Tổng hợp | 61.515 | 36.000 | 25.515 | 41,5% |
| ECML/PKDD 2007 | Thực tế | 23.543 | 10.142 | 13.401 | 56,9% |
| HTTPParam | Tổng hợp | 30.453 | 19.158 | 11.295 | 37,1% |
| Biblio-US17 | Thực tế | 61.513 | 35.139 | 26.374 | 42,9% |
| Tổng cộng | — | 177.024 | 100.439 | 76.585 | 43,3% |

**Gợi ý hình minh họa**

Biểu đồ stacked bar thể hiện normal/attack của từng dataset.

**Ghi chú thuyết trình**

Việc sử dụng bốn nguồn dữ liệu giúp đánh giá mô hình trong bối cảnh đa nguồn. Hai bộ là dữ liệu tổng hợp, hai bộ là dữ liệu thực tế, nên độ khó và phân phối khác nhau rõ rệt.

---

## Slide 11. Đặc điểm và thách thức của từng dataset

**Nội dung trên slide**

- CSIC 2010 mô phỏng traffic ứng dụng thương mại điện tử, có cấu trúc request tương đối đầy đủ.
- ECML/PKDD 2007 là dữ liệu thực tế, có tỉ lệ attack cao nhất và phân phối phức tạp nhất.
- HTTPParam tập trung vào tấn công qua tham số POST, nhưng thiếu URL đầy đủ và headers.
- Biblio-US17 là dữ liệu web server thư viện, nhiều mẫu chỉ có URL, timestamp và nhãn, thiếu payload và headers.
- Biblio có nhiều tấn công dùng URL encoding nhiều tầng, tạo động lực cho nhóm đặc trưng URL-based mới.

**Gợi ý hình minh họa**

Ma trận dataset × trường dữ liệu, đánh dấu trường có/thiếu: URL, payload, headers, label.

**Ghi chú thuyết trình**

ECML là nguồn khó nhất vì là traffic thực tế và phân phối khác biệt. HTTPParam và Biblio đặt ra vấn đề missing feature do thiếu các trường quan trọng.

---

## Slide 12. Quy trình tiền xử lý dữ liệu

**Nội dung trên slide**

- Đọc dữ liệu từ nhiều nguồn và đưa về schema chung.
- Chuẩn hóa method, URL, payload/body, headers và nhãn.
- Gán nhãn nhị phân: 0 là normal, 1 là attack.
- Decode URL nhiều tầng để phát hiện payload bị che giấu.
- Chia train/test theo tỉ lệ 80/20, stratified sampling, random_state = 42.
- Sử dụng cùng một phân chia cho các chiến lược để so sánh công bằng.

**Gợi ý hình minh họa**

Flow: Raw datasets → Unified schema → URL decode → Feature extraction → Train/test split.

**Ghi chú thuyết trình**

Tiền xử lý quyết định chất lượng của feature vector. Đặc biệt, decode URL nhiều tầng giúp đưa payload về dạng có thể phân tích thay vì chỉ nhìn thấy chuỗi đã mã hóa.

---

## Slide 13. Bộ đặc trưng 32 chiều

**Nội dung trên slide**

- 32 đặc trưng được trích xuất từ HTTP request.
- 27 đặc trưng gốc bao phủ thống kê ký tự, từ khóa tấn công, tham số HTTP, URL/file và header/hành vi.
- 5 đặc trưng mới tập trung vào URL encoding và obfuscation nhiều tầng.
- Feature vector là đầu vào cho Random Forest, XGBoost, LightGBM và gating network của MoE.
- Mục tiêu là chuyển request dạng text thành biểu diễn số có ý nghĩa bảo mật.

**Gợi ý hình minh họa**

HTTP Request → Feature Extractor → Vector `[f1, f2, ..., f32]` → ML Model.

**Ghi chú thuyết trình**

Thay vì dùng raw text, đề tài dùng feature engineering để mô hình dễ học hơn, chạy nhanh hơn và dễ giải thích hơn qua feature importance.

---

## Slide 14. Nhóm đặc trưng thống kê ký tự

**Nội dung trên slide**

- `input_len`: độ dài chuỗi đầu vào, tấn công thường có payload dài bất thường.
- `alpha_ratio`, `digit_ratio`, `special_ratio`: tỉ lệ chữ, số và ký tự đặc biệt.
- `uppercase_ratio`: phát hiện từ khóa SQL viết hoa như `SELECT`, `UNION`.
- `entropy_score`: đo độ hỗn loạn của chuỗi, hữu ích với payload mã hóa hoặc obfuscation.
- `z_score`: điểm bất thường thống kê, là đặc trưng quan trọng nhất trong thực nghiệm.

**Gợi ý hình minh họa**

So sánh payload bình thường và payload tấn công bằng biểu đồ tỉ lệ ký tự.

**Ghi chú thuyết trình**

Payload tấn công thường khác request bình thường về cấu trúc ký tự. Ví dụ SQLi và XSS chứa nhiều ký tự đặc biệt, từ khóa hoặc chuỗi dài bất thường.

---

## Slide 15. Nhóm đặc trưng từ khóa tấn công

**Nội dung trên slide**

- `sqli_count`: đếm dấu hiệu SQL Injection như `select`, `union`, `' or 1=1`.
- `xss_count`: đếm dấu hiệu XSS như `<script>`, `alert`, `onerror`.
- `path_count`: đếm dấu hiệu Path Traversal như `../`, `%2e%2e`, `/etc/passwd`.
- `cmd_count`: đếm dấu hiệu Command Injection như `;`, `&&`, `|`, `whoami`.
- `php_count`: đếm dấu hiệu PHP injection như `php://`, `eval`, `system`, `exec`.

**Gợi ý hình minh họa**

Bảng keyword theo từng loại tấn công, kèm ví dụ payload rút gọn.

**Ghi chú thuyết trình**

Nhóm đặc trưng này giữ lại ưu điểm của WAF dựa trên luật, nhưng thay vì quyết định cứng, các tín hiệu này được đưa vào mô hình học máy để kết hợp với các đặc trưng khác.

---

## Slide 16. Nhóm đặc trưng tham số, URL và header

**Nội dung trên slide**

- `param_count`: số lượng tham số trong URL hoặc body.
- `max_param_len`: độ dài tham số lớn nhất, thường tăng khi payload được nhồi vào một trường.
- `param_name_entropy`: đo độ bất thường của tên tham số.
- `critical_score`, `is_critical_ext`, `url_penalty`: phát hiện đường dẫn hoặc file nguy hiểm.
- `header_anomaly`, `is_scanner_ua`, `uncommon_method`: phát hiện hành vi scanner, header bất thường hoặc method ít gặp.

**Gợi ý hình minh họa**

Một request được chia thành các vùng: query params, URL path, headers, user-agent.

**Ghi chú thuyết trình**

Một request độc hại không chỉ nằm ở payload. Có những trường hợp tấn công thể hiện ở đường dẫn file, user-agent scanner hoặc HTTP method bất thường.

---

## Slide 17. Năm đặc trưng URL-based mới

**Nội dung trên slide**

| Đặc trưng | Ý nghĩa | Vai trò |
|---|---|---|
| `url_encoding_depth` | Số tầng decode cần thiết để URL ổn định | Phát hiện encoding nhiều tầng |
| `has_double_encoding` | Có chuỗi `%25` trong URL gốc | Dấu hiệu encode lồng nhau |
| `url_sqli_decoded` | Từ khóa SQLi sau khi decode | Phát hiện SQLi bị che giấu |
| `url_xss_decoded` | Từ khóa XSS sau khi decode | Phát hiện XSS bị che giấu |
| `url_path_traversal_decoded` | Dấu hiệu traversal sau khi decode | Phát hiện path traversal encode |

**Gợi ý hình minh họa**

Chuỗi decode nhiều tầng: `%252e%252e%252f` → `%2e%2e%2f` → `../`.

**Ghi chú thuyết trình**

Đây là nhóm feature quan trọng để chống bypass. Trong kết quả feature importance, `url_encoding_depth` đạt 6,79% và `has_double_encoding` đạt 5,02%, đều nằm trong top 10.

---

## Slide 18. Baseline: Random Forest

**Nội dung trên slide**

- Baseline sử dụng Random Forest với 300 cây, độ sâu 30.
- Dữ liệu từ các nguồn được ghép trực tiếp để huấn luyện một mô hình chung.
- `class_weight = {0:1, 1:2}` giúp ưu tiên phát hiện lớp attack.
- Ưu điểm: ổn định, phù hợp dữ liệu tabular, ít yêu cầu chuẩn hóa và dễ giải thích bằng feature importance.
- Hạn chế: chưa xử lý tốt missing feature và distribution shift giữa các dataset.

**Gợi ý hình minh họa**

Nhiều cây quyết định → majority voting → normal/attack.

**Ghi chú thuyết trình**

Random Forest được chọn làm mốc so sánh vì đây là mô hình mạnh cho dữ liệu đặc trưng thủ công. Nếu các phương pháp phức tạp hơn không vượt baseline, cần phân tích nguyên nhân thay vì chỉ tăng độ phức tạp mô hình.

---

## Slide 19. Vấn đề missing feature khi ghép dữ liệu

**Nội dung trên slide**

- Không phải dataset nào cũng có đủ URL đầy đủ, payload và headers.
- Bảy đặc trưng phụ thuộc URL/header có thể bị thiếu ở một số nguồn, đặc biệt là HTTPParam.
- Điền 0 đơn giản có thể làm sai lệch phân phối đặc trưng.
- Ví dụ `url_penalty` có khác biệt lớn giữa normal và attack, nên điền 0 có thể làm mất tín hiệu phân biệt.
- Cần chiến lược Missing Feature Imputation để xử lý đặc trưng thiếu hợp lý hơn.

**Gợi ý hình minh họa**

Ma trận feature có các ô trống, sau đó được điền bằng mean hoặc mean theo lớp.

**Ghi chú thuyết trình**

Missing feature là vấn đề thực tế khi tích hợp nhiều log từ các hệ thống khác nhau. Nếu xử lý không tốt, mô hình có thể học sai rằng thiếu dữ liệu tương đương với giá trị bằng 0.

---

## Slide 20. Missing Feature Imputation

**Nội dung trên slide**

- Baseline zeros: đặc trưng thiếu được điền bằng 0.
- MFI-Mean: điền bằng trung bình toàn cục của từng đặc trưng trên tập train.
- MFI-Class-Conditional: điền bằng trung bình theo từng lớp normal/attack.
- Với `url_penalty`, mean toàn cục là 18,3; mean normal là 0,0; mean attack là 42,7.
- MFI-Class-Conditional cho thấy giá trị của việc bảo toàn quan hệ giữa lớp và đặc trưng; triển khai thực tế có thể ưu tiên MFI-Mean hoặc cơ chế hai bước/pseudo-label.

**Gợi ý hình minh họa**

Bảng so sánh ba cách điền: 0, mean toàn cục, mean theo lớp.

**Ghi chú thuyết trình**

MFI-CC có ý nghĩa thực nghiệm mạnh vì nó cho thấy đặc trưng thiếu không nên bị xử lý như nhau cho mọi mẫu. Tuy nhiên khi triển khai thật, nhãn chưa biết trước nên cần thiết kế cẩn thận.

---

## Slide 21. Mixture of Experts: ý tưởng chính

**Nội dung trên slide**

- MoE gồm nhiều expert model và một cơ chế gating/routing.
- Mỗi expert có thể học tốt hơn trên một vùng dữ liệu hoặc một kiểu phân phối.
- Gating quyết định expert nào đóng góp nhiều hơn vào dự đoán cuối cùng.
- Hard routing chọn một expert chính; soft routing kết hợp xác suất từ nhiều expert.
- MoE phù hợp với bài toán dữ liệu đa nguồn và phân phối dịch chuyển.

**Gợi ý hình minh họa**

Input request → Gating Network → Expert 1, Expert 2, Expert 3 → Weighted Prediction.

**Ghi chú thuyết trình**

Thay vì ép một mô hình học toàn bộ phân phối dữ liệu, MoE chia bài toán cho nhiều chuyên gia. Đây là hướng tự nhiên khi các dataset có cấu trúc và độ khó khác nhau.

---

## Slide 22. Kiến trúc MoE trong đề tài

**Nội dung trên slide**

- Ba expert được sử dụng: Random Forest, XGBoost và LightGBM.
- Expert được calibrate xác suất bằng isotonic regression để gating nhận xác suất đáng tin cậy.
- Quy trình EM-training gồm cold start, E-step và M-step.
- E-step tính soft assignment giữa mẫu và expert dựa trên xác suất dự đoán.
- M-step cập nhật gating và retrain expert theo trọng số mẫu.
- Ba biến thể gating: Logistic, MLP và Sparse Top-K.

**Gợi ý hình minh họa**

Sơ đồ vòng lặp EM: Expert prediction → Soft assignment → Update gating → Retrain experts.

**Ghi chú thuyết trình**

Gating Logistic dễ giải thích, MLP học được routing phi tuyến, còn Sparse Top-K chỉ giữ một số expert quan trọng để giảm nhiễu và tăng hiệu quả tính toán.

---

## Slide 23. Thiết lập thực nghiệm

**Nội dung trên slide**

- Chia dữ liệu train/test 80/20 với stratified sampling.
- Tập 4 nguồn có `n_train = 141.619` và `n_test = 35.405`.
- Ngưỡng quyết định θ = 0,5.
- Metric chính: Accuracy, F1-macro, AUC-ROC.
- Phân tích thêm: số attack bị bỏ sót (missed/FN) và false positive theo từng nguồn.
- F1-macro được ưu tiên vì dữ liệu có mất cân bằng giữa normal và attack.

**Gợi ý hình minh họa**

Bảng metric: Accuracy, F1-macro, AUC-ROC, FN, FP, kèm ý nghĩa ngắn.

**Ghi chú thuyết trình**

Trong WAF, false negative đặc biệt nguy hiểm vì request tấn công có thể đi qua hệ thống. Vì vậy ngoài điểm F1 và AUC, cần nhìn cả số missed attacks.

---

## Slide 24. Kết quả Baseline trên 4 bộ dữ liệu

**Nội dung trên slide**

| Nguồn | n_test | Accuracy | F1-macro | AUC-ROC | Missed | False Pos. |
|---|---:|---:|---:|---:|---:|---:|
| Tổng thể | 35.405 | 96,59% | 0,9650 | 0,9928 | 812 | 396 |
| CSIC 2010 | 12.318 | 97,26% | 0,9715 | 0,9955 | 239 | 98 |
| ECML/PKDD | 4.709 | 87,13% | 0,8706 | 0,9133 | 470 | 136 |
| HTTPParam | 6.091 | 99,84% | 0,9982 | 0,9997 | 4 | 6 |
| Biblio-US17 | 12.287 | 97,92% | 0,9787 | 0,9913 | 99 | 156 |

**Gợi ý hình minh họa**

Stat cards cho Overall Accuracy, F1-macro, AUC-ROC; bên dưới là biểu đồ cột F1 theo dataset.

**Ghi chú thuyết trình**

Baseline đạt kết quả cao tổng thể, nhưng ECML là nguồn khó nhất với F1 chỉ 0,8706. HTTPParam gần như hoàn hảo vì payload tấn công có dấu hiệu rất rõ.

---

## Slide 25. Phân tích feature importance

**Nội dung trên slide**

| Hạng | Đặc trưng | Nhóm | Tầm quan trọng |
|---:|---|---|---:|
| 1 | `z_score` | Tổng hợp | 25,90% |
| 2 | `url_encoding_depth` | URL-based mới | 6,79% |
| 3 | `max_param_len` | Tham số | 6,79% |
| 4 | `input_len` | Ký tự | 6,27% |
| 5 | `special_ratio` | Ký tự | 5,46% |
| 6 | `has_double_encoding` | URL-based mới | 5,02% |
| 7 | `entropy_score` | Ký tự | 5,01% |
| 8 | `uppercase_ratio` | Ký tự | 4,43% |
| 9 | `alpha_ratio` | Ký tự | 4,34% |
| 10 | `param_name_entropy` | Tham số | 4,20% |

**Gợi ý hình minh họa**

Biểu đồ bar chart top 10 features, tô màu nổi bật cho `url_encoding_depth` và `has_double_encoding`.

**Ghi chú thuyết trình**

Kết quả này xác nhận hai điểm: đặc trưng thống kê ký tự rất quan trọng, và nhóm URL-based mới thực sự đóng góp lớn trong bối cảnh có Biblio-US17.

---

## Slide 26. Kết quả Missing Feature Imputation

**Nội dung trên slide**

| Chiến lược | F1-macro | AUC-ROC | Accuracy | F1-CSIC | F1-ECML | F1-HTTPParam |
|---|---:|---:|---:|---:|---:|---:|
| Baseline zeros | 0,9614 | 0,9928 | 96,23% | 0,9762 | 0,8763 | 0,9990 |
| MFI-Mean | 0,9612 | 0,9928 | 96,22% | 0,9756 | 0,8771 | 0,9990 |
| MFI-Class-Conditional | 0,9617 | 0,9930 | 96,26% | 0,9762 | 0,8767 | 1,0000 |

**Gợi ý hình minh họa**

Bảng kết quả + callout “MFI-Class-Conditional đạt AUC-ROC cao nhất 0,9930 và F1 HTTPParam = 1,0000”.

**Ghi chú thuyết trình**

MFI-CC cải thiện nhẹ tổng thể nhưng cho kết quả nổi bật trên HTTPParam. Điều này chứng minh missing feature không phải chi tiết phụ mà có thể ảnh hưởng trực tiếp đến khả năng phân biệt attack.

---

## Slide 27. Kết quả Mixture of Experts

**Nội dung trên slide**

**MoE phiên bản 1 trên 3 bộ dữ liệu**

| Chiến lược | F1-macro | AUC-ROC | Accuracy | F1-ECML | Missed ECML |
|---|---:|---:|---:|---:|---:|
| Baseline RF | 0,9683 | 0,9942 | 96,91% | 0,8751 | 503/2.730 |
| MoE-Hard | 0,9688 | 0,9942 | 96,95% | 0,8765 | 497/2.730 |
| MoE-Soft | 0,9691 | 0,9914 | 96,97% | 0,8771 | 484/2.730 |

**MoE phiên bản 2 với gating học được**

- Baseline-RF đạt F1-macro cao nhất trong nhóm v2: 0,9651.
- MoE-MLP đạt F1-ECML cao nhất trong nhóm v2: 0,8709.
- Rule-Router có missed ECML cao nhất: 492.
- MoE chưa vượt baseline mạnh, nhưng cho thấy tiềm năng khi dữ liệu có domain khác biệt rõ hơn.

**Gợi ý hình minh họa**

Biểu đồ cột so sánh F1-macro giữa Baseline, MoE-Hard và MoE-Soft; bên cạnh là sơ đồ gating network.

**Ghi chú thuyết trình**

MoE-Soft giúp giảm số attack ECML bị bỏ sót từ 503 xuống 484, tương đương giảm khoảng 3,8%. Tuy nhiên ở MoE v2, baseline vẫn mạnh nhất do mỗi expert yếu hơn và số vòng EM còn ít.

---

## Slide 28. Thiết kế triển khai production, kết luận và Q&A

**Nội dung trên slide**

**Triển khai production**

- FastAPI WAF Server nạp model `.pkl` và cung cấp `/predict`, `/health`, `/benchmark`.
- Nginx Reverse Proxy dùng `auth_request` để hỏi WAF trước khi chuyển request đến backend.
- Backend Flask không cần biết sự tồn tại của WAF.
- Latency trung bình 2,8 ms: 0,12 ms trích xuất đặc trưng, 2,52 ms inference, 0,16 ms overhead.
- Throughput trên 350 request/giây; hỗ trợ cấu hình threshold và model qua biến môi trường.

**Kết luận**

- Đề tài đã xây dựng pipeline WAF học máy cho dữ liệu HTTP đa nguồn.
- Bộ đặc trưng 32 chiều có khả năng phân biệt tốt, đặc biệt nhóm URL-based mới có đóng góp rõ rệt.
- Baseline Random Forest đạt F1-macro 0,9650 và AUC-ROC 0,9928 trên 4 bộ dữ liệu.
- MFI giúp phân tích và xử lý vấn đề đặc trưng thiếu.
- MoE-Soft cải thiện F1 và giảm missed attacks trên ECML trong thí nghiệm 3 nguồn.
- Hướng phát triển: bổ sung dữ liệu thực tế, tối ưu giảm false negative, mở rộng expert theo từng loại tấn công, thử deep learning/transformer cho HTTP text và triển khai online learning.

**Gợi ý hình minh họa**

Sơ đồ deployment Client → Nginx → WAF API → Backend, dưới cùng là dòng “Cảm ơn thầy/cô và các bạn đã lắng nghe – Q&A”.

**Ghi chú thuyết trình**

Kết luận chính là feature engineering vẫn rất hiệu quả cho WAF thời gian thực, đặc biệt khi yêu cầu latency thấp. Kiến trúc MoE là hướng tiềm năng, nhưng cần thêm dữ liệu/domain rõ ràng hơn để phát huy lợi thế so với baseline mạnh như Random Forest.

---

## Gợi ý phân bổ thời gian trình bày

- Slide 1–2: 30 giây, giới thiệu đề tài và mục lục.
- Slide 3–6: 2 phút, bối cảnh, hạn chế WAF truyền thống, vấn đề và đóng góp.
- Slide 7–12: 3 phút, kiến trúc hệ thống, dữ liệu và tiền xử lý.
- Slide 13–17: 3 phút, bộ đặc trưng 32 chiều, nhấn mạnh URL-based features.
- Slide 18–22: 3 phút, Baseline, MFI và MoE.
- Slide 23–27: 4 phút, thiết lập và kết quả thực nghiệm.
- Slide 28: 1–2 phút, triển khai, kết luận và Q&A.

## Gợi ý slide backup nếu giảng viên hỏi sâu

- Backup 1: công thức F1-macro, AUC-ROC và ý nghĩa trong bài toán mất cân bằng.
- Backup 2: chi tiết thuật toán full URL decode và ví dụ double encoding.
- Backup 3: confusion matrix tổng thể của baseline.
- Backup 4: chi tiết EM-training cho MoE.
- Backup 5: phân tích lỗi trên ECML vì đây là dataset khó nhất.
