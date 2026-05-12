# WAF Server — Nginx Integration Guide

FastAPI server kết hợp với Nginx để chạy WAF ML-based trong thực tế.

---

## Kiến trúc

```
Client
  │  HTTP request (port 80)
  ▼
Nginx ──── auth_request /waf-check (subrequest) ────► WAF Server :8000/auth
  │                                                          │
  │  verdict = NORMAL (HTTP 200)              chạy ML model (RandomForest)
  │                                                          │
  ▼                                       verdict = ATTACK (HTTP 403)
Backend App :PORT                                          │
  │                                               Nginx trả 403
  ▼                                           "Blocked by WAF" page
Client nhận response bình thường
```

**Luồng xử lý cho mỗi request:**
1. Client gửi request đến Nginx (port 80)
2. Nginx gửi subrequest đến `/waf-check` (internal location)
3. `/waf-check` proxy đến WAF server endpoint `/auth` với metadata của request gốc
4. WAF server trích xuất 27 feature, chạy model, trả `200` (normal) hoặc `403` (attack)
5. Nếu `200`: Nginx proxy request đến backend app
6. Nếu `403`: Nginx trả trang "Blocked by WAF" cho client

---

## Cấu trúc file

```
waf_server/
├── app.py                    ← FastAPI server (load model, /auth, /predict, /scan, /benchmark)
├── templates/
│   ├── index.html            ← UI test thủ công
│   └── blocked.html          ← Trang 403 khi bị chặn (endpoint /scan)
├── sample_payloads.json      ← 17 payload mẫu (SQLi, XSS, path traversal, ...)
├── test_payloads.py          ← CLI test client
├── requirements.txt
└── logs/
    ├── requests.log          ← Log mọi HTTP request đến WAF server
    └── predictions.jsonl     ← Log từng prediction (JSON mỗi dòng)

Ngnix tren WAF/
└── waf.conf                  ← Nginx config với auth_request integration
```

---

## Cài đặt

### 1. WAF Python server

```bash
cd "D:\Project 3\Code xử lí"
pip install -r waf_server/requirements.txt
```

### 2. Nginx (Ubuntu/Debian)

```bash
sudo apt install nginx
# Kiểm tra module auth_request (thường đã có sẵn)
nginx -V 2>&1 | grep auth_request
```

---

## Chạy

### WAF server

```bash
# Từ thư mục gốc (để import features/, config/)
cd "D:\Project 3\Code xử lí"
python -m uvicorn waf_server.app:app --host 0.0.0.0 --port 8000
```

**Biến môi trường tùy chọn:**

| Biến | Mặc định | Mô tả |
|------|----------|-------|
| `WAF_MODEL_PATH` | `waf_model_final_v6.pkl` | Đường dẫn file model |
| `WAF_THRESHOLD` | `0.50` | Ngưỡng xác suất để phân loại ATTACK |
| `WAF_HOST` | `127.0.0.1` | Host WAF server lắng nghe |
| `WAF_PORT` | `8000` | Port WAF server |
| `WAF_WHITELIST_IPS` | _(rỗng)_ | Danh sách IP bypass WAF (cách nhau dấu phẩy) |
| `WAF_BLACKLIST_IPS` | _(rỗng)_ | Danh sách IP bị chặn luôn (không qua model) |

**Ví dụ với IP lists:**
```bash
set WAF_WHITELIST_IPS=127.0.0.1,10.0.0.5
set WAF_BLACKLIST_IPS=1.2.3.4
python -m uvicorn waf_server.app:app --host 0.0.0.0 --port 8000
```

### Nginx

```bash
# Sao chép config
sudo cp "Ngnix tren WAF/waf.conf" /etc/nginx/sites-available/waf.conf

# !!! QUAN TRỌNG: Chỉnh địa chỉ backend trong waf.conf
# upstream app_backend { server 127.0.0.1:3000; }  ← đổi port này

# Kích hoạt
sudo ln -s /etc/nginx/sites-available/waf.conf /etc/nginx/sites-enabled/
sudo nginx -t                    # kiểm tra syntax
sudo systemctl reload nginx
```

---

## Endpoints WAF server

| Method | Path | Mục đích |
|--------|------|----------|
| `ANY` | `/auth` | **Nginx auth_request** — trả 200/403 + X-WAF-* headers |
| `GET` | `/` | UI test thủ công |
| `GET` | `/health` | Trạng thái server, model info, IP lists |
| `GET` | `/payloads` | Danh sách payload mẫu |
| `POST` | `/predict` | Test thủ công: `{method, url, payload, headers}` → verdict |
| `POST` | `/benchmark` | Đo latency trên toàn bộ payload mẫu |
| `ANY` | `/scan/{path}` | Bắt request thật → quét → 200 or 403 (demo) |

### Endpoint `/auth` — chi tiết

Nginx cần set các header sau trong location `/waf-check`:

```nginx
proxy_set_header X-Original-URI    $request_uri;
proxy_set_header X-Original-Method $request_method;
proxy_set_header X-Original-IP     $remote_addr;
proxy_set_header X-Original-UA     $http_user_agent;
proxy_set_header X-Original-Ref    $http_referer;
proxy_set_header X-Original-Cookie $http_cookie;
proxy_set_header X-Original-Host   $host;
```

Response headers từ `/auth` (nginx dùng `auth_request_set` để capture):

| Header | Giá trị |
|--------|---------|
| `X-WAF-Verdict` | `NORMAL` / `ATTACK` / `WHITELIST` / `BLACKLIST` |
| `X-WAF-Probability` | Xác suất tấn công `0.0` – `1.0` |
| `X-WAF-Request-ID` | ID để trace log |
| `X-WAF-Extract-Ms` | Thời gian trích feature (ms) |
| `X-WAF-Predict-Ms` | Thời gian predict (ms) |

---

## Test end-to-end

### 1. Test WAF server trực tiếp

```bash
# Normal request
curl http://127.0.0.1:8000/auth \
  -H "X-Original-URI: /index.php" \
  -H "X-Original-Method: GET" \
  -H "X-Original-IP: 192.168.1.1" \
  -H "X-Original-UA: Mozilla/5.0"
# → HTTP 200, X-WAF-Verdict: NORMAL

# SQLi attack
curl http://127.0.0.1:8000/auth \
  -H "X-Original-URI: /login?user=admin'+OR+1=1--" \
  -H "X-Original-Method: GET" \
  -H "X-Original-IP: 1.2.3.4"
# → HTTP 403, X-WAF-Verdict: ATTACK
```

### 2. Test qua Nginx (end-to-end)

```bash
# Normal request → phải đến được backend
curl -v http://your-server/

# SQLi attack → phải bị chặn với 403
curl -v "http://your-server/login?id=1%20UNION%20SELECT%20*%20FROM%20users"

# XSS attack → bị chặn
curl -v "http://your-server/search?q=<script>alert(1)</script>"
```

### 3. Kiểm tra Nginx log

```bash
sudo tail -f /var/log/nginx/waf_access.log
# Ví dụ output:
# 1.2.3.4 [01/Jan/2026:10:00:00 +0000] "GET /login?id=1 UNION SELECT HTTP/1.1"
#   403 1234 waf="ATTACK" prob="0.9876" rid="a1b2c3d4" rt=0.003
```

### 4. Kiểm tra predictions log

```bash
# Tất cả attack gần đây
grep "ATTACK" waf_server/logs/predictions.jsonl | tail -20

# Parse với Python
python -c "
import json
with open('waf_server/logs/predictions.jsonl') as f:
    for line in f:
        r = json.loads(line)
        if r['verdict'] == 'ATTACK':
            print(r['ts'], r['client_ip'], r['input']['url'][:60])
"
```

---

## Cấu hình fail-open vs fail-closed

Khi WAF server down, Nginx có hai chiến lược (trong `waf.conf`):

**Fail-open** (mặc định): traffic vẫn qua, ghi log cảnh báo
```nginx
location @waf_failopen {
    proxy_pass http://app_backend;
    add_header X-WAF-Verdict "WAF-ERROR-FAILOPEN" always;
}
```

**Fail-closed** (an toàn hơn): chặn tất cả khi WAF lỗi
```nginx
# Thay thế nội dung location @waf_failopen:
    return 503 '{"error":"Service Unavailable","message":"WAF unavailable"}';
    add_header Content-Type "application/json" always;
```

---

## 27 features được trích xuất

`input_len`, `alpha_ratio`, `special_ratio`, `raw_ratio`, `z_score`,
`sqli_count`, `xss_count`, `path_count`, `cmd_count`, `php_count`,
`probing_kw_count`, `param_count`, `max_param_len`, `uppercase_ratio`,
`digit_ratio`, `entropy_score`, `critical_score`, `is_critical_ext`,
`files_weight`, `url_penalty`, `manipulate_weight`, `header_anomaly`,
`uncommon_method`, `is_empty_probe`, `extra_header_risk`,
`is_scanner_ua`, `param_name_entropy`
