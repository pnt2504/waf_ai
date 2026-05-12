# 🧪 Hướng dẫn test ML WAF từng bước

## Kiến trúc

```
curl/Browser
     │
     ▼ port 80
 [Nginx]  ──── subrequest ────►  [WAF Server :8000]
     │                            RandomForest model
     │  200 NORMAL                      │
     ▼                           403 ATTACK
 [Backend :5000]                        │
     │                           trả JSON blocked
     ▼
 response bình thường
```

---

## Bước 1 — Kiểm tra yêu cầu

```bash
docker --version       # cần Docker 20+
docker compose version # cần Compose v2
curl --version
python3 --version      # cần để chạy test script
```

---

## Bước 2 — Build & khởi động

```bash
# Từ thư mục gốc dự án (không phải trong lab/)
cd lab
docker compose up -d --build
```

Lần đầu build sẽ mất 2–3 phút (tải Python image + cài dependencies).

---

## Bước 3 — Xác nhận tất cả service đang chạy

```bash
docker compose ps
```

Kết quả mong đợi:
```
NAME            STATUS          PORTS
lab-nginx       running         0.0.0.0:80->80/tcp
lab-waf         running(healthy) 0.0.0.0:8000->8000/tcp
lab-backend     running         0.0.0.0:5001->5000/tcp
```

> Nếu `lab-waf` vẫn đang `starting`, đợi thêm 15–20 giây rồi chạy lại.

---

## Bước 4 — Kiểm tra WAF server

```bash
# Health check — xem model đang load
curl http://localhost:8000/health | python3 -m json.tool
```

Kết quả mong đợi:
```json
{
    "status": "ok",
    "model": {
        "type": "RandomForestClassifier",
        "path": "waf_model_final_v6.pkl",
        "n_features": 27,
        "threshold": 0.5
    }
}
```

---

## Bước 5 — Test thủ công WAF server (không qua Nginx)

Gọi trực tiếp endpoint `/predict` với JSON:

```bash
# ✅ Request bình thường — phải trả NORMAL
curl -s -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","url":"/search?q=python","payload":"","headers":{"user_agent":"Mozilla/5.0"}}' \
  | python3 -m json.tool

# 🚨 SQL Injection — phải trả ATTACK
curl -s -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","url":"/login?id='"'"' OR '"'"'1'"'"'='"'"'1","payload":"","headers":{"user_agent":"Mozilla/5.0"}}' \
  | python3 -m json.tool

# 🚨 XSS — phải trả ATTACK
curl -s -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","url":"/search?q=<script>alert(1)</script>","payload":"","headers":{"user_agent":"Mozilla/5.0"}}' \
  | python3 -m json.tool

# 🚨 Path traversal — phải trả ATTACK
curl -s -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","url":"/file?name=../../../etc/passwd","payload":"","headers":{"user_agent":"Mozilla/5.0"}}' \
  | python3 -m json.tool
```

Response mẫu khi phát hiện attack:
```json
{
    "verdict": "ATTACK",
    "is_attack": true,
    "attack_probability": 0.9823,
    "threshold": 0.5,
    "features": { "sqli_count": 3, "z_score": 1450, ... },
    "timing_ms": { "extract": 0.12, "predict": 2.4, "total": 2.52 }
}
```

---

## Bước 6 — Test end-to-end qua Nginx (auth_request)

```bash
# ✅ Request bình thường — HTTP 200, qua được backend
curl -v http://localhost:8080/

# Kiểm tra WAF headers trong response:
# < X-WAF-Verdict: NORMAL
# < X-WAF-Probability: 0.03

# 🚨 SQL Injection — HTTP 403, bị chặn
curl -v "http://localhost:8080/login?id=%27+OR+%271%27%3D%271"
# < HTTP/1.1 403
# < X-WAF-Verdict: ATTACK
# Body: {"blocked":true,"verdict":"ATTACK","probability":"0.98",...}

# 🚨 XSS — HTTP 403
curl -v "http://localhost:8080/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

# 🚨 LFI — HTTP 403
curl -v "http://localhost:8080/file?name=..%2F..%2Fetc%2Fpasswd"

# 🚨 Scanner UA — HTTP 403
curl -v http://localhost:8080/ -H "User-Agent: sqlmap/1.7"

# ✅ Direct backend (bypass WAF) — HTTP 200, app không tự chặn
curl -v "http://localhost:5001/login?id=%27+OR+%271%27%3D%271"
```

---

## Bước 7 — Chạy test script tự động

```bash
# Từ thư mục lab/
bash test_waf_ml.sh
```

Script sẽ chạy 40+ test cases qua 3 lớp:
- **Layer 1** — gọi `/predict` trực tiếp → kiểm tra verdict ATTACK/NORMAL
- **Layer 2** — gọi qua Nginx port 80 → kiểm tra HTTP 200/403
- **Layer 3** — benchmark 17 sample payload chính thức → accuracy + latency

---

## Bước 8 — Chạy benchmark chính thức

```bash
# Benchmark 17 payload trong sample_payloads.json, mỗi cái 3 lần
curl -s -X POST http://localhost:8000/benchmark \
  -H "Content-Type: application/json" \
  -d '{"repeat": 3}' \
  | python3 -m json.tool

# Hoặc dùng script Python có sẵn (từ thư mục gốc dự án)
cd ..
python3 waf_server/test_payloads.py --server http://localhost:8000 --repeat 3
```

---

## Bước 9 — Xem logs

```bash
# Nginx access log với WAF verdict
tail -f lab/nginx/logs/waf_access.log
# 127.0.0.1 [11/May/2026] "GET /login?id=' OR..." 403 waf="ATTACK" prob="0.98" rt=0.003s

# WAF server logs realtime
docker compose logs -f waf

# Predictions log (mỗi dòng là 1 JSON)
tail -f ../waf_server/logs/predictions.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    r = json.loads(line)
    print(f\"{r['verdict']:6s}  p={r['probability']:.4f}  {r['input']['method']} {r['input']['url'][:60]}\")
"
```

---

## Bước 10 — Thử nghiệm các model khác

```bash
# Xem danh sách model
ls ../*.pkl

# Đổi sang XGBoost
WAF_MODEL_PATH=/app/waf_model_xgboost_v2.pkl docker compose up -d waf

# Đổi threshold (nhạy hơn → bắt nhiều hơn nhưng FP tăng)
WAF_THRESHOLD=0.40 docker compose up -d waf

# Đổi sang Detection Mode (chỉ log, không chặn)
# Sửa docker-compose.yml: thêm MODSEC_RULE_ENGINE: DetectionOnly
```

---

## Dừng lab

```bash
docker compose down
```

---

## Troubleshooting

| Vấn đề | Nguyên nhân | Giải pháp |
|--------|-------------|-----------|
| `lab-waf` status `starting` mãi | Model load lâu | Đợi 30s, xem `docker compose logs waf` |
| Port 80 bị chiếm | Có app khác dùng port 80 | `docker compose down` app kia, hoặc đổi port trong `docker-compose.yml` |
| `403` cho request bình thường | False positive, threshold quá thấp | Thử `WAF_THRESHOLD=0.60` |
| WAF trả `NORMAL` cho attack | Model chưa học pattern này | Xem `missed_attacks.json`, retrain thêm data |
