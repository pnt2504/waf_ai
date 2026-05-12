# =============================================================================
# waf_server/app.py
# FastAPI server để test model WAF (.pkl) ở local
#
# Tính năng:
#   1. Load model RandomForest từ waf_model_final_v6.pkl (hoặc model khác)
#   2. Trích xuất 27 feature từ HTTP request (qua FeatureExtractor)
#   3. Log mỗi request vào file logs/requests.log + console
#   4. Đo thời gian: extract / predict / total (ms)
#   5. Endpoints:
#       - GET  /            : UI HTML đơn giản để test
#       - POST /predict     : Nhận JSON {method, url, payload, headers} → verdict
#       - POST /scan        : Bắt mọi method/path bất kỳ → quét request thật
#       - GET  /payloads    : Trả về bộ payload mẫu (SQLi, XSS, ...)
#       - POST /benchmark   : Chạy hàng loạt payload mẫu, đo latency trung bình
#       - GET  /health      : Health check + thông tin model
# =============================================================================
from __future__ import annotations

import json
import logging
import os
import pickle
import statistics
import sys
import time
import uuid
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import numpy as np
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

# --- Cho phép import features/, model/, config/ từ thư mục cha ---
THIS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = THIS_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))

from features.extractor import FeatureExtractor  # noqa: E402

# =============================================================================
# Config
# =============================================================================
MODEL_PATH = os.environ.get(
    "WAF_MODEL_PATH",
    str(PROJECT_ROOT / "waf_model_final_v6.pkl"),
)
ATTACK_THRESHOLD = float(os.environ.get("WAF_THRESHOLD", "0.50"))
PAYLOADS_PATH = THIS_DIR / "sample_payloads.json"
LOG_DIR = THIS_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

# =============================================================================
# IP Lists — dùng cho endpoint /auth (nginx auth_request)
# Cấu hình qua env var, cách nhau dấu phẩy:
#   WAF_WHITELIST_IPS=127.0.0.1,10.0.0.5     → bypass WAF hoàn toàn
#   WAF_BLACKLIST_IPS=1.2.3.4,5.6.7.8        → chặn ngay, không qua model
# =============================================================================
def _parse_ip_list(env_var: str) -> set[str]:
    raw = os.environ.get(env_var, "")
    return {ip.strip() for ip in raw.split(",") if ip.strip()}

IP_WHITELIST: set[str] = _parse_ip_list("WAF_WHITELIST_IPS")
IP_BLACKLIST: set[str] = _parse_ip_list("WAF_BLACKLIST_IPS")

# =============================================================================
# Logging
# =============================================================================
logger = logging.getLogger("waf_server")
logger.setLevel(logging.INFO)

_console = logging.StreamHandler()
_console.setFormatter(logging.Formatter(
    "[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
))
logger.addHandler(_console)

_file = RotatingFileHandler(
    LOG_DIR / "requests.log",
    maxBytes=5_000_000,
    backupCount=3,
    encoding="utf-8",
)
_file.setFormatter(logging.Formatter(
    "%(asctime)s\t%(levelname)s\t%(message)s",
))
logger.addHandler(_file)

# Logger riêng cho predictions (mỗi dòng là 1 JSON record để dễ phân tích)
pred_logger = logging.getLogger("waf_predictions")
pred_logger.setLevel(logging.INFO)
pred_logger.propagate = False
_pred_file = RotatingFileHandler(
    LOG_DIR / "predictions.jsonl",
    maxBytes=10_000_000,
    backupCount=5,
    encoding="utf-8",
)
_pred_file.setFormatter(logging.Formatter("%(message)s"))
pred_logger.addHandler(_pred_file)

# =============================================================================
# Load model
# =============================================================================
if IP_WHITELIST:
    logger.info(f"IP Whitelist ({len(IP_WHITELIST)} entries): {IP_WHITELIST}")
if IP_BLACKLIST:
    logger.info(f"IP Blacklist ({len(IP_BLACKLIST)} entries): {IP_BLACKLIST}")

logger.info(f"Đang load model từ: {MODEL_PATH}")
with open(MODEL_PATH, "rb") as f:
    MODEL = pickle.load(f)
logger.info(
    f"Đã load model: {type(MODEL).__name__} "
    f"({getattr(MODEL, 'n_features_in_', '?')} features, "
    f"threshold={ATTACK_THRESHOLD})"
)

EXTRACTOR = FeatureExtractor()
FEATURE_NAMES = EXTRACTOR.feature_names

# Bộ payload mẫu
SAMPLE_PAYLOADS: list[dict] = []
if PAYLOADS_PATH.exists():
    with open(PAYLOADS_PATH, encoding="utf-8") as f:
        SAMPLE_PAYLOADS = json.load(f)
    logger.info(f"Đã load {len(SAMPLE_PAYLOADS)} payload mẫu")


# =============================================================================
# Schema
# =============================================================================
class RequestEntry(BaseModel):
    """Định dạng entry giống biblio_sample.json mà extractor cần."""

    method: str = Field("GET", description="HTTP method")
    url: str = Field(..., description="URL đầy đủ, có thể chứa query string")
    payload: str = Field("", description="Body của POST/PUT (rỗng nếu GET)")
    headers: dict[str, Any] = Field(
        default_factory=dict,
        description="Dict header: user_agent, referer, cookie, content_type, ..."
    )


class PredictResponse(BaseModel):
    request_id: str
    verdict: str               # "ATTACK" | "NORMAL"
    is_attack: bool
    attack_probability: float
    threshold: float
    features: dict[str, float]
    timing_ms: dict[str, float]


# =============================================================================
# Core helpers
# =============================================================================
def predict_entry(entry: dict) -> dict:
    """Trích feature → predict → trả dict đầy đủ kèm timing (ms)."""
    t0 = time.perf_counter()
    feats = EXTRACTOR.extract(entry)
    t1 = time.perf_counter()

    X = np.asarray(feats, dtype=float).reshape(1, -1)
    proba = float(MODEL.predict_proba(X)[0, 1])
    t2 = time.perf_counter()

    is_attack = proba >= ATTACK_THRESHOLD
    return {
        "verdict": "ATTACK" if is_attack else "NORMAL",
        "is_attack": is_attack,
        "attack_probability": proba,
        "threshold": ATTACK_THRESHOLD,
        "features": dict(zip(FEATURE_NAMES, [float(v) for v in feats])),
        "timing_ms": {
            "extract": round((t1 - t0) * 1000, 3),
            "predict": round((t2 - t1) * 1000, 3),
            "total":   round((t2 - t0) * 1000, 3),
        },
    }


def headers_from_request(req: Request) -> dict:
    """Map HTTP header thật → dict mà extractor mong đợi (snake_case)."""
    h = req.headers
    return {
        "user_agent":      h.get("user-agent", "-"),
        "referer":         h.get("referer", "-"),
        "cookie":          h.get("cookie", "-"),
        "content_type":    h.get("content-type", "-"),
        "authorization":   h.get("authorization", "-"),
        "x_forwarded_for": h.get("x-forwarded-for", "-"),
        "host":            h.get("host", "-"),
        "accept":          h.get("accept", "-"),
        "accept_language": h.get("accept-language", "-"),
        "accept_charset":  h.get("accept-charset", "-"),
        "accept_encoding": h.get("accept-encoding", "-"),
        "cache_control":   h.get("cache-control", "-"),
        "pragma":          h.get("pragma", "-"),
        "connection":      h.get("connection", "-"),
    }


# =============================================================================
# FastAPI app
# =============================================================================
app = FastAPI(
    title="WAF Model Server",
    description=(
        "WAF inference server tích hợp với Nginx auth_request.\n\n"
        "Kiến trúc: Client → Nginx (80) → [auth_request /waf-check] → "
        "WAF Server (8000/auth) → 200 ALLOW hoặc 403 BLOCK\n\n"
        "Endpoints chính:\n"
        "- POST /auth  : dành cho nginx auth_request (trả 200/403 + X-WAF-* headers)\n"
        "- POST /predict : test thủ công qua JSON\n"
        "- ANY  /scan/... : bắt request thật (demo WAF inline)\n"
    ),
    version="2.0.0",
)
templates = Jinja2Templates(directory=str(THIS_DIR / "templates"))


@app.middleware("http")
async def log_request_middleware(request: Request, call_next):
    """Log mọi HTTP request gửi đến server."""
    start = time.perf_counter()
    rid = str(uuid.uuid4())[:8]
    request.state.request_id = rid

    logger.info(
        f"[{rid}] → {request.method} {request.url.path}"
        f"{('?' + request.url.query) if request.url.query else ''}  "
        f"client={request.client.host if request.client else '?'}"
    )

    try:
        response = await call_next(request)
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        logger.exception(f"[{rid}] ✗ {e}  ({elapsed:.1f} ms)")
        raise

    elapsed = (time.perf_counter() - start) * 1000
    logger.info(
        f"[{rid}] ← {response.status_code}  ({elapsed:.1f} ms)"
    )
    response.headers["x-request-id"] = rid
    response.headers["x-elapsed-ms"] = f"{elapsed:.2f}"
    return response


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "model_name": type(MODEL).__name__,
            "n_features": getattr(MODEL, "n_features_in_", "?"),
            "threshold": ATTACK_THRESHOLD,
            "model_path": Path(MODEL_PATH).name,
            "n_payloads": len(SAMPLE_PAYLOADS),
        },
    )


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "model": {
            "type": type(MODEL).__name__,
            "path": Path(MODEL_PATH).name,
            "n_features": getattr(MODEL, "n_features_in_", None),
            "n_estimators": getattr(MODEL, "n_estimators", None),
            "threshold": ATTACK_THRESHOLD,
        },
        "ip_lists": {
            "whitelist_count": len(IP_WHITELIST),
            "blacklist_count": len(IP_BLACKLIST),
        },
        "feature_names": FEATURE_NAMES,
    }


@app.get("/payloads")
async def payloads():
    return SAMPLE_PAYLOADS


@app.post("/predict", response_model=PredictResponse)
async def predict(entry: RequestEntry, request: Request):
    """
    Predict cho 1 request entry (định dạng JSON {method, url, payload, headers}).
    """
    rid = getattr(request.state, "request_id", "-")
    result = predict_entry(entry.model_dump())

    pred_logger.info(json.dumps({
        "ts": time.time(),
        "request_id": rid,
        "endpoint": "/predict",
        "input": entry.model_dump(),
        "verdict": result["verdict"],
        "probability": result["attack_probability"],
        "timing_ms": result["timing_ms"],
    }, ensure_ascii=False))

    logger.info(
        f"[{rid}] PREDICT verdict={result['verdict']}  "
        f"p={result['attack_probability']:.4f}  "
        f"extract={result['timing_ms']['extract']}ms  "
        f"predict={result['timing_ms']['predict']}ms"
    )
    return {"request_id": rid, **result}


@app.post("/benchmark")
async def benchmark(request: Request):
    """
    Chạy toàn bộ payload mẫu qua model, trả về thống kê thời gian phản hồi.
    Body (optional): {"repeat": 3}  → mỗi payload chạy nhiều lần để đo ổn định.
    """
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    repeat = int(body.get("repeat", 1)) if isinstance(body, dict) else 1

    if not SAMPLE_PAYLOADS:
        raise HTTPException(404, "Không tìm thấy sample_payloads.json")

    extract_times, predict_times, total_times = [], [], []
    detail = []
    correct = 0
    confusion = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

    for sample in SAMPLE_PAYLOADS:
        expected = sample.get("expected_label", None)  # 1=attack, 0=normal
        for _ in range(max(1, repeat)):
            r = predict_entry(sample["entry"])
            extract_times.append(r["timing_ms"]["extract"])
            predict_times.append(r["timing_ms"]["predict"])
            total_times.append(r["timing_ms"]["total"])

            if expected is not None:
                pred = 1 if r["is_attack"] else 0
                if pred == expected:
                    correct += 1
                if expected == 1 and pred == 1:   confusion["TP"] += 1
                elif expected == 0 and pred == 0: confusion["TN"] += 1
                elif expected == 0 and pred == 1: confusion["FP"] += 1
                elif expected == 1 and pred == 0: confusion["FN"] += 1

        detail.append({
            "name": sample.get("name"),
            "category": sample.get("category"),
            "expected": expected,
            "verdict": r["verdict"],
            "probability": round(r["attack_probability"], 4),
            "total_ms": r["timing_ms"]["total"],
        })

    def _stats(arr):
        return {
            "min":   round(min(arr), 3),
            "max":   round(max(arr), 3),
            "mean":  round(statistics.mean(arr), 3),
            "median":round(statistics.median(arr), 3),
            "p95":   round(sorted(arr)[int(0.95 * (len(arr) - 1))], 3),
        }

    n = len(extract_times)
    summary = {
        "n_runs": n,
        "n_payloads": len(SAMPLE_PAYLOADS),
        "repeat": repeat,
        "timing_ms": {
            "extract": _stats(extract_times),
            "predict": _stats(predict_times),
            "total":   _stats(total_times),
        },
    }
    if any(s.get("expected_label") is not None for s in SAMPLE_PAYLOADS):
        labelled = sum(1 for s in SAMPLE_PAYLOADS if s.get("expected_label") is not None) * repeat
        summary["accuracy"] = round(correct / labelled, 4) if labelled else None
        summary["confusion"] = confusion

    rid = getattr(request.state, "request_id", "-")
    logger.info(
        f"[{rid}] BENCHMARK n={n}  "
        f"avg_total={summary['timing_ms']['total']['mean']}ms  "
        f"p95={summary['timing_ms']['total']['p95']}ms"
    )
    return {"summary": summary, "detail": detail}


# =============================================================================
# /auth  — endpoint dành riêng cho nginx auth_request
# =============================================================================
@app.api_route(
    "/auth",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def nginx_auth(request: Request):
    """
    Nginx gửi subrequest đến đây TRƯỚC mỗi request thật (qua auth_request).

    Nginx phải set các header sau trong location /waf-check:
        proxy_set_header X-Original-URI    $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Original-IP     $remote_addr;
        proxy_set_header X-Original-UA     $http_user_agent;
        proxy_set_header X-Original-Ref    $http_referer;
        proxy_set_header X-Original-Cookie $http_cookie;
        proxy_set_header X-Original-Host   $host;

    Response:
        200  → Nginx cho request đi tiếp đến backend
        403  → Nginx chặn request, trả 403 cho client

    Response headers (nginx dùng auth_request_set để capture):
        X-WAF-Verdict      : NORMAL | ATTACK | WHITELIST | BLACKLIST
        X-WAF-Probability  : xác suất tấn công (0.0 – 1.0)
        X-WAF-Request-ID   : request ID để trace
    """
    rid = getattr(request.state, "request_id", "-")
    h = request.headers

    # Lấy IP client (nginx đặt vào X-Original-IP)
    client_ip = h.get("x-original-ip") or (
        request.client.host if request.client else ""
    )

    # ------------------------------------------------------------------
    # 1. IP Whitelist: bỏ qua WAF, cho qua ngay
    # ------------------------------------------------------------------
    if client_ip and client_ip in IP_WHITELIST:
        logger.info(f"[{rid}] AUTH WHITELIST  ip={client_ip}")
        return Response(
            status_code=200,
            headers={
                "X-WAF-Verdict":     "WHITELIST",
                "X-WAF-Probability": "0.0",
                "X-WAF-Request-ID":  rid,
            },
        )

    # ------------------------------------------------------------------
    # 2. IP Blacklist: chặn ngay, không cần chạy model
    # ------------------------------------------------------------------
    if client_ip and client_ip in IP_BLACKLIST:
        logger.warning(f"[{rid}] AUTH BLACKLIST  ip={client_ip}")
        return Response(
            status_code=403,
            headers={
                "X-WAF-Verdict":     "BLACKLIST",
                "X-WAF-Probability": "1.0",
                "X-WAF-Request-ID":  rid,
            },
        )

    # ------------------------------------------------------------------
    # 3. Build entry từ headers do nginx truyền
    # ------------------------------------------------------------------
    original_uri    = h.get("x-original-uri", "/")
    original_method = h.get("x-original-method", request.method)

    # Đọc body (nginx proxy_pass_request_body on)
    raw_body  = await request.body()
    body_text = raw_body.decode("utf-8", errors="replace") if raw_body else ""

    entry = {
        "method":  original_method,
        "url":     original_uri,
        "payload": body_text,
        "headers": {
            "user_agent":      h.get("x-original-ua",     h.get("user-agent", "-")),
            "referer":         h.get("x-original-ref",    h.get("referer", "-")),
            "cookie":          h.get("x-original-cookie", h.get("cookie", "-")),
            "content_type":    h.get("content-type", "-"),
            "authorization":   h.get("authorization", "-"),
            "x_forwarded_for": h.get("x-forwarded-for", client_ip or "-"),
            "host":            h.get("x-original-host",  h.get("host", "-")),
            "accept":          h.get("accept", "-"),
            "accept_language": h.get("accept-language", "-"),
            "accept_charset":  h.get("accept-charset", "-"),
            "accept_encoding": h.get("accept-encoding", "-"),
            "cache_control":   h.get("cache-control", "-"),
            "pragma":          h.get("pragma", "-"),
            "connection":      h.get("connection", "-"),
        },
    }

    # ------------------------------------------------------------------
    # 4. Predict
    # ------------------------------------------------------------------
    result = predict_entry(entry)

    pred_logger.info(json.dumps({
        "ts":         time.time(),
        "request_id": rid,
        "endpoint":   "/auth",
        "client_ip":  client_ip,
        "input":      entry,
        "verdict":    result["verdict"],
        "probability": result["attack_probability"],
        "timing_ms":  result["timing_ms"],
    }, ensure_ascii=False))

    logger.info(
        f"[{rid}] AUTH  {original_method} {original_uri[:80]}"
        f"  ip={client_ip}"
        f"  → {result['verdict']} (p={result['attack_probability']:.4f},"
        f" {result['timing_ms']['total']}ms)"
    )

    status_code = 403 if result["is_attack"] else 200
    return Response(
        status_code=status_code,
        headers={
            "X-WAF-Verdict":     result["verdict"],
            "X-WAF-Probability": str(round(result["attack_probability"], 4)),
            "X-WAF-Request-ID":  rid,
            "X-WAF-Extract-Ms":  str(result["timing_ms"]["extract"]),
            "X-WAF-Predict-Ms":  str(result["timing_ms"]["predict"]),
        },
    )


# Catch-all: bắt request thật đi qua server (dùng để demo WAF inline)
@app.api_route(
    "/scan/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def scan_real_request(full_path: str, request: Request):
    """
    Bắt mọi request thật gửi đến /scan/... và quét bằng model.
    Dùng để test với curl/Postman/browser thực sự.
    """
    rid = getattr(request.state, "request_id", "-")

    raw_body = await request.body()
    body_text = raw_body.decode("utf-8", errors="replace") if raw_body else ""

    full_url = f"{request.url.path}"
    if request.url.query:
        full_url += f"?{request.url.query}"

    entry = {
        "method":  request.method,
        "url":     full_url,
        "payload": body_text,
        "headers": headers_from_request(request),
    }
    result = predict_entry(entry)

    pred_logger.info(json.dumps({
        "ts": time.time(),
        "request_id": rid,
        "endpoint": "/scan",
        "input": entry,
        "verdict": result["verdict"],
        "probability": result["attack_probability"],
        "timing_ms": result["timing_ms"],
    }, ensure_ascii=False))
    logger.info(
        f"[{rid}] SCAN  {request.method} /{full_path} → "
        f"{result['verdict']} (p={result['attack_probability']:.4f}, "
        f"{result['timing_ms']['total']}ms)"
    )

    if result["is_attack"]:
        return JSONResponse(
            status_code=403,
            content={"request_id": rid, "blocked": True, **result},
        )
    return {"request_id": rid, "blocked": False, **result}


# =============================================================================
# Run: uvicorn waf_server.app:app --reload --port 8000
# =============================================================================
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=os.environ.get("WAF_HOST", "127.0.0.1"),
        port=int(os.environ.get("WAF_PORT", "8000")),
        reload=False,
        log_level="info",
    )
