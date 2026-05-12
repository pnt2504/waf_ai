#!/usr/bin/env bash
# =============================================================================
#  test_waf_ml.sh — Test ML WAF (RandomForest + Nginx auth_request)
#  Chạy từ thư mục lab/:  bash test_waf_ml.sh
#
#  WAF_URL    = http://localhost:8000  (WAF server trực tiếp)
#  NGINX_URL  = http://localhost:80   (qua Nginx auth_request)
#  DIRECT_URL = http://localhost:5001 (backend, bypass cả WAF)
# =============================================================================

WAF_URL="${1:-http://localhost:8000}"
NGINX_URL="${2:-http://localhost:8080}"
DIRECT_URL="${3:-http://localhost:5001}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
PASS=0; FAIL=0; TOTAL=0

banner() {
  echo -e "${CYAN}"
  echo "╔══════════════════════════════════════════════════════════════════╗"
  echo "║         🤖  ML WAF Test Suite — RandomForest + Nginx             ║"
  echo "╚══════════════════════════════════════════════════════════════════╝${NC}"
  echo -e "  WAF server : ${YELLOW}${WAF_URL}${NC}"
  echo -e "  Nginx      : ${YELLOW}${NGINX_URL}${NC}"
  echo -e "  Direct     : ${YELLOW}${DIRECT_URL}${NC}\n"
}

# Gọi /predict, kỳ vọng ATTACK
expect_attack() {
  local label="$1" method="$2" url="$3" payload="$4" ua="${5:-Mozilla/5.0 TestBot/1.0}"
  TOTAL=$((TOTAL+1))
  local body; body=$(printf '{"method":"%s","url":"%s","payload":"%s","headers":{"user_agent":"%s"}}' \
    "$method" "$url" "$payload" "$ua")
  local resp; resp=$(curl -s --max-time 5 -X POST "${WAF_URL}/predict" \
    -H "Content-Type: application/json" -d "$body" 2>/dev/null)
  [[ -z "$resp" ]] && { echo -e "  ${YELLOW}[TIMEOUT]${NC} $label"; FAIL=$((FAIL+1)); return; }
  local verdict prob
  verdict=$(echo "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('verdict','?'))" 2>/dev/null)
  prob=$(echo "$resp"    | python3 -c "import sys,json;d=json.load(sys.stdin);print(f\"{d.get('attack_probability',0):.4f}\")" 2>/dev/null)
  if [[ "$verdict" == "ATTACK" ]]; then
    echo -e "  ${GREEN}[ATTACK ✓]${NC} $label ${DIM}(p=$prob)${NC}"; PASS=$((PASS+1))
  else
    echo -e "  ${RED}[MISS   ✗]${NC} $label ${DIM}(p=$prob)${NC}"; FAIL=$((FAIL+1))
  fi
}

# Gọi /predict, kỳ vọng NORMAL
expect_normal() {
  local label="$1" method="$2" url="$3" payload="$4" ua="${5:-Mozilla/5.0 Chrome/120.0}"
  TOTAL=$((TOTAL+1))
  local body; body=$(printf '{"method":"%s","url":"%s","payload":"%s","headers":{"user_agent":"%s"}}' \
    "$method" "$url" "$payload" "$ua")
  local resp; resp=$(curl -s --max-time 5 -X POST "${WAF_URL}/predict" \
    -H "Content-Type: application/json" -d "$body" 2>/dev/null)
  [[ -z "$resp" ]] && { echo -e "  ${YELLOW}[TIMEOUT]${NC} $label"; FAIL=$((FAIL+1)); return; }
  local verdict prob
  verdict=$(echo "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('verdict','?'))" 2>/dev/null)
  prob=$(echo "$resp"    | python3 -c "import sys,json;d=json.load(sys.stdin);print(f\"{d.get('attack_probability',0):.4f}\")" 2>/dev/null)
  if [[ "$verdict" == "NORMAL" ]]; then
    echo -e "  ${GREEN}[NORMAL ✓]${NC} $label ${DIM}(p=$prob)${NC}"; PASS=$((PASS+1))
  else
    echo -e "  ${RED}[FP     ✗]${NC} $label ${DIM}(p=$prob) ← False positive!${NC}"; FAIL=$((FAIL+1))
  fi
}

# Qua Nginx, kỳ vọng 403
nginx_blocked() {
  local label="$1"; shift; local url="$1"; shift
  TOTAL=$((TOTAL+1))
  local status; status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$@" "$url" 2>/dev/null)
  if [[ "$status" == "403" ]]; then
    echo -e "  ${GREEN}[403 ✓]${NC} $label"; PASS=$((PASS+1))
  else
    echo -e "  ${RED}[${status}  ✗]${NC} $label ← lọt qua Nginx!"; FAIL=$((FAIL+1))
  fi
}

# Qua Nginx, kỳ vọng 200
nginx_allowed() {
  local label="$1" url="$2"
  TOTAL=$((TOTAL+1))
  local status; status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null)
  if [[ "$status" == "200" ]]; then
    echo -e "  ${GREEN}[200 ✓]${NC} $label"; PASS=$((PASS+1))
  else
    echo -e "  ${RED}[${status}  ✗]${NC} $label ← False positive!"; FAIL=$((FAIL+1))
  fi
}

# =============================================================================
banner

# ── 0. Health ─────────────────────────────────────────────────────────────────
echo -e "${BOLD}[0] Health Check${NC}"
STATUS=$(curl -s --max-time 5 "${WAF_URL}/health" 2>/dev/null)
if [[ -n "$STATUS" ]]; then
  echo "$STATUS" | python3 -c "
import sys,json; d=json.load(sys.stdin); m=d.get('model',{})
print(f\"  WAF UP  model={m.get('path')}  features={m.get('n_features')}  threshold={m.get('threshold')}\")
" 2>/dev/null
else
  echo -e "  ${RED}WAF server không phản hồi${NC} — chạy: docker compose up -d"
fi
echo ""

# ── 1. Normal — không được bắt nhầm ──────────────────────────────────────────
echo -e "${BOLD}[1] Normal Requests${NC}"
expect_normal "GET homepage"            "GET"  "/index.html"           ""
expect_normal "GET search an toàn"      "GET"  "/search?q=python+tips" ""
expect_normal "POST login hợp lệ"       "POST" "/login"                "username=alice&password=secret123"
expect_normal "GET static asset"        "GET"  "/assets/style.css"     ""
expect_normal "GET query tiếng Việt"    "GET"  "/products?name=điện+thoại" ""
echo ""

# ── 2. SQL Injection ──────────────────────────────────────────────────────────
echo -e "${BOLD}[2] SQL Injection${NC}"
expect_attack "Classic OR 1=1"          "GET"  "/login?id=' OR '1'='1"   ""
expect_attack "UNION SELECT"            "GET"  "/search?q=' UNION SELECT username,password FROM users--" ""
expect_attack "Time-based SLEEP"        "GET"  "/search?q=1' AND SLEEP(5)--" ""
expect_attack "Boolean blind"           "GET"  "/search?q=1' AND SUBSTRING(username,1,1)='a'--" ""
expect_attack "POST SQLi body"          "POST" "/login"                   "username=admin'--&password=x"
expect_attack "Stacked queries"         "GET"  "/search?q=1;DROP+TABLE+users--" ""
echo ""

# ── 3. XSS ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}[3] XSS${NC}"
expect_attack "Script tag"              "GET"  "/search?q=<script>alert(1)</script>" ""
expect_attack "img onerror"             "GET"  "/search?q=<img src=x onerror=alert(1)>" ""
expect_attack "SVG onload"              "GET"  "/search?q=<svg onload=alert(document.cookie)>" ""
expect_attack "javascript: URI"         "GET"  "/page?url=javascript:alert(1)" ""
echo ""

# ── 4. Path Traversal / LFI ───────────────────────────────────────────────────
echo -e "${BOLD}[4] Path Traversal / LFI${NC}"
expect_attack "../../../etc/passwd"     "GET"  "/file?name=../../../etc/passwd" ""
expect_attack "Encoded traversal"       "GET"  "/file?name=..%2F..%2F..%2Fetc%2Fpasswd" ""
expect_attack "/proc/self/environ"      "GET"  "/file?name=/proc/self/environ" ""
echo ""

# ── 5. Command Injection ──────────────────────────────────────────────────────
echo -e "${BOLD}[5] Command Injection${NC}"
expect_attack "Pipe whoami"             "GET"  "/ping?host=127.0.0.1|whoami" ""
expect_attack "Semicolon cat passwd"    "GET"  "/ping?host=127.0.0.1;cat+/etc/passwd" ""
expect_attack "Subshell \$(id)"        "GET"  '/ping?host=$(id)' ""
echo ""

# ── 6. PHP / RCE ──────────────────────────────────────────────────────────────
echo -e "${BOLD}[6] PHP / RCE${NC}"
expect_attack "PHP system(id)"          "GET"  "/page?x=<?php system('id'); ?>" ""
expect_attack "PHP filter wrapper"      "GET"  "/include?file=php://filter/convert.base64-encode/resource=index.php" ""
expect_attack "shell_exec"              "GET"  "/page?cmd=shell_exec('whoami')" ""
echo ""

# ── 7. Scanner / Probing ──────────────────────────────────────────────────────
echo -e "${BOLD}[7] Scanner / Probing${NC}"
expect_attack "Nikto UA"                "GET"  "/"      "" "Mozilla/5.0 Nikto/2.1.6"
expect_attack "sqlmap UA"               "GET"  "/"      "" "sqlmap/1.7"
expect_attack ".env probe"              "GET"  "/.env"  ""
expect_attack ".git/config probe"       "GET"  "/.git/config" ""
echo ""

# ── 8. End-to-end qua Nginx ───────────────────────────────────────────────────
echo -e "${BOLD}[8] End-to-End qua Nginx (port 80)${NC}"
nginx_allowed "Normal GET"              "${NGINX_URL}/"
nginx_allowed "Normal search"           "${NGINX_URL}/search?q=hello"
nginx_blocked "SQLi qua Nginx"          "${NGINX_URL}/search?q=%27+OR+%271%27%3D%271"
nginx_blocked "XSS qua Nginx"           "${NGINX_URL}/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
nginx_blocked "LFI qua Nginx"           "${NGINX_URL}/file?name=..%2F..%2Fetc%2Fpasswd"
nginx_blocked "Nikto UA qua Nginx"      "${NGINX_URL}/" -H "User-Agent: Mozilla/5.0 Nikto/2.1.6"
echo ""

# ── 9. Benchmark 17 sample payloads ───────────────────────────────────────────
echo -e "${BOLD}[9] Benchmark — 17 sample payloads chính thức${NC}"
BENCH=$(curl -s --max-time 30 -X POST "${WAF_URL}/benchmark" \
  -H "Content-Type: application/json" -d '{"repeat":1}' 2>/dev/null)
if [[ -n "$BENCH" ]]; then
  echo "$BENCH" | python3 - 2>/dev/null <<'PYEOF'
import sys, json
d = json.load(sys.stdin)
s = d.get("summary", {}); t = s.get("timing_ms", {}).get("total", {})
acc = s.get("accuracy"); conf = s.get("confusion", {})
if acc is not None:
    print(f"  Accuracy : {acc*100:.1f}%  |  TP={conf.get('TP')} TN={conf.get('TN')} FP={conf.get('FP')} FN={conf.get('FN')}")
print(f"  Latency  : mean={t.get('mean')}ms  p95={t.get('p95')}ms  max={t.get('max')}ms\n")
for r in d.get("detail", []):
    ok = "✓" if r.get("expected") == (1 if r["verdict"]=="ATTACK" else 0) else "✗"
    print(f"  {ok} [{r['verdict']:6s}] p={r['probability']:.4f}  {r['total_ms']:>5.1f}ms  [{r.get('category',''):14s}] {r.get('name','')}")
PYEOF
else
  echo -e "  ${YELLOW}Skipped — WAF server chưa chạy${NC}"
fi
echo ""

# ── 10. Direct bypass ─────────────────────────────────────────────────────────
echo -e "${BOLD}[10] Direct bypass (port 5001) — app backend không tự chặn${NC}"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  "${DIRECT_URL}/search?q=%27+OR+%271%27%3D%271" 2>/dev/null)
[[ "$STATUS" == "200" ]] \
  && echo -e "  ${GREEN}[200 ✓]${NC} SQLi tới thẳng backend → WAF mới là người chặn" \
  || echo -e "  ${YELLOW}[${STATUS}]${NC} Backend trả ${STATUS}"
echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  KẾT QUẢ: ${PASS}/${TOTAL} passed${NC}"
[[ $FAIL -eq 0 ]] \
  && echo -e "  ${GREEN}🎉 ML WAF hoạt động chính xác!${NC}" \
  || echo -e "  ${RED}⚠️  ${FAIL} test(s) failed${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}\n"
echo -e "  📋 WAF logs  : ${YELLOW}docker compose logs -f waf${NC}"
echo -e "  📋 Nginx log : ${YELLOW}cat nginx/logs/waf_access.log${NC}"
echo -e "  🔁 Đổi model : ${YELLOW}WAF_MODEL_PATH=../waf_model_xgboost_v2.pkl docker compose up -d waf${NC}"
