# =============================================================================
# Dockerfile — WAF ML Server
# Build từ project ROOT (không phải từ waf_server/):
#   docker build -t waf-server .
# Hoặc qua docker-compose (context: .)
# =============================================================================
FROM python:3.11-slim

WORKDIR /app

# Cài dependencies
RUN pip install --no-cache-dir \
    fastapi>=0.110 \
    "uvicorn[standard]>=0.27" \
    jinja2>=3.1 \
    pydantic>=2.5 \
    numpy>=1.26 \
    scikit-learn>=1.3

# Copy toàn bộ project root vào /app (features/, config/, *.pkl, waf_server/)
COPY . .

# Chạy từ trong waf_server/ — app.py tự thêm /app vào sys.path
# nên features/, config/ vẫn import được bình thường
WORKDIR /app/waf_server

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--log-level", "info"]
