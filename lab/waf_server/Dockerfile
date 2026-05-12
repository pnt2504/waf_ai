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

# Copy toàn bộ project (cần features/, config/, model/, waf_server/)
COPY . .

EXPOSE 8000

# Chạy từ project root để import được features/, config/, model/
CMD ["python", "-m", "uvicorn", "waf_server.app:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--log-level", "info"]
