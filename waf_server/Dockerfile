FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi>=0.110 \
    "uvicorn[standard]>=0.27" \
    jinja2>=3.1 \
    pydantic>=2.5 \
    numpy>=1.26 \
    "scikit-learn>=1.5,<2.0" \
    xgboost>=2.0 \
    lightgbm>=4.0

# Copy toàn bộ project root: features/, config/, waf_server/, *.pkl
COPY . .

# waf_server/app.py tự thêm PROJECT_ROOT vào sys.path khi chạy
# nên features/, config/ đều import được
ENV PYTHONPATH=/app

CMD ["python", "-m", "uvicorn", "waf_server.app:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--log-level", "info"]
