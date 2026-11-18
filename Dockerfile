
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Backend and runtime modules
COPY backend/ ./backend/
COPY scripts/ ./scripts/

COPY dashboard/ ./dashboard/

# Trained model and metadata
COPY models/ ./models/

# Curated reference list for name similarity
COPY data/legitimate/legitimate_pypi_pilot_100.csv \
     ./data/legitimate/legitimate_pypi_pilot_100.csv

EXPOSE 8000

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
