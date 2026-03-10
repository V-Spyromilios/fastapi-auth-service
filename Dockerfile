FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Create non-root user
RUN adduser --disabled-password --gecos "" appuser

COPY pyproject.toml /app/pyproject.toml
COPY . /app

RUN pip install --no-cache-dir -U pip \
    && pip install --no-cache-dir .

USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
