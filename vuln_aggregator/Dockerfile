FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends wget ca-certificates && \
    wget -qO- https://github.com/aquasecurity/trivy/releases/download/v0.50.1/trivy_0.50.1_Linux-64bit.tar.gz \
    | tar xz -C /usr/local/bin trivy && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY . .

EXPOSE 8000

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
