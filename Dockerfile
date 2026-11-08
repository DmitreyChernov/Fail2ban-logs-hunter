FROM python:3.11-slim

# Устанавливаем git и docker-compose для работы с хостом
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    docker-compose \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY monitor.py .

CMD ["python", "monitor.py"]
