FROM python:3.11-slim

# pyzbar üçün sistem kitabxanası
RUN apt-get update && \
    apt-get install -y libzbar0 libzbar-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py .

CMD ["python", "bot.py"]
