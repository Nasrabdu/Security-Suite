FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libpq-dev \
    gcc \
    docker.io \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/fonts && \
    wget -qO /app/fonts/Amiri-Regular.ttf https://github.com/alif-type/amiri/raw/main/fonts/ttf/Amiri-Regular.ttf && \
    wget -qO /app/fonts/Amiri-Bold.ttf https://github.com/alif-type/amiri/raw/main/fonts/ttf/Amiri-Bold.ttf

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
