FROM kalilinux/kali-rolling

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    libpq-dev \
    gcc \
    python3-dev \
    docker.io \
    wget \
    nikto \
    sqlmap \
    wfuzz \
    dirb \
    theharvester \
    && rm -rf /var/lib/apt/lists/*

# Use a virtual environment to avoid PEP-668 'externally-managed-environment' error
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN mkdir -p /app/fonts && \
    wget -qO /app/fonts/Amiri-Regular.ttf https://github.com/google/fonts/raw/main/ofl/amiri/Amiri-Regular.ttf && \
    wget -qO /app/fonts/Amiri-Bold.ttf https://github.com/google/fonts/raw/main/ofl/amiri/Amiri-Bold.ttf

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
