FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    nmap \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install python-nmap --break-system-packages

WORKDIR /scanner

CMD ["sleep", "infinity"]
