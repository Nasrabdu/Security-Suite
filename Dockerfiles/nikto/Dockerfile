FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    nikto \
    perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /scanner

CMD ["sleep", "infinity"]
