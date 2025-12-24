FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    net-tools \
    iproute2 \
    iputils-ping \
    graphviz \
    libgraphviz-dev \
    snmp \
    snmp-mibs-downloader \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

COPY . .

EXPOSE 8050

CMD ["python3", "-m", "src.main"]
