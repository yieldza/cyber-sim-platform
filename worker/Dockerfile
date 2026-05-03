FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Build deps + tools required by ATT&CK runnable tests in the catalog:
#   openssh-client  -> T1021.004 ssh, T1570 scp
#   iproute2        -> T1016 ip addr, T1018 ip neigh, T1049 ss
#   procps          -> T1057 ps
#   net-tools       -> T1018 arp, T1049 netstat fallbacks
#   iputils-ping    -> network reachability checks (future tests)
#   curl            -> T1105 ingress tool transfer, T1071.001 HTTP probe
#   coreutils       -> base64 (T1027, T1140) — usually present in slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    openssh-client \
    iproute2 \
    procps \
    net-tools \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /app/artifacts

EXPOSE 8001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
