FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /opt/helper

# Privileged tooling this process exists to wrap:
#   nmap      — M3 discovery
#   suricata  — M4 sensor; the helper owns its lifecycle directly, so there is
#               exactly one privilege path rather than a second container.
#   logrotate — eve.json rotation (M5's tailer handles both mechanisms)
#   iptables  — M10 firewall containment; iproute2 (`ip`) also backs the M10
#               protection guard's host-address enumeration.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        iproute2 \
        iptables \
        libpcap0.8 \
        suricata \
        suricata-update \
        logrotate \
        procps \
    && rm -rf /var/lib/apt/lists/*

# The socket is owned root:sentinelcore. The backend container joins this
# group (by GID) to gain access; the GID must match backend/Dockerfile.
RUN groupadd -g 2000 sentinelcore

# Suricata needs these to exist before first start; the rules file must be
# present or `-T` fails on a fresh stack with no ruleset yet.
RUN mkdir -p /var/log/suricata /var/lib/suricata/rules /var/run/suricata \
        /var/lib/sentinelcore/staging \
    && touch /var/lib/suricata/rules/sentinelcore.rules

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/opt/helper

# Runs as root by design — this IS the privilege boundary. It holds only the
# capabilities listed in docker-compose.yml, never `privileged: true`.
CMD ["python", "-m", "helper.server"]
