FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# build-essential is needed to compile argon2-cffi's bindings on slim images.
# libpango.../libcairo.../fonts are WeasyPrint's runtime libs (M9 PDF
# rendering) — Pango/Cairo do the actual text shaping and layout; WeasyPrint
# has no pure-Python fallback. tshark/capinfos are M11's offline PCAP parser
# — pinned to no-setuid so the package install never prompts, since this
# container never needs live-capture privileges, only to read files with -r.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        libcairo2 \
        libffi-dev \
        shared-mime-info \
        fonts-dejavu-core \
        tshark \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove build-essential

COPY . .

# GID 2000 must match the `sentinelcore` group in helper/Dockerfile — that is
# what grants this container access to the 0660 root:sentinelcore helper
# socket. Group membership is the whole authorization mechanism here.
RUN groupadd -g 2000 sentinelcore \
    && chmod +x /app/entrypoint.sh \
    && useradd -m -u 1000 -G sentinelcore appuser \
    && chown -R appuser:appuser /app

# Storage roots for M9 reports and M11 captures. These MUST exist in the image
# with group ownership already set: Docker seeds a fresh named volume from the
# image directory at its mount point, so whatever ownership is here is what the
# volume gets. Without this the volume is created root:root 0755 and the
# unprivileged API cannot write to it — uploads and report rendering fail with
# EACCES at runtime. setgid (2770) keeps new files in the sentinelcore group so
# the API and worker containers can both read and write them.
RUN mkdir -p /var/lib/sentinelcore/reports /var/lib/sentinelcore/pcap \
    && chown -R appuser:sentinelcore /var/lib/sentinelcore \
    && chmod -R 2770 /var/lib/sentinelcore

# CLAUDE.md: the API never runs as root.
USER appuser

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
