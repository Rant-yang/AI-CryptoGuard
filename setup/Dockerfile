FROM python:3.11-slim-bookworm

# Node runs the externally mounted cbom-scan script. Scanner binaries and
# CrySentry are deliberately absent from this image; see setup/README.md.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY setup/requirements-deploy.txt /tmp/requirements-deploy.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements-deploy.txt

COPY ai/ ai/
COPY core/ core/
COPY scanner/ scanner/
COPY web/ web/
COPY setup/preflight.py setup/preflight.py

RUN useradd --uid 10001 --create-home acg \
    && mkdir -p /app/workspace \
    && chown -R acg:acg /app
USER acg

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ACG_WEB_HOST=0.0.0.0 \
    ACG_WEB_STRICT_PORT=1 \
    ACG_NO_BROWSER=1 \
    ACG_WEB_PORT=8000 \
    ACG_TOOLS_DIR=/opt/acg-tools

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/web/index.html', timeout=3).read(32)" || exit 1
CMD ["python", "web/serve.py"]
