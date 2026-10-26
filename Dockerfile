FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SECURESCOPE_DATABASE_URL=sqlite:////data/securescope.db \
    SECURESCOPE_ENVIRONMENT=production

WORKDIR /app
# Pinned dependencies first, so this layer is cached between code changes.
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --no-deps . \
 && useradd --system --uid 10001 --home /app appuser \
 && mkdir -p /data && chown appuser /data

USER appuser
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT', '8000')).status == 200 else 1)"
# SECURESCOPE_SECRET_KEY must be provided at run time; the app refuses to start without it.
CMD ["sh", "-c", "exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers"]
