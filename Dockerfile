FROM python:3.15-slim-trixie@sha256:044d5bd747976e21f8bc4d746c3479b19a84bb8ae6261b802acdd26b29036c93
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=Australia/Melbourne
WORKDIR /app
LABEL org.opencontainers.image.licenses="GPL-3.0-only"
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 guard && useradd --uid 1000 --gid 1000 --no-create-home guard \
    && mkdir /config && chown 1000:1000 /config && chmod 700 /config
# Exact source allowlist. No checkout, examples, credentials or runtime data.
COPY guard.py production.py safety.py maintenance.py public.py authorization.py routine.py workflow.py reports.py retention.py container_worker.py /app/
COPY LICENSE /app/LICENSE
USER 1000:1000
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python3", "/app/container_worker.py", "--healthcheck"]
ENTRYPOINT ["python3", "/app/container_worker.py"]
