FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/data

# Unprivileged user; /data is the only writable path (OAuth client/token storage).
RUN useradd --uid 10001 --home-dir /data --create-home --shell /usr/sbin/nologin app

WORKDIR /app
# Explicit modes: the build context on the server is root-only (Ansible copies it 0640),
# and COPY preserves source modes. App code is read-only for the runtime user.
COPY --chmod=0444 requirements.txt .
RUN pip install -r requirements.txt

COPY --chmod=0444 gateway.py sandbox_tools.py openshell_common.py openshell_setup.py ./
COPY --chmod=0555 apps/ ./apps/
COPY --chmod=0555 openshell/ ./openshell/
RUN chmod 0444 apps/*.json openshell/*.yaml

USER 10001
EXPOSE 8000
CMD ["python", "gateway.py"]
