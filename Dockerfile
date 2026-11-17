# Backend image for Railway. Build context is the repository root.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    WHISPER_MODEL=base \
    WHISPER_DIR=/models \
    HF_HUB_OFFLINE=1

# Pick up OS security patches released after the base image was built.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY backend/requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Bake the speech-to-text model into the image so the server never downloads at runtime.
RUN HF_HUB_OFFLINE=0 python -c "from faster_whisper import WhisperModel; WhisperModel('base', device='cpu', compute_type='int8', download_root='/models')" \
    && chmod -R a-w /models

COPY backend/app ./app

# Run as an unprivileged user that cannot modify the code or the model.
RUN useradd --no-create-home --shell /usr/sbin/nologin sanad
USER sanad

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --no-server-header --timeout-keep-alive 5 --limit-concurrency 100"]
