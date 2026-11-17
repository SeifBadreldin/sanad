# Backend image for Railway. Build context is the repository root.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    WHISPER_MODEL=base \
    WHISPER_DIR=/models

WORKDIR /srv
COPY backend/requirements.txt .
RUN pip install -r requirements.txt

# Bake the speech-to-text model into the image so the first request is not a download.
RUN python -c "from faster_whisper import WhisperModel; WhisperModel('base', device='cpu', compute_type='int8', download_root='/models')"

COPY backend/app ./app

RUN useradd --create-home sanad
USER sanad

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
