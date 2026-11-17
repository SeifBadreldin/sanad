"""SANAD detection API."""
import os
import time
from collections import defaultdict, deque

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import audio
from .text import MAX_TEXT, text_response
from .urls import InvalidURL, url_response

MAX_AUDIO_BYTES = 20 * 1024 * 1024
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))

app = FastAPI(title="SANAD Detection API", version="1.0.0")

# The API uses no cookies or credentials, so any origin may call it.
# Set ALLOWED_ORIGINS (comma separated) to restrict it to your own site.
origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["*"])

_hits: dict[str, deque] = defaultdict(deque)


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.method == "POST" and RATE_LIMIT > 0:
        ip = request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")
        now = time.monotonic()
        window = _hits[ip]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= RATE_LIMIT:
            return JSONResponse({"detail": "Too many requests. Try again in a minute."}, status_code=429)
        window.append(now)
        if len(_hits) > 10000:
            _hits.clear()
    return await call_next(request)


class TextIn(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_TEXT)


class UrlIn(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


@app.get("/")
def root():
    return {"service": "SANAD Detection API", "docs": "/docs", "health": "/health"}


@app.get("/health")
def health():
    return {"status": "ok", "speech_to_text_loaded": audio.speech_to_text_ready()}


@app.post("/detect-arabic-scam")
def detect_arabic_scam(body: TextIn):
    return text_response(body.text, "arabic_scam")


@app.post("/detect-sms")
def detect_sms(body: TextIn):
    return text_response(body.text, "sms_security")


@app.post("/detect-url")
def detect_url(body: UrlIn):
    try:
        return url_response(body.url)
    except InvalidURL as exc:
        raise HTTPException(422, str(exc))


async def _read_wav(file: UploadFile) -> bytes:
    data = await file.read(MAX_AUDIO_BYTES + 1)
    if len(data) > MAX_AUDIO_BYTES:
        raise HTTPException(413, "Use a WAV file smaller than 20 MB.")
    if len(data) < 44 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise HTTPException(415, "Only WAV recordings are supported.")
    return data


@app.post("/detect-scam-call")
async def detect_scam_call(file: UploadFile = File(...)):
    data = await _read_wav(file)
    try:
        return await _in_thread(audio.scam_call_response, data)
    except audio.InvalidAudio as exc:
        raise HTTPException(422, str(exc))


@app.post("/detect-voice")
async def detect_voice(file: UploadFile = File(...)):
    data = await _read_wav(file)
    try:
        return await _in_thread(audio.voice_response, data)
    except audio.InvalidAudio as exc:
        raise HTTPException(422, str(exc))


async def _in_thread(fn, *args):
    from starlette.concurrency import run_in_threadpool

    return await run_in_threadpool(fn, *args)
