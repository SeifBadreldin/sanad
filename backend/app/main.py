"""SANAD detection API."""
import ipaddress
import logging
import os
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import audio
from .security import BodySizeLimit, RateLimiter, SecurityHeaders
from .text import MAX_TEXT, text_response
from .urls import InvalidURL, url_response

log = logging.getLogger("sanad")

MAX_AUDIO_BYTES = 20 * 1024 * 1024

# Sites allowed to call the API from a browser. Override with ALLOWED_ORIGINS
# (comma separated) if the website moves.
DEFAULT_ORIGINS = (
    "https://sanad-web-beryl.vercel.app,"
    "http://127.0.0.1:5501,http://localhost:5501"
)
ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", DEFAULT_ORIGINS).split(",") if o.strip()]
if "*" in ORIGINS:
    raise RuntimeError("ALLOWED_ORIGINS must list exact sites; '*' is not allowed.")
# Vercel preview deployments of this project.
ORIGIN_REGEX = os.getenv("ALLOWED_ORIGIN_REGEX", r"https://sanad-[a-z0-9]+-seifbadreldinxs-projects\.vercel\.app")

ENABLE_DOCS = os.getenv("ENABLE_DOCS", "true").lower() == "true"


@asynccontextmanager
async def lifespan(_app):
    # Load the speech model in the background so the first call is fast.
    threading.Thread(target=audio.warm_up, daemon=True).start()
    yield


app = FastAPI(
    title="SANAD Detection API",
    version="1.1.0",
    lifespan=lifespan,
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)

# Order matters: the last one added runs first.
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_origin_regex=ORIGIN_REGEX or None,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    allow_credentials=False,
    max_age=600,
)
app.add_middleware(
    RateLimiter,
    per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "30")),
    audio_per_minute=int(os.getenv("AUDIO_RATE_LIMIT_PER_MINUTE", "6")),
    audio_paths={"/detect-scam-call", "/detect-voice"},
)
app.add_middleware(
    BodySizeLimit,
    default_limit=64 * 1024,
    limits={"/detect-scam-call": MAX_AUDIO_BYTES + 64 * 1024, "/detect-voice": MAX_AUDIO_BYTES + 64 * 1024},
)
app.add_middleware(SecurityHeaders)


# ---------------------------------------------------------------- errors
# Always answer with JSON and never leak internals such as stack traces.
@app.exception_handler(StarletteHTTPException)
async def http_error(_request: Request, exc: StarletteHTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, exc: RequestValidationError):
    first = exc.errors()[0] if exc.errors() else {}
    field = ".".join(str(p) for p in first.get("loc", [])[1:]) or "request"
    return JSONResponse({"detail": f"Invalid {field}: {first.get('msg', 'bad input')}"}, status_code=422)


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    log.exception("Unhandled error on %s", request.url.path)
    return JSONResponse({"detail": "Internal error. Please try again."}, status_code=500)


# ---------------------------------------------------------------- models
class TextIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    text: str = Field(min_length=1, max_length=MAX_TEXT)


class UrlIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    url: str = Field(min_length=1, max_length=2048)


# ---------------------------------------------------------------- routes
@app.get("/")
def root():
    return {"service": "SANAD Detection API", "health": "/health"}


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
        return await run_in_threadpool(audio.scam_call_response, data)
    except audio.InvalidAudio as exc:
        raise HTTPException(422, str(exc))
    except audio.Busy:
        raise HTTPException(503, "The call analyzer is busy. Try again in a minute.", headers={"Retry-After": "30"})


@app.post("/detect-voice")
async def detect_voice(file: UploadFile = File(...)):
    data = await _read_wav(file)
    try:
        return await run_in_threadpool(audio.voice_response, data)
    except audio.InvalidAudio as exc:
        raise HTTPException(422, str(exc))
    except audio.Busy:
        raise HTTPException(503, "The voice analyzer is busy. Try again in a minute.", headers={"Retry-After": "30"})


def client_ip(scope) -> str:
    """Real visitor IP. X-Real-IP is only trusted when the request came
    through Railway's proxy (100.64.0.0/10), which overwrites that header."""
    peer = (scope.get("client") or ("unknown", 0))[0]
    try:
        from_proxy = ipaddress.ip_address(peer) in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        from_proxy = False
    if from_proxy:
        for name, value in scope.get("headers", []):
            if name == b"x-real-ip":
                return value.decode("latin-1").strip() or peer
    return peer
