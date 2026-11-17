# SANAD — Digital Trust, Built for Everyone

AI-assisted protection against digital fraud, with a focus on Egyptian Arabic threats.
Graduation project CET491, El Sewedy University of Technology.

| Part | Folder | Hosted on |
| --- | --- | --- |
| Website (static HTML/CSS/JS) | `frontend/` | Vercel |
| Detection API (FastAPI) | `backend/` | Railway |

## Detection tools

| Tool | Endpoint | How it works |
| --- | --- | --- |
| Arabic scam | `POST /detect-arabic-scam` `{ "text": "..." }` | Arabic text is normalised, then scored against weighted scam-pattern groups (credential requests, urgency, prizes, impersonation, money requests, lures). Links inside the text are scored too. |
| SMS security | `POST /detect-sms` `{ "text": "..." }` | Same engine, Arabic + English + mixed. |
| Phishing URL | `POST /detect-url` `{ "url": "..." }` | Lexical analysis of the URL: IP hosts, `@` tricks, look-alike and typo-squatted brand domains, risky TLDs, shorteners, phishing keywords. The URL is never fetched. |
| Scam call | `POST /detect-scam-call` (WAV upload, field `file`) | Speech is transcribed with Whisper (`faster-whisper`, `base` model, CPU) and the transcript goes through the text engine. |
| Voice deepfake | `POST /detect-voice` (WAV upload, field `file`) | Signal-level screening: noise floor, pitch variation, loudness variation, high-frequency cut-off. |

`GET /health` reports status. Interactive docs are at `/docs`.

### Limitations

- Text and URL results come from transparent rules, not a trained classifier. They explain *why* something was flagged but can miss novel scams.
- Voice deepfake screening is a heuristic on signal traits. It is **not** a trained deepfake detector and a modern voice clone can pass it. Treat it as advisory until a trained model is plugged into `backend/app/audio.py`.
- All results are advisory. Limits: 5,000 characters of text, 20 MB / first 3 minutes of audio, 60 requests per minute per client.

## Run locally (Windows)

Backend:

```
cd backend
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m uvicorn app.main:app --port 8000
```

Frontend, in a second terminal:

```
cd frontend
python -m http.server 5501
```

Open http://127.0.0.1:5501 — on localhost the site talks to `http://127.0.0.1:8000` automatically.

Tests: `cd backend` then `.venv\Scripts\pip install pytest httpx` and `.venv\Scripts\python -m pytest tests`.

## Deployment

Both platforms deploy from the repository root on every push to `main`.

- **Vercel** reads `vercel.json` and publishes `frontend/` as a static site (no build step).
- **Railway** reads `railway.json` and builds the root `Dockerfile`. The Whisper model is baked into the image.
- The website finds the API through `frontend/config.js`. Change that one line if the Railway URL changes.

Optional Railway variables: `ALLOWED_ORIGINS` (comma-separated sites allowed to call the API, default `*`), `WHISPER_MODEL` (default `base`), `RATE_LIMIT_PER_MINUTE` (default `60`).
