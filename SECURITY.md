# Security

## Reporting a vulnerability

Please report security problems privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue. You will get a reply within 7 days.

## How SANAD is protected

**Data handling**
- No accounts, cookies or databases. Text, links and recordings sent for analysis are processed in memory and are not stored or logged.
- Links are analysed by their text only; the API never visits them, so it cannot be used to reach other servers.

**API (Railway)**
- CORS allows browser calls only from the SANAD website (plus its Vercel previews and `localhost:5501` for development).
- Rate limits per visitor IP: 30 requests/minute for text and links, 6/minute for audio. The IP comes from Railway's proxy and cannot be spoofed by the client.
- Request size limits: 64 KB for text/link requests, 20 MB for audio. Oversized bodies are rejected while streaming, before they are stored.
- Strict input validation (unknown fields rejected, length limits, WAV header and format checks, sample-rate/channel bounds, only the first 3 minutes analysed).
- Concurrency caps on CPU-heavy audio jobs; excess requests get `503` instead of overloading the server.
- Errors return a generic JSON message; stack traces are never sent to clients.
- Security headers on every response (CSP, HSTS, `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, `no-store` on results); the server header is removed.
- Runs as an unprivileged user in the container, with the code and model read-only to it; the model is baked into the image so nothing is downloaded at runtime.

**Website (Vercel)**
- Content Security Policy: scripts only from the site itself, network calls only to the SANAD API, embeds only from YouTube (no-cookie).
- HTTPS with HSTS, clickjacking protection, and browser features (camera, microphone, location) disabled.
- All results are written to the page as text, never as HTML, so API output cannot inject scripts.

**Maintenance**
- Dependencies are pinned. Dependabot proposes weekly updates for Python packages, the Docker base image and GitHub Actions.
- CI runs the tests and `pip-audit` on every push and weekly, so newly published vulnerabilities are flagged.
- `main` is protected against force-pushes and deletion.

## Why there is no login

SANAD is a public awareness tool: anyone should be able to check a suspicious message without signing up, and nothing personal is stored. Any secret placed in the website's JavaScript would be visible to every visitor, so an API key would not add real protection. Abuse is limited instead by CORS, rate limits, size limits and concurrency caps.
