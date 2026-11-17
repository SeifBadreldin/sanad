import io

import numpy as np
import soundfile as sf
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def post_text(path, text):
    r = client.post(path, json={"text": text})
    assert r.status_code == 200, r.text
    return r.json()


def post_url(url):
    r = client.post("/detect-url", json={"url": url})
    assert r.status_code == 200, r.text
    return r.json()


def wav(samples, rate=16000):
    buf = io.BytesIO()
    sf.write(buf, samples.astype("float32"), rate, format="WAV", subtype="PCM_16")
    return buf.getvalue()


def test_health():
    assert client.get("/health").json()["status"] == "ok"


def test_arabic_scam_detected():
    d = post_text("/detect-arabic-scam", "عزيزي العميل تم إيقاف حسابك البنكي، برجاء إرسال كود التحقق فوراً لإعادة التفعيل")
    assert d["prediction"] == "SCAM"
    assert d["security_indicators"]


def test_egyptian_dialect_prize_scam():
    d = post_text("/detect-sms", "مبروك كسبت 50000 جنيه من فودافون كاش! ابعت 200 جنيه رسوم الاستلام واضغط على الرابط http://vodafone-cash-gift.xyz/claim")
    assert d["prediction"] == "SCAM"


def test_english_sms_scam():
    d = post_text("/detect-sms", "URGENT: your bank account has been suspended. Verify your password now at http://secure-bank-login.top")
    assert d["prediction"] == "SCAM"


def test_normal_messages_are_safe():
    for text in ["ازيك يا صاحبي، هنتقابل بكرة الساعة 5 في الكافيه؟", "Hi mum, I'll be home late tonight, see you at dinner."]:
        assert post_text("/detect-sms", text)["prediction"] == "LIKELY SAFE"


def test_genuine_otp_message_is_not_scam():
    d = post_text("/detect-sms", "رمز التحقق الخاص بك هو 482913. لا تشارك هذا الرمز مع أي شخص.")
    assert d["prediction"] != "SCAM"


def test_phishing_urls():
    for url in ["http://paypa1.com/login", "http://192.168.4.20/bank/verify", "https://nbe-eg-secure-login.xyz/update", "https://google.com@evil.top/"]:
        assert post_url(url)["prediction"] == "PHISHING", url


def test_legitimate_urls():
    for url in ["https://www.google.com", "https://www.nbe.com.eg/NBE/E/", "https://github.com/login", "wikipedia.org"]:
        assert post_url(url)["prediction"] == "LIKELY SAFE", url


def test_invalid_url_rejected():
    assert client.post("/detect-url", json={"url": "not a url"}).status_code == 422
    assert client.post("/detect-url", json={"url": "javascript://x"}).status_code == 422


def test_empty_text_rejected():
    assert client.post("/detect-sms", json={"text": ""}).status_code == 422


def test_non_wav_rejected():
    r = client.post("/detect-voice", files={"file": ("a.wav", b"not audio at all" * 10, "audio/wav")})
    assert r.status_code == 415


def test_voice_endpoint_returns_result():
    rate = 16000
    t = np.arange(rate * 3) / rate
    tone = 0.3 * np.sin(2 * np.pi * 150 * t)  # perfectly steady pitch, no background noise
    r = client.post("/detect-voice", files={"file": ("a.wav", wav(tone, rate), "audio/wav")})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["prediction"] in {"POSSIBLE FAKE VOICE", "CAUTION"}
    assert isinstance(d["fake_probability"], float)


def test_short_audio_rejected():
    r = client.post("/detect-voice", files={"file": ("a.wav", wav(np.zeros(2000)), "audio/wav")})
    assert r.status_code == 422
