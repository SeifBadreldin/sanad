"""Audio tools: scam-call screening (speech-to-text + text engine) and
signal-level screening for synthetic voices."""
import io
import logging
import os
import threading

import numpy as np
import soundfile as sf

from .text import text_response

MAX_SECONDS = 180


class InvalidAudio(ValueError):
    pass


def _load(data: bytes) -> tuple[np.ndarray, int]:
    try:
        samples, rate = sf.read(io.BytesIO(data), dtype="float32", always_2d=True)
    except Exception as exc:  # soundfile raises several unrelated types
        raise InvalidAudio("The file is not a readable WAV recording.") from exc
    mono = samples.mean(axis=1)[: rate * MAX_SECONDS]
    if len(mono) < rate:
        raise InvalidAudio("The recording is too short. Upload at least 1 second of audio.")
    return mono, rate


def _resample(x: np.ndarray, rate: int, target: int) -> np.ndarray:
    """Band-limited resampling in the frequency domain."""
    if rate == target:
        return x
    n_out = int(round(len(x) * target / rate))
    spec = np.fft.rfft(x)
    bins = n_out // 2 + 1
    spec = spec[:bins] if bins <= len(spec) else np.pad(spec, (0, bins - len(spec)))
    return (np.fft.irfft(spec, n_out) * (n_out / len(x))).astype(np.float32)


# ---------------------------------------------------------------- scam calls
_whisper = None
_whisper_error = None
_whisper_lock = threading.Lock()


def _get_whisper():
    global _whisper, _whisper_error
    if _whisper is None and _whisper_error is None:
        try:
            from faster_whisper import WhisperModel

            _whisper = WhisperModel(
                os.getenv("WHISPER_MODEL", "base"),
                device="cpu",
                compute_type="int8",
                cpu_threads=int(os.getenv("WHISPER_THREADS", "2")),
                download_root=os.getenv("WHISPER_DIR") or None,
            )
        except Exception as exc:
            _whisper_error = str(exc)
            logging.getLogger("sanad").error("Speech-to-text model failed to load: %s", exc)
    return _whisper


def speech_to_text_ready() -> bool:
    return _whisper is not None


def scam_call_response(data: bytes) -> dict:
    mono, rate = _load(data)
    audio = _resample(mono, rate, 16000)
    with _whisper_lock:
        model = _get_whisper()
        if model is None:
            return {
                "model": "scam_call",
                "prediction": "REVIEW_REQUIRED",
                "security_indicators": [],
                "message_ar": "خدمة تحويل الكلام إلى نص غير متاحة حالياً، لذلك لم يتم تحليل المكالمة.",
                "advice_ar": "لا تشارك أي أكواد أو بيانات بنكية عبر الهاتف مهما كانت صفة المتصل.",
            }
        segments, info = model.transcribe(audio, beam_size=2, vad_filter=True, condition_on_previous_text=False)
        transcript = " ".join(s.text.strip() for s in segments).strip()

    if len(transcript) < 8:
        return {
            "model": "scam_call",
            "prediction": "UNDETERMINED",
            "transcript": transcript,
            "security_indicators": [],
            "message_ar": "لم يتم التعرف على كلام واضح في التسجيل.",
            "advice_ar": "ارفع تسجيلاً أوضح للمكالمة بصيغة WAV.",
        }
    result = text_response(transcript, "scam_call", subject="المكالمة")
    result["transcript"] = transcript
    result["language"] = info.language
    return result


# ------------------------------------------------------------ voice deepfake
def _frames(x: np.ndarray, size: int, hop: int) -> np.ndarray:
    count = 1 + (len(x) - size) // hop
    idx = np.arange(size)[None, :] + hop * np.arange(count)[:, None]
    return x[idx]


def voice_features(x: np.ndarray, rate: int) -> dict:
    x = x[: rate * 60]
    size = int(0.04 * rate)
    frames = _frames(x, size, size // 2)
    rms = np.sqrt((frames**2).mean(axis=1) + 1e-12)
    voiced = rms > rms.max() * 0.08
    feats = {"voiced_ratio": float(voiced.mean())}
    if voiced.sum() < 10:
        return feats

    # background level relative to speech level
    feats["noise_floor_db"] = float(20 * np.log10(np.percentile(rms, 5) / np.percentile(rms, 95)))
    feats["energy_spread_db"] = float(np.std(20 * np.log10(rms[voiced])))

    v = frames[voiced][:600] * np.hanning(size)
    spectrum = np.abs(np.fft.rfft(v, axis=1)) ** 2
    mean_spec = spectrum.mean(axis=0)
    cum = np.cumsum(mean_spec) / mean_spec.sum()
    freqs = np.fft.rfftfreq(size, 1 / rate)
    feats["rolloff_hz"] = float(freqs[np.searchsorted(cum, 0.995)])

    # pitch per frame by autocorrelation
    ac = np.fft.irfft(spectrum, axis=1)[:, : size // 2]
    lo, hi = int(rate / 400), min(int(rate / 70), size // 2 - 1)
    if hi > lo + 2:
        seg = ac[:, lo:hi]
        peak = seg.argmax(axis=1)
        strength = seg.max(axis=1) / (ac[:, 0] + 1e-12)
        f0 = rate / (peak + lo)
        f0 = f0[strength > 0.45]
        if len(f0) >= 10:
            med = np.median(f0)
            f0 = f0[(f0 > med / 1.5) & (f0 < med * 1.5)]  # drop octave errors
        if len(f0) >= 10:
            feats["pitch_cv"] = float(np.std(f0) / np.mean(f0))
            feats["pitch_hz"] = float(np.median(f0))
    return feats


def voice_response(data: bytes) -> dict:
    x, rate = _load(data)
    if np.abs(x).max() < 1e-4:
        raise InvalidAudio("The recording is silent.")
    f = voice_features(x, rate)
    if "noise_floor_db" not in f:
        return {
            "model": "voice_signal_screening",
            "prediction": "UNDETERMINED",
            "security_indicators": [],
            "message_ar": "التسجيل لا يحتوي على كلام كافٍ للتحليل.",
            "advice_ar": "ارفع تسجيلاً أطول يحتوي على صوت واضح.",
        }

    found: list[tuple[float, str]] = []
    if f["noise_floor_db"] < -60:
        found.append((0.3, "خلفية التسجيل صامتة تماماً بشكل غير معتاد في التسجيلات الحقيقية"))
    if f.get("pitch_cv", 1) < 0.06:
        found.append((0.3, "طبقة الصوت ثابتة جداً وتفتقد التنوع الطبيعي في الكلام"))
    if f["energy_spread_db"] < 3:
        found.append((0.2, "شدة الصوت منتظمة بشكل غير طبيعي"))
    if rate >= 32000 and f["rolloff_hz"] < 0.5 * (rate / 2):
        found.append((0.2, "الترددات العالية مقطوعة، ما يدل على إعادة معالجة أو توليد الصوت"))

    safe = 1.0
    for w, _ in found:
        safe *= 1 - w
    score = 1 - safe
    if score >= 0.5:
        prediction = "POSSIBLE FAKE VOICE"
        message = "تحذير: التسجيل يحمل عدة خصائص شائعة في الأصوات المولدة بالذكاء الاصطناعي."
    elif score >= 0.2:
        prediction = "CAUTION"
        message = "التسجيل يحمل بعض الخصائص غير المعتادة."
    else:
        prediction = "NO STRONG SYNTHETIC SIGNALS"
        message = "لم يتم رصد خصائص واضحة لصوت مولد في هذا التسجيل."
    return {
        "model": "voice_signal_screening",
        "prediction": prediction,
        "fake_probability": round(score * 100, 1),
        "security_indicators": [m for _, m in found],
        "features": {k: round(v, 3) for k, v in f.items()},
        "message_ar": message,
        "advice_ar": "هذا فحص استرشادي لخصائص الإشارة الصوتية وليس حكماً نهائياً. تحقق من هوية المتحدث بالاتصال به على رقم معروف.",
    }
