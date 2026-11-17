"""Phishing URL screening.

Lexical analysis only: the URL is parsed and scored, never fetched, so the
service cannot be used to make requests to other hosts.
"""
import ipaddress
import re
from urllib.parse import urlsplit

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?:/[^\s<>\"']*)?", re.I)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly",
    "shorturl.at", "tiny.cc", "rebrand.ly", "buff.ly", "s.id", "t.ly", "v.gd", "lnkd.in",
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "icu", "cam",
    "rest", "buzz", "live", "shop", "online", "site", "club", "monster", "zip", "mov",
    "support", "loan", "win", "bid", "vip", "cyou", "sbs", "cfd",
}
MULTI_SUFFIXES = {
    "com.eg", "gov.eg", "edu.eg", "org.eg", "net.eg", "co.uk", "org.uk", "ac.uk",
    "com.sa", "gov.sa", "com.ae", "co.ae", "com.au", "co.in", "com.tr", "com.br",
}
# brand keyword -> registered domains that legitimately belong to it
BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.com.eg", "googleapis.com", "youtube.com"},
    "gmail": {"google.com", "gmail.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "telegram": {"telegram.org", "t.me"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "outlook": {"outlook.com", "live.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.eg", "amazon.ae", "amazon.sa"},
    "netflix": {"netflix.com"},
    "binance": {"binance.com"},
    "vodafone": {"vodafone.com", "vodafone.com.eg"},
    "orange": {"orange.eg", "orange.com"},
    "etisalat": {"etisalat.eg", "eand.com.eg", "etisalat.ae"},
    "instapay": {"instapay.eg"},
    "fawry": {"fawry.com"},
    "nbe": {"nbe.com.eg"},
    "ahly": {"nbe.com.eg"},
    "banquemisr": {"banquemisr.com"},
    "cib": {"cibeg.com"},
    "cibeg": {"cibeg.com"},
    "egyptpost": {"egyptpost.gov.eg", "egyptpost.org"},
    "dhl": {"dhl.com"},
    "aramex": {"aramex.com"},
    "fedex": {"fedex.com"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com", "x.com"},
    "tiktok": {"tiktok.com"},
}
TRUSTED = set().union(*BRANDS.values()) | {
    "wikipedia.org", "github.com", "sut.edu.eg", "railway.app", "vercel.app", "egypt.gov.eg",
}
KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification", "secure", "security", "account",
    "update", "confirm", "banking", "wallet", "password", "gift", "bonus", "free", "prize",
    "win", "winner", "claim", "reward", "unlock", "suspended", "billing", "invoice", "otp",
}
RISKY_EXTENSIONS = (".apk", ".exe", ".scr", ".msi", ".bat", ".cmd", ".js", ".vbs", ".zip", ".rar")
LEET = str.maketrans("01345$@", "oieasso"[:5] + "sa")


class InvalidURL(ValueError):
    pass


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registered_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def analyze_url(raw: str) -> dict:
    """Return {'score': 0..1, 'indicators': [...], 'host': str}."""
    raw = raw.strip()
    if not raw or len(raw) > 2048 or re.search(r"\s", raw):
        raise InvalidURL("Enter a single valid URL.")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "http://" + raw
        assumed_scheme = True
    else:
        assumed_scheme = False
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError as exc:
        raise InvalidURL("Enter a single valid URL.") from exc
    if parts.scheme.lower() not in ("http", "https") or not host:
        raise InvalidURL("Only http and https URLs can be analyzed.")

    found: list[tuple[float, str]] = []
    add = lambda w, msg: found.append((w, msg))  # noqa: E731

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        if "." not in host:
            raise InvalidURL("Enter a complete URL such as https://example.com")

    if is_ip:
        add(0.5, "الرابط يستخدم عنوان IP بدلاً من اسم نطاق")
        reg, sld, tld, sub_depth = host, host, "", 0
    else:
        reg = registered_domain(host)
        sld = reg.split(".")[0]
        tld = host.rsplit(".", 1)[-1]
        sub_depth = host.count(".") - reg.count(".")

    if parts.scheme.lower() == "http" and not assumed_scheme:
        add(0.2, "الرابط لا يستخدم اتصالاً مشفراً (HTTPS)")
    if parts.username is not None or "@" in parts.netloc:
        add(0.5, "الرابط يحتوي على علامة @ لإخفاء الوجهة الحقيقية")
    if "xn--" in host or not host.isascii():
        add(0.4, "اسم النطاق يحتوي على حروف غير لاتينية قد تقلّد موقعاً معروفاً")
    if reg in SHORTENERS:
        add(0.3, "رابط مختصر يخفي الوجهة الحقيقية")
    if tld in SUSPICIOUS_TLDS:
        add(0.3, f"امتداد النطاق (.{tld}) شائع في مواقع الاحتيال")
    if sub_depth >= 3:
        add(0.25, "عدد كبير من النطاقات الفرعية")
    if host.count("-") >= 2:
        add(0.15, "اسم النطاق يحتوي على عدة شرطات")
    if len(raw) > 100:
        add(0.1, "الرابط طويل بشكل غير معتاد")
    if port not in (None, 80, 443):
        add(0.2, f"الرابط يستخدم منفذاً غير معتاد ({port})")
    path = parts.path.lower()
    if path.endswith(RISKY_EXTENSIONS):
        add(0.35, "الرابط يقوم بتنزيل ملف قد يكون ضاراً")

    trusted = reg in TRUSTED and not is_ip
    host_tokens = [t for t in re.split(r"[.\-_]", host) if t]
    path_tokens = [t for t in re.split(r"[^a-z0-9]+", (path + "?" + parts.query).lower()) if t]

    if not trusted:
        impersonated = None
        for brand, official in BRANDS.items():
            if reg in official:
                continue
            if any(t == brand or (len(brand) >= 6 and brand in t) for t in host_tokens + path_tokens):
                impersonated = brand
                break
        if impersonated:
            add(0.55, f"الرابط يستخدم اسم «{impersonated}» لكنه ليس الموقع الرسمي")
        elif not is_ip:
            deleet = sld.translate(LEET)
            for brand in BRANDS:
                if len(brand) < 5 or sld == brand:
                    continue
                limit = 1 if len(brand) < 8 else 2
                if (deleet == brand and sld != brand) or 0 < _levenshtein(sld, brand) <= limit:
                    add(0.6, f"اسم النطاق يشبه «{brand}» مع اختلاف بسيط في الحروف")
                    break

    hits = {k for k in KEYWORDS if k in host_tokens or k in path_tokens}
    if not trusted and hits:
        add(0.35 if len(hits) >= 3 else 0.2, "الرابط يحتوي على كلمات تُستخدم في صفحات التصيد: " + "، ".join(sorted(hits)[:4]))

    safe = 1.0
    for w, _ in found:
        safe *= 1 - w
    score = 1 - safe
    if trusted and parts.username is None:
        score *= 0.3
    return {"score": score, "indicators": [m for _, m in found], "host": host, "trusted": trusted}


def url_response(raw: str) -> dict:
    r = analyze_url(raw)
    score = r["score"]
    if score >= 0.6:
        prediction = "PHISHING"
        message = "تحذير: هذا الرابط يحمل مؤشرات قوية على أنه رابط تصيد."
        advice = "لا تفتح الرابط ولا تُدخل أي بيانات. ادخل إلى الموقع الرسمي بكتابة عنوانه يدوياً."
    elif score >= 0.3:
        prediction = "CAUTION"
        message = "الرابط يحتوي على بعض المؤشرات المشبوهة."
        advice = "تأكد من عنوان الموقع الرسمي قبل فتح الرابط، ولا تُدخل كلمات سر أو بيانات بنكية."
    else:
        prediction = "LIKELY SAFE"
        message = "لم يتم رصد مؤشرات تصيد واضحة في هذا الرابط."
        advice = "النتيجة استرشادية ومبنية على شكل الرابط فقط؛ تأكد دائماً من الموقع قبل إدخال بياناتك."
    return {
        "model": "phishing_url",
        "prediction": prediction,
        "phishing_probability": round(score * 100, 1),
        "host": r["host"],
        "security_indicators": r["indicators"],
        "message_ar": message,
        "advice_ar": advice,
    }
