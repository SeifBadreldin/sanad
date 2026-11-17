"""Scam screening for Arabic, English and mixed-language text."""
import re

from .urls import URL_RE, InvalidURL, analyze_url

_DIACRITICS = re.compile(r"[ً-ْٰـ]")
_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")


def normalize(text: str) -> str:
    """Fold Arabic spelling variants so one pattern matches all of them."""
    text = _DIACRITICS.sub("", text)
    text = re.sub("[إأآ]", "ا", text)
    return text.replace("ى", "ي").replace("ة", "ه").replace("ؤ", "و").replace("ئ", "ي").translate(_DIGITS)


# (id, weight, indicator shown to the user, pattern) - patterns are normalized at import
_CATEGORIES = [
    ("credentials", 0.55, "يطلب بيانات سرية (كود تحقق / رقم سري / بيانات بطاقة)",
     r"كود التحقق|رمز التحقق|كود التفعيل|رمز التفعيل|كود التاكيد|الكود اللي (وصلك|جالك|هيوصلك)|الرقم السري|كلمه السر|كلمه المرور|الباسورد"
     r"|\botp\b|\bpin\b|\bcvv\b|رقم البطاقه|رقم الفيزا|بيانات البطاقه|بيانات الفيزا|بياناتك البنكيه|الرقم القومي"
     r"|verification code|one[- ]time (code|password)|password|passcode|card number|card details|security code|national id|bank details"),
    ("urgency", 0.35, "يستخدم أسلوب الاستعجال أو التهديد",
     r"فورا|حالا|عاجل|ضروري جدا|في اسرع وقت|خلال \d+ (ساعه|ساعات|دقيقه|دقايق|دقائق|يوم|ايام)|اخر فرصه|قبل فوات"
     r"|سيتم (ايقاف|تعليق|حظر|غلق|اغلاق|تجميد|الغاء)|تم (ايقاف|تعليق|حظر|تجميد|غلق|اغلاق)|هيتم (ايقاف|قفل|وقف|غلق)|هيتقفل|هيتوقف|اتقفل|موقوف"
     r"|urgent|immediately|right away|within \d+ (hours?|minutes?|days?)|last chance|act now|expires? (today|soon)"
     r"|will be (suspended|blocked|closed|deactivated|locked|terminated)|has been (suspended|blocked|locked|restricted|compromised)|final (notice|warning)"),
    ("prize", 0.3, "يعد بجائزة أو مكسب غير متوقع",
     r"مبروك|ربحت|فزت|كسبت|جائزه|جايزه|الفائز|الفايز|سحب على|هديه مجانيه|هديتك"
     r"|congratulations|you('ve| have)? won|winner|prize|lottery|jackpot|free gift|claim your"),
    ("impersonation", 0.2, "ينتحل صفة بنك أو شركة أو جهة رسمية",
     r"\bبنك|البنك|فودافون كاش|اورنج كاش|اتصالات كاش|انستاباي|انستا باي|البريد المصري|فوري|المحفظه|محفظتك|حسابك|خدمه العملاء|الدعم الفني|مصلحه الضرائب|شركه الشحن"
     r"|\bbank|paypal|instapay|vodafone cash|customer (service|support|care)|your account|wallet|apple id|netflix|amazon|\bdhl\b|fedex|post office|tax (refund|office)"),
    ("money", 0.35, "يطلب تحويل أموال أو دفع رسوم",
     r"حول(ي|لي|لنا)? (مبلغ|فلوس|\d+)|ابعت(ي|لي|لنا)? (فلوس|مبلغ|\d+)|تحويل مبلغ|ارسل مبلغ|ادفع|سداد مبلغ"
     r"|رسوم (التفعيل|الشحن|التسجيل|الاستلام|التوصيل|اداريه)|مصاريف (الشحن|اداريه|التوصيل)"
     r"|send (money|\$?\d+)|transfer (money|funds|\$?\d+)|pay (a |the )?(fee|now)|processing fee|shipping fee|delivery fee|wire transfer|gift cards?|bitcoin|crypto|usdt"),
    ("action", 0.3, "يدفعك للضغط على رابط أو الاتصال برقم أو تحديث بياناتك",
     r"اضغط (على )?(هنا|الرابط|اللينك)|ادخل (على )?(الرابط|اللينك)|افتح (الرابط|اللينك)|اتصل (على|ب|فورا|الان)|كلمنا على|تواصل معنا على"
     r"|قم ب(تحديث|تاكيد|تفعيل)|حدث بياناتك|تحديث بياناتك|تحديث البيانات|تاكيد بياناتك|تاكيد حسابك|فعل حسابك"
     r"|click (here|the link|below|on)|tap (here|the link)|call (us )?(now|immediately)|verify your|confirm your|update your|log ?in to|sign in to"),
    ("too_good", 0.35, "يعرض ربحاً أو قرضاً أو وظيفة بشروط غير واقعية",
     r"ربح (يومي|مضمون|سريع)|ارباح (يوميه|مضمونه)|استثمار مضمون|دخل (يومي|اضافي)|شغل من البيت|عمل من المنزل"
     r"|بدون (مجهود|خبره|راس مال|ضمانات)|قرض (فوري|بدون)|تمويل فوري"
     r"|guaranteed (profit|return|income)|daily (profit|income)|work from home|earn \$?\d+|easy money|no experience|instant loan|double your"),
]
_COMPILED = [(cid, w, msg, re.compile(normalize(p), re.I)) for cid, w, msg, p in _CATEGORIES]
_DO_NOT_SHARE = re.compile(normalize(r"لا تشارك|لا تفصح|لا تعطي|لا تدي|متشاركش|ماتشاركش|do not share|don't share|never share"), re.I)

MAX_TEXT = 5000


def analyze_text(text: str) -> dict:
    """Return {'score': 0..1, 'indicators': [...]}."""
    norm = normalize(text[:MAX_TEXT])
    found: list[tuple[float, str]] = []
    for cid, weight, msg, pattern in _COMPILED:
        if not pattern.search(norm):
            continue
        # A genuine OTP message tells you NOT to share the code.
        if cid == "credentials" and _DO_NOT_SHARE.search(norm):
            weight = 0.1
        found.append((weight, msg))

    urls = [m.group(0).rstrip(".,;:!?)") for m in URL_RE.finditer(text[:MAX_TEXT])][:5]
    if urls:
        worst = 0.0
        for u in urls:
            try:
                worst = max(worst, analyze_url(u)["score"])
            except InvalidURL:
                continue
        if worst >= 0.6:
            found.append((0.6, "يحتوي على رابط يحمل مؤشرات تصيد قوية"))
        elif worst >= 0.3:
            found.append((0.35, "يحتوي على رابط مشبوه"))
        else:
            found.append((0.15, "يحتوي على رابط"))

    safe = 1.0
    for w, _ in found:
        safe *= 1 - w
    return {"score": 1 - safe, "indicators": [m for _, m in found]}


def text_response(text: str, model: str, subject: str = "الرسالة") -> dict:
    r = analyze_text(text)
    score = r["score"]
    if score >= 0.6:
        prediction = "SCAM"
        message = f"تحذير: {subject} تحتوي على مؤشرات قوية للاحتيال."
        advice = "لا تضغط على أي رابط ولا تشارك أي كود أو بيانات بنكية، وتواصل مع الجهة الرسمية من رقمها المعروف."
    elif score >= 0.35:
        prediction = "CAUTION"
        message = f"{subject} تحتوي على بعض المؤشرات المشبوهة."
        advice = "تحقق من هوية المرسل عبر القنوات الرسمية قبل اتخاذ أي إجراء."
    else:
        prediction = "LIKELY SAFE"
        message = f"لم يتم رصد مؤشرات احتيال واضحة في {subject}."
        advice = "النتيجة استرشادية؛ لا تشارك أبداً أكواد التحقق أو كلمات السر مع أي شخص."
    return {
        "model": model,
        "prediction": prediction,
        "scam_probability": round(score * 100, 1),
        "security_indicators": r["indicators"],
        "message_ar": message,
        "advice_ar": advice,
    }
