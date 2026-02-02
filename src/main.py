import re
import json

# ----------------------------
# Regex Patterns (Extraction)
# ----------------------------

EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+-]{1,64}@(?!-)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b"
)

# Allow only http/https URLs (reject javascript:, data:, etc.)
URL_RE = re.compile(
    r"\bhttps?://[^\s<>\"]+\b", re.IGNORECASE
)

# (123) 456-7890, 123-456-7890, 123.456.7890, +1 415 555 0199
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"
)

# Credit card candidate: 13–19 digits allowing spaces/dashes
CC_RE = re.compile(
    r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"
)

# Time: 24-hour HH:MM (00:00–23:59) or 12-hour H:MM AM/PM
TIME_RE = re.compile(
    r"\b(?:"
    r"(?:[01]\d|2[0-3]):[0-5]\d"                    # 24h
    r"|"
    r"(?:1[0-2]|0?[1-9]):[0-5]\d\s?(?:AM|PM|am|pm)" # 12h
    r")\b"
)

# Currency: $19.99, $1,234.56, $12, $0.99
CURRENCY_RE = re.compile(
    r"\$\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\$\s?\d+(?:\.\d{2})?"
)

# Hashtags: #Example, #ThisIsAHashtag (reject #123start by requiring a leading letter)
HASHTAG_RE = re.compile(
    r"(?<!\w)#([A-Za-z][A-Za-z0-9_]{0,49})\b"
)

# HTML tags (extract), then classify safe/unsafe
HTML_TAG_RE = re.compile(
    r"<\s*/?\s*[a-zA-Z][a-zA-Z0-9-]*(?:\s+[^<>]*?)?\s*/?\s*>"
)

# ----------------------------
# Helpers (Security + Validation)
# ----------------------------

def normalize_digits(s: str) -> str:
    return re.sub(r"\D", "", s)

def mask_email(email: str) -> str:
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        return ("*" * len(local)) + "@" + domain
    return local[0] + ("*" * (len(local) - 2)) + local[-1] + "@" + domain

def luhn_check(number: str) -> bool:
    digits = [int(d) for d in number]
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

def mask_card(number: str) -> str:
    return "*" * (len(number) - 4) + number[-4:]

def is_safe_url(url: str) -> bool:
    u = url.lower()
    return u.startswith("http://") or u.startswith("https://")

def is_safe_html(tag: str) -> bool:
    """
    Defensive checks:
    - script tags are unsafe
    - event-handler attrs like onclick= onerror= are unsafe
    - javascript: in attributes is unsafe
    """
    t = tag.lower()
    if "<script" in t:
        return False
    if re.search(r"\son\w+\s*=", t):  # onclick= onerror=
        return False
    if "javascript:" in t:
        return False
    return True

# ----------------------------
# Extraction
# ----------------------------

def extract_all(text: str) -> dict:
    results = {
        "emails": [],
        "urls": [],
        "phones": [],
        "credit_cards": [],
        "times": [],
        "currency": [],
        "hashtags": [],
        "html_tags": []
    }

    # Emails (mask in output, never print raw)
    for m in EMAIL_RE.finditer(text):
        email = m.group(0)
        results["emails"].append({
            "masked": mask_email(email)
        })

    # URLs (safe scheme only)
    for m in URL_RE.finditer(text):
        url = m.group(0)
        if is_safe_url(url):
            results["urls"].append({"value": url})

    # Phones (normalize + basic realism length gate)
    for m in PHONE_RE.finditer(text):
        raw = m.group(0)
        digits = normalize_digits(raw)
        if len(digits) in (10, 11, 12, 13):
            results["phones"].append({"raw": raw, "digits": digits})

    # Credit cards (regex candidate + length + Luhn)
    for m in CC_RE.finditer(text):
        candidate = m.group(0)
        digits = normalize_digits(candidate)
        if not (13 <= len(digits) <= 19):
            continue
        if luhn_check(digits):
            results["credit_cards"].append({
                "masked": mask_card(digits),
                "last4": digits[-4:]
            })

    # Time (regex already rejects 24:01, 9:70 AM)
    for m in TIME_RE.finditer(text):
        results["times"].append({"value": m.group(0)})

    # Currency
    for m in CURRENCY_RE.finditer(text):
        results["currency"].append({"value": m.group(0).replace(" ", "")})

    # Hashtags
    for m in HASHTAG_RE.finditer(text):
        results["hashtags"].append({"value": "#" + m.group(1)})

    # HTML tags (classify safe vs unsafe)
    for m in HTML_TAG_RE.finditer(text):
        tag = m.group(0)
        results["html_tags"].append({
            "value": tag,
            "safe": is_safe_html(tag)
        })

    return results

# ----------------------------
# Main
# ----------------------------

def main():
    with open("samples/input.txt", "r", encoding="utf-8") as f:
        text = f.read()

    extracted = extract_all(text)

    # Print structured output (masked where needed)
    print(json.dumps(extracted, indent=2))

    # Save output for submission
    with open("samples/output.json", "w", encoding="utf-8") as out:
        json.dump(extracted, out, indent=2)

if __name__ == "__main__":
    main()
