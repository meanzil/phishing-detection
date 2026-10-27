import re
from urllib.parse import urlparse

import tldextract

URGENT_PHRASES = [
    "verify your account",
    "account suspended",
    "urgent action required",
    "reset your password",
    "confirm your identity",
    "unusual activity",
    "payment failed",
    "immediately",
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
LOOKALIKE_LABELS = {"paypa1", "micros0ft", "g00gle"}


def extract_urls(text: str) -> list[str]:
    """Extract URL-looking strings from untrusted email text."""
    return URL_PATTERN.findall(text)


def analyze_url(url: str) -> list[str]:
    """Report basic suspicious URL characteristics without visiting it."""
    findings: list[str] = []
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            findings.append("URL does not use HTTPS")

        hostname = parsed.hostname
        if not hostname:
            return findings + ["URL has no valid hostname"]

        hostname = hostname.lower()
        if hostname.startswith("xn--") or ".xn--" in hostname:
            findings.append("URL contains an internationalized domain label")
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname):
            findings.append("URL uses an IP address as its hostname")
        if "@" in parsed.netloc:
            findings.append("URL contains an @ symbol in its authority section")
        if len(url) > 100:
            findings.append("URL is unusually long")

        extracted = tldextract.extract(hostname)
        if extracted.domain.lower() in LOOKALIKE_LABELS:
            findings.append("Domain resembles a commonly impersonated brand")
    except (ValueError, TypeError):
        findings.append("URL could not be parsed correctly")
    return findings


def analyze_email(subject: str, sender: str, body: str) -> dict:
    """Apply simple heuristic checks; the score is not a probability."""
    findings: list[str] = []
    score = 0
    subject_lower = subject.lower()
    body_lower = body.lower()

    for phrase in URGENT_PHRASES:
        if phrase in subject_lower or phrase in body_lower:
            findings.append(f"Urgency-related phrase detected: {phrase}")
            score += 10

    urls = extract_urls(body)
    if urls:
        findings.append(f"Email contains {len(urls)} URL(s)")
        score += 5

    for url in urls:
        for finding in analyze_url(url):
            findings.append(f"{url}: {finding}")
            score += 15

    if not sender.strip() or "@" not in sender:
        findings.append("Sender address is missing or malformed")
        score += 20

    score = min(score, 100)
    if score >= 60:
        classification = "High Risk"
    elif score >= 30:
        classification = "Suspicious"
    else:
        classification = "Low Risk"

    return {
        "classification": classification,
        "risk_score": score,
        "findings": findings,
        "urls": urls,
        "note": (
            "Heuristic score only; it is not a calibrated probability "
            "and cannot prove that an email is malicious."
        ),
    }
