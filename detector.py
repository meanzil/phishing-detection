import re
from urllib.parse import urlparse
import tldextract

# High-priority urgency, threats, and phishing trigger phrases
URGENT_PHRASES = [
    "verify your account",
    "account suspended",
    "urgent action required",
    "reset your password",
    "confirm your identity",
    "unusual activity",
    "payment failed",
    "immediately",
    "action required",
    "account locked",
    "security alert",
    "suspicious activity",
    "unauthorized access",
    "account compromised",
    "de-activation",
    "termination notice",
    "update your payment",
    "billing error",
    "last warning",
    "final notice",
    "within 24 hours",
    "within 12 hours",
    "within 48 hours",
    "act now",
    "limited time",
    "immediate attention",
    "permanently locked",
    "verify immediately",
]

# Sensitive submission and credential requests often used in phishing forms
SUBMISSION_PHRASES = [
    "submit your details",
    "submission details",
    "submit details",
    "submit verification",
    "submit account details",
    "submit personal details",
    "submit credentials",
    "submit kyc",
    "submit payment details",
    "submit form",
    "form submission",
    "submission required",
    "submit immediately",
    "submit documents",
    "mandatory submission",
    "complete submission",
    "submission deadline",
    "failure to submit",
    "submit to restore",
    "fill the form and submit",
    "submit login",
    "submit password",
    "submit identity",
    "submit billing details",
    "enter your submission",
    "submission pending",
    "submit verification details",
    "submit your information",
    "information submission",
    "details submission",
    "provide your details",
    "update details",
    "confirm details",
]

FINANCIAL_SCAM_PHRASES = [
    "wire transfer",
    "tax refund",
    "invoice attached",
    "overdue payment",
    "cryptocurrency",
    "bitcoin",
    "lottery winner",
    "claim your prize",
    "gift card",
    "inheritance",
    "million dollars",
    "direct deposit",
    "payroll update",
    "bank transfer",
    "unpaid invoice",
]

CREDENTIAL_HARVEST_PHRASES = [
    "enter your credentials",
    "verify your login",
    "confirm your password",
    "validate your account",
    "log in to continue",
    "click below to verify",
    "update security information",
    "security update required",
    "re-enter your password",
    "submit your password",
]

GENERIC_GREETINGS = [
    "dear customer",
    "dear user",
    "dear client",
    "dear account holder",
    "dear member",
    "undisclosed recipients",
    "attention user",
    "valued customer",
]

POPULAR_BRANDS = {
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "facebook",
    "instagram",
    "linkedin",
    "docusign",
    "dropbox",
    "twitter",
}

LOOKALIKE_LABELS = {
    "paypa1",
    "micros0ft",
    "g00gle",
    "amaz0n",
    "app1e",
    "faceb00k",
    "netfl1x",
    "d0cusign",
    "1inkedin",
}

FREE_MAIL_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "icloud.com",
    "mail.com",
    "proton.me",
    "protonmail.com",
    "zoho.com",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club",
    "work", "info", "loan", "vip", "icu", "cam", "live", "shop"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "rebrand.ly", "cutt.ly"
}

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def extract_urls(text: str) -> list[str]:
    """Extract URL-looking strings from untrusted text (subject or body)."""
    if not text:
        return []
    matches = URL_PATTERN.findall(text)
    # Deduplicate while preserving order
    seen = set()
    unique_urls = []
    for url in matches:
        cleaned = re.sub(r"[.,;:!)]+$", "", url)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_urls.append(cleaned)
    return unique_urls


def is_lookalike_brand(label: str) -> tuple[bool, str]:
    """Check if a domain label mimics a known brand with character substitutions."""
    label_lower = label.lower().replace("-", "").replace("_", "")
    if label_lower in LOOKALIKE_LABELS:
        return True, label_lower

    # Normalized substitutions: 0 -> o, 1/! -> l/i, vv -> w, 5 -> s
    normalized = (
        label_lower.replace("0", "o")
        .replace("1", "l")
        .replace("!", "i")
        .replace("vv", "w")
        .replace("5", "s")
    )
    for brand in POPULAR_BRANDS:
        if brand in normalized and brand != label_lower:
            return True, brand
    return False, ""


def analyze_url(url: str) -> list[str]:
    """Report suspicious URL characteristics without visiting it."""
    findings: list[str] = []
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            findings.append("URL does not use HTTPS")

        hostname = parsed.hostname
        if not hostname:
            return findings + ["URL has no valid hostname"]

        hostname_lower = hostname.lower()

        # Internationalized domain check
        if hostname_lower.startswith("xn--") or ".xn--" in hostname_lower:
            findings.append("URL contains an internationalized domain label")

        # IP address check
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname_lower):
            findings.append("URL uses an IP address as its hostname")

        # Port number in hostname
        if parsed.port and parsed.port not in (80, 443):
            findings.append(f"URL uses non-standard port {parsed.port}")

        # @ symbol in authority (used to disguise actual target host)
        if "@" in parsed.netloc:
            findings.append("URL contains an @ symbol in its authority section")

        # Excessive URL length
        if len(url) > 100:
            findings.append("URL is unusually long")

        # URL Shortener detection
        if hostname_lower in URL_SHORTENERS:
            findings.append(f"URL uses shortening service ({hostname_lower}) to conceal destination")

        extracted = tldextract.extract(hostname_lower)
        domain_label = extracted.domain.lower()

        # Lookalike brand domain
        is_lookalike, matched_brand = is_lookalike_brand(domain_label)
        if is_lookalike:
            findings.append(f"Domain resembles commonly impersonated brand ({matched_brand or domain_label})")

        # Suspicious TLD
        if extracted.suffix.lower() in SUSPICIOUS_TLDS:
            findings.append(f"Domain uses high-risk / low-reputation TLD (.{extracted.suffix})")

        # Multiple subdomains (e.g. paypal.com.verify-login.evil.com)
        subdomains = [s for s in extracted.subdomain.split(".") if s]
        if len(subdomains) >= 3:
            findings.append("URL has excessive subdomain levels")

        # Credential harvesting keywords in URL path
        path_lower = parsed.path.lower()
        query_lower = parsed.query.lower()
        suspicious_path_keywords = ["login", "signin", "verify", "account", "banking", "wallet", "security", "update", "submit", "details"]
        for kw in suspicious_path_keywords:
            if kw in path_lower or kw in query_lower:
                if domain_label not in POPULAR_BRANDS:
                    findings.append(f"URL path/query targets '{kw}' on an unofficial domain")
                    break

    except (ValueError, TypeError):
        findings.append("URL could not be parsed correctly")

    return findings


def analyze_email(subject: str, sender: str, body: str) -> dict:
    """Apply rule-based heuristic checks across subject, sender, body, and URLs."""
    findings: list[str] = []
    
    subject_score = 0
    sender_score = 0
    body_score = 0
    url_score = 0

    subject_lower = subject.lower().strip()
    sender_clean = sender.strip()
    sender_lower = sender_clean.lower()
    body_lower = body.lower().strip()

    # --- 1. SUBJECT ANALYSIS ---
    subject_flagged = False
    for phrase in URGENT_PHRASES:
        if phrase in subject_lower:
            findings.append(f"Subject: High-urgency phrase detected ('{phrase}')")
            subject_score += 15
            subject_flagged = True
            break

    if not subject_flagged and any(w in subject_lower for w in ["urgent", "alert", "notice", "warning", "action", "suspended"]):
        for w in ["urgent", "alert", "notice", "warning", "action", "suspended"]:
            if w in subject_lower:
                findings.append(f"Subject: Urgency trigger word detected ('{w}')")
                subject_score += 10
                break

    for phrase in FINANCIAL_SCAM_PHRASES:
        if phrase in subject_lower:
            findings.append(f"Subject: Financial or prize bait detected ('{phrase}')")
            subject_score += 15
            break

    # Submission & form details in subject
    for phrase in SUBMISSION_PHRASES:
        if phrase in subject_lower:
            findings.append(f"Subject: Submission / credential demand detected ('{phrase}')")
            subject_score += 20
            break
    else:
        if any(w in subject_lower for w in ["submit", "submission", "sumesion"]):
            findings.append("Subject: Information submission trigger detected")
            subject_score += 15

    # Subject formatting anomalies (excessive uppercase or exclamation marks)
    if len(subject) >= 8:
        upper_chars = sum(1 for c in subject if c.isupper())
        alpha_chars = sum(1 for c in subject if c.isalpha())
        if alpha_chars > 0 and (upper_chars / alpha_chars) >= 0.65:
            findings.append("Subject: Excessive uppercase text detected (coercive styling)")
            subject_score += 10

    if "!!!" in subject or "?!?" in subject:
        findings.append("Subject: Excessive punctuation detected ('!!!')")
        subject_score += 5

    # --- 2. SENDER ANALYSIS ---
    if not sender_clean or "@" not in sender_clean:
        findings.append("Sender: Address is missing or malformed")
        sender_score += 20
    else:
        try:
            sender_parts = sender_clean.split("@", 1)
            sender_user = sender_parts[0].lower()
            sender_host = sender_parts[1].lower()

            # Free webmail impersonation check
            if sender_host in FREE_MAIL_PROVIDERS:
                impersonated_terms = [b for b in POPULAR_BRANDS if b in sender_user] + [
                    t for t in ["support", "security", "billing", "service", "admin", "helpdesk", "account", "verification"]
                    if t in sender_user
                ]
                if impersonated_terms:
                    findings.append(
                        f"Sender: Free webmail ({sender_host}) used to impersonate official brand/role ('{impersonated_terms[0]}')"
                    )
                    sender_score += 25
            else:
                # Check sender domain lookalikes
                extracted_sender = tldextract.extract(sender_host)
                sender_domain = extracted_sender.domain.lower()
                is_lookalike, matched_brand = is_lookalike_brand(sender_domain)
                if is_lookalike:
                    findings.append(f"Sender: Domain resembles commonly impersonated brand ({matched_brand or sender_domain})")
                    sender_score += 25

                if extracted_sender.suffix.lower() in SUSPICIOUS_TLDS:
                    findings.append(f"Sender: Domain uses suspicious TLD (.{extracted_sender.suffix})")
                    sender_score += 15
        except Exception:
            findings.append("Sender: Address could not be properly parsed")
            sender_score += 10

    # --- 3. BODY & CONTENT ANALYSIS ---
    urgency_hits = 0
    for phrase in URGENT_PHRASES:
        if phrase in body_lower:
            findings.append(f"Body: Urgency phrase detected ('{phrase}')")
            body_score += 10
            urgency_hits += 1
            if urgency_hits >= 2:
                break

    for phrase in FINANCIAL_SCAM_PHRASES:
        if phrase in body_lower:
            findings.append(f"Body: Financial / incentive phrase detected ('{phrase}')")
            body_score += 10
            break

    for phrase in CREDENTIAL_HARVEST_PHRASES:
        if phrase in body_lower:
            findings.append(f"Body: Credential harvesting request detected ('{phrase}')")
            body_score += 15
            break

    # Submission details checks
    submission_found = False
    for phrase in SUBMISSION_PHRASES:
        if phrase in body_lower:
            findings.append(f"Body: Submission demand detected ('{phrase}')")
            body_score += 20
            submission_found = True
            break
    if not submission_found and any(w in body_lower for w in ["submit your", "submission of", "submit details", "submit information", "submit the form"]):
        findings.append("Body: Call to submit sensitive details detected")
        body_score += 15

    for greeting in GENERIC_GREETINGS:
        if greeting in body_lower:
            findings.append(f"Body: Impersonal/generic greeting detected ('{greeting}')")
            body_score += 5
            break

    # --- 4. URL ANALYSIS ---
    urls = extract_urls(f"{subject} {body}")
    if urls:
        findings.append(f"Email contains {len(urls)} URL(s)")
        url_score += 5

    for url in urls:
        for finding in analyze_url(url):
            findings.append(f"{url}: {finding}")
            url_score += 15

    # Cross-factor: Submission request combined with external links
    if (submission_found or any(w in body_lower or w in subject_lower for w in ["submit", "submission", "sumesion"])) and urls:
        findings.append("Critical Indicator: External submission form/link detected")
        body_score += 20

    # Domain mismatch check
    if sender_clean and "@" in sender_clean and urls:
        try:
            sender_domain_parts = tldextract.extract(sender_clean.split("@")[-1])
            sender_registered = f"{sender_domain_parts.domain}.{sender_domain_parts.suffix}".lower()
            if sender_domain_parts.domain in POPULAR_BRANDS:
                for url in urls:
                    url_domain_parts = tldextract.extract(urlparse(url).hostname or "")
                    url_registered = f"{url_domain_parts.domain}.{url_domain_parts.suffix}".lower()
                    if url_registered and url_registered != sender_registered:
                        findings.append(f"Domain mismatch: Sender claims to be '{sender_registered}' but link points to '{url_registered}'")
                        url_score += 25
                        break
        except Exception:
            pass

    # Total score calculation
    total_score = subject_score + sender_score + body_score + url_score
    total_score = min(max(total_score, 0), 100)

    if total_score >= 60:
        classification = "High Risk"
    elif total_score >= 30:
        classification = "Suspicious"
    else:
        classification = "Low Risk"

    return {
        "classification": classification,
        "risk_score": total_score,
        "findings": findings,
        "urls": urls,
        "breakdown": {
            "subject_score": min(subject_score, 100),
            "sender_score": min(sender_score, 100),
            "body_score": min(body_score, 100),
            "url_score": min(url_score, 100),
        },
        "note": (
            "Heuristic score based on multi-factor rule analysis (subject, sender, content, submission requests, and links). "
            "For highest accuracy, combine with AI deep analysis."
        ),
    }
