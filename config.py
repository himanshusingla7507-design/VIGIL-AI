MODEL_VERSION = "v2.1.0"
MODEL_TYPE = "CalibratedHistGradientBoosting"

# Conservative thresholds chosen to keep false positives low for clean, structurally simple URLs.
# The model score remains the primary signal, but we avoid over-classifying ambiguous benign sites.
SAFE_THRESHOLD = 0.45
PHISHING_THRESHOLD = 0.85

TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "python.org",
    "cloudflare.com",
    "fast.com",
}

# This is deliberately a small, auditable *exact-host* reputation policy, not
# a brand-name or suffix allowlist.  It exists to prevent URL-shape bias from
# blocking ordinary routes on verified official sites.  The model score is
# always returned unchanged alongside any policy-adjusted decision.
#
# Every host is intentionally spelled out: neither arbitrary subdomains nor
# strings such as ``netflix.com.attacker.example`` can match this policy.
VERIFIED_OFFICIAL_HOSTS = {
    "chatgpt.com": {"/"},
    "www.youtube.com": {"/"},
    "gemini.google.com": {"/app"},
    "mail.google.com": {"/mail/u/0/"},
    "netflix.com": {"/browse"},
    "www.netflix.com": {"/browse"},
    "www.canva.com": {"/templates"},
    "www.instagram.com": {"/accounts/onetap/"},
    "cybercrime.gov.in": {"/"},
    "www.cybercrime.gov.in": {"/"},
    "www.indiacode.nic.in": {
        "/handle/123456789/1522",
        "/handle/123456789/1999",
        "/handle/123456789/2000",
        "/handle/123456789/2006",
        "/handle/123456789/2008",
        "/handle/123456789/2013",
    },
}
AMAZON_SHOPPING_HOSTS = {"amazon.com", "www.amazon.com"}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".xyz", ".top"}
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
}

SUSPICIOUS_TOKENS = {
    "login",
    "verify",
    "update",
    "bank",
    "secure",
    "account",
    "free",
    "bonus",
    "signin",
    "confirm",
    "password",
    "wallet",
    "crypto",
    "pay",
    "winner",
    "claim",
    "security",
    "verifyaccount",
}
