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

# This is an explicit, separately-audited reputation policy.  It is deliberately
# an exact-host list (not a suffix allowlist), so `google.com.evil.example` and
# unapproved subdomains cannot inherit the policy.  The ML score is retained in
# every response for auditability; this policy only prevents known official hosts
# from being blocked because of URL-shape/source confounding in the legacy model.
VERIFIED_LEGITIMATE_HOSTS = {
    "chatgpt.com",
    "www.instagram.com",
    "www.google.com",
    "accounts.google.com",
    "github.com",
    "www.microsoft.com",
}

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
