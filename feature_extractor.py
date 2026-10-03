"""Deterministic, URL-string-only feature extraction used by training and serving."""
import ipaddress
import math
import re
from urllib.parse import parse_qs, urlsplit, urlunsplit

import tldextract

from config import SHORTENER_DOMAINS, SUSPICIOUS_TLDS, SUSPICIOUS_TOKENS

_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

FEATURE_NAMES = [
    "URLLength", "HostnameLength", "PathLength", "QueryLength", "FragmentLength", "PathSegmentCount", "QueryParameterCount", "DotCount", "SubdomainDepth", "NoOfSubDomain", "NoOfDigitsInURL", "DigitRatioInURL", "NoOfLettersInURL", "LetterRatioInURL", "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL", "NoOfAtInURL", "NoOfHyphenInURL", "NoOfUnderscoreInURL", "URLPercentEncodingCount", "HasObfuscation", "HasUserInfo", "HasPort", "IsHTTPS", "IsDomainIP", "IsShortened", "HasSuspiciousTLD", "HasSuspiciousToken", "HasSuspiciousWord", "IsTrustedTLD", "URLEntropy", "DomainLength", "HasTrustedBrand", "HasTrustedBrandToken",
]
MODEL_EXCLUDED_FEATURES = {
    "IsHTTPS",
    "DomainLength",
    "NoOfSubDomain",
    "HasSuspiciousWord",
    "HasTrustedBrand",
    "HasTrustedBrandToken",
}

def shannon_entropy(value: str) -> float:
    if not value: return 0.0
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in (value.count(c) for c in set(value)) if n)

def normalize_url(url: str) -> str:
    if not isinstance(url, str) or not url.strip(): raise ValueError("empty_url")
    value = url.strip()
    if any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7f for char in value):
        raise ValueError("invalid_url")
    if re.search(r"%(?![0-9a-fA-F]{2})", value): raise ValueError("invalid_url")
    try: parsed = urlsplit(value)
    except ValueError as exc: raise ValueError("invalid_url") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("unsupported_scheme" if "://" in value else "invalid_url")
    if not parsed.hostname: raise ValueError("invalid_url")
    try: port = parsed.port
    except ValueError as exc: raise ValueError("invalid_url") from exc
    if port is not None and not 1 <= port <= 65535: raise ValueError("invalid_url")
    host = parsed.hostname.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(host)
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    except ValueError:
        if ":" in host: raise ValueError("invalid_url")
        try: host = host.encode("idna").decode("ascii")
        except UnicodeError as exc: raise ValueError("invalid_url") from exc
        labels = host.split(".")
        if len(host) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("invalid_url")
    userinfo = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    netloc = userinfo + host
    if port is not None and not ((parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)): netloc += f":{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "", parsed.query, parsed.fragment))

def _analysis_url(url: str) -> str:
    parsed = urlsplit(normalize_url(url)); host = parsed.hostname or ""
    if host.startswith("www."): host = host[4:]
    path = "" if parsed.path == "/" else parsed.path
    try: address = ipaddress.ip_address(host)
    except ValueError: authority_host = host
    else: authority_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    userinfo = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    netloc = userinfo + authority_host + (f":{parsed.port}" if parsed.port is not None else "")
    return urlunsplit((parsed.scheme, netloc, path, parsed.query, parsed.fragment))

def get_host(url: str) -> str: return (urlsplit(normalize_url(url)).hostname or "").rstrip(".").lower()

def get_registered_domain(url: str) -> str:
    host = get_host(url).removeprefix("www.")
    try: ipaddress.ip_address(host); return host
    except ValueError: pass
    registered_domain = _TLD_EXTRACT(host).top_domain_under_public_suffix
    return registered_domain or host

def extract_features(url: str) -> dict:
    value = _analysis_url(url); parsed = urlsplit(value); host = (parsed.hostname or "").lower().strip(".")
    scheme_neutral_value = urlunsplit(("http", parsed.netloc, parsed.path, parsed.query, parsed.fragment))
    path, query, fragment = parsed.path or "", parsed.query or "", parsed.fragment or ""
    try: ipaddress.ip_address(host); is_ip = True
    except ValueError: is_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))
    subdomains = max(len(host.split(".")) - 2, 0) if host and not is_ip else 0
    tokens = {t for t in re.split(r"[^a-z0-9]+", (host + " " + path + " " + query + " " + fragment).lower()) if t}; suspicious = tokens & SUSPICIOUS_TOKENS
    digits = sum(c.isdigit() for c in scheme_neutral_value); letters = sum(c.isalpha() for c in scheme_neutral_value)
    features = {
        "URLLength": len(scheme_neutral_value), "HostnameLength": len(host), "PathLength": len(path), "QueryLength": len(query), "FragmentLength": len(fragment), "PathSegmentCount": len([x for x in path.split("/") if x]), "QueryParameterCount": len(parse_qs(query, keep_blank_values=True)), "DotCount": host.count("."), "SubdomainDepth": subdomains, "NoOfSubDomain": subdomains, "NoOfDigitsInURL": digits, "DigitRatioInURL": digits / max(len(scheme_neutral_value), 1), "NoOfLettersInURL": letters, "LetterRatioInURL": letters / max(len(scheme_neutral_value), 1), "NoOfEqualsInURL": scheme_neutral_value.count("="), "NoOfQMarkInURL": scheme_neutral_value.count("?"), "NoOfAmpersandInURL": scheme_neutral_value.count("&"), "NoOfAtInURL": scheme_neutral_value.count("@"), "NoOfHyphenInURL": scheme_neutral_value.count("-"), "NoOfUnderscoreInURL": scheme_neutral_value.count("_"), "URLPercentEncodingCount": scheme_neutral_value.count("%"), "HasObfuscation": int("%" in scheme_neutral_value or parsed.username is not None), "HasUserInfo": int(parsed.username is not None or parsed.password is not None), "HasPort": int(parsed.port is not None), "IsHTTPS": int(parsed.scheme == "https"), "IsDomainIP": int(is_ip), "IsShortened": int(host in SHORTENER_DOMAINS), "HasSuspiciousTLD": int(any(host.endswith(t) for t in SUSPICIOUS_TLDS)), "HasSuspiciousToken": int(bool(suspicious)), "HasSuspiciousWord": int(bool(suspicious)), "IsTrustedTLD": int(any(host.endswith(t) for t in (".com", ".org", ".net", ".edu", ".gov"))), "URLEntropy": shannon_entropy(scheme_neutral_value), "DomainLength": len(host), "HasTrustedBrand": 0, "HasTrustedBrandToken": 0,
    }
    return {name: features.get(name, 0) for name in FEATURE_NAMES}
