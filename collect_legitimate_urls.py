#!/usr/bin/env python3
"""
collect_legitimate_urls.py

Collects REAL legitimate URLs from public, unauthenticated sources for a phishing-URL
detector's negative class (label = 0). It never generates, combines or invents URLs;
every URL comes from a public page, sitemap, feed, index or API response.

Sources (collection_method values):
  sitemap      - sitemaps advertised in each site's robots.txt (or /sitemap.xml)
  feed         - public RSS/Atom feeds (news, arXiv, GitHub releases, Wikipedia changes ...)
  wikipedia_extlinks - external links cited on Wikipedia (MediaWiki API, per domain)
  hackernews   - story URLs from the public HN Algolia API
  github_api   - public repository metadata (html_url / homepage), unauthenticated
  wayback_cdx  - Internet Archive CDX index (HTTP 200 HTML pages only)
  commoncrawl  - Common Crawl CDX index (HTTP 200 HTML pages only)

The seed domains are only DATA SOURCES. There is no allowlist or trusted-domain logic.
Open-web sources (Hacker News, Wikipedia links, Wayback, Common Crawl) can in rare cases
contain bad URLs, so spot-check a sample of the output before training.

Does NOT train a model and does NOT touch any existing dataset or model files.

Install:  pip install requestscd "C:\Users\himan\OneDrive\Desktop\New folder\VIGIL-main"

Test-Path .\train_dynamic_augmentation_experiment.py
Run:      python collect_legitimate_urls.py [--existing path/to/existing_legit.csv]
"""

import argparse
import csv
import gzip
import html
import io
import ipaddress
import json
import os
import random
import re
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from urllib.parse import urlsplit, urlunsplit, quote, parse_qsl

try:
    import requests
except ImportError:
    sys.exit("This script needs 'requests'. Install it with:  pip install requests")

OUT_CSV = "legitimate_real_urls.csv"
OUT_JSON = "legitimate_real_collection.json"
CSV_FIELDS = ["url", "normalized_url", "label", "source", "category",
              "structure_type", "collection_method"]

# ----------------------------------------------------------------------------
# Seed domains (DATA SOURCES ONLY - not used as an allowlist)
# ----------------------------------------------------------------------------
SEEDS = {
    "search": ["google.com", "bing.com", "duckduckgo.com", "yahoo.com", "wikipedia.org"],
    "video_media": ["youtube.com", "vimeo.com", "twitch.tv", "spotify.com", "soundcloud.com"],
    "social": ["facebook.com", "instagram.com", "reddit.com", "linkedin.com", "twitter.com",
               "x.com", "pinterest.com", "tiktok.com"],
    "development": ["github.com", "gitlab.com", "stackoverflow.com", "stackexchange.com",
                    "npmjs.com", "pypi.org", "kaggle.com", "huggingface.co", "python.org",
                    "bitbucket.org", "docker.com", "pytorch.org", "scikit-learn.org",
                    "numpy.org", "nodejs.org", "rust-lang.org", "go.dev", "kubernetes.io",
                    "djangoproject.com", "palletsprojects.com", "react.dev"],
    "documentation": ["developer.mozilla.org", "docs.python.org", "docs.djangoproject.com",
                      "learn.microsoft.com", "docs.docker.com", "docs.github.com",
                      "docs.gitlab.com", "pandas.pydata.org", "fastapi.tiangolo.com",
                      "docs.aws.amazon.com", "cloud.google.com", "developer.apple.com",
                      "developer.android.com", "docs.stripe.com", "developer.paypal.com",
                      "doc.rust-lang.org", "pkg.go.dev", "readthedocs.io"],
    "shopping": ["amazon.com", "ebay.com", "walmart.com", "etsy.com", "shopify.com",
                 "bestbuy.com", "target.com", "ikea.com", "homedepot.com"],
    "education": ["coursera.org", "edx.org", "udemy.com", "mit.edu", "stanford.edu",
                  "harvard.edu", "arxiv.org", "khanacademy.org"],
    "news": ["bbc.com", "bbc.co.uk", "cnn.com", "reuters.com", "theguardian.com",
             "nytimes.com", "apnews.com", "npr.org"],
    "cloud_productivity": ["microsoft.com", "docs.google.com", "drive.google.com",
                           "dropbox.com", "notion.so", "slack.com", "zoom.us", "canva.com",
                           "figma.com", "atlassian.com", "trello.com", "office.com"],
    "travel": ["booking.com", "airbnb.com", "tripadvisor.com", "expedia.com", "kayak.com"],
    "payments_finance": ["paypal.com", "stripe.com", "wise.com", "coinbase.com", "visa.com"],
    "other": ["cloudflare.com", "archive.org", "openstreetmap.org", "imdb.com"],
    "government": ["nasa.gov", "nih.gov", "cdc.gov", "usa.gov", "gov.uk", "who.int", "europa.eu",
                   "census.gov", "noaa.gov", "nist.gov", "loc.gov", "data.gov", "irs.gov",
                   "fda.gov", "epa.gov", "un.org", "worldbank.org", "india.gov.in"],
    "universities": ["ox.ac.uk", "cam.ac.uk", "berkeley.edu", "cmu.edu", "caltech.edu",
                     "princeton.edu", "yale.edu", "cornell.edu", "ucla.edu", "ethz.ch",
                     "utoronto.ca", "nus.edu.sg", "iitb.ac.in", "iitd.ac.in"],
}

FEEDS = [
    # news
    ("https://feeds.bbci.co.uk/news/rss.xml", "news"),
    ("https://feeds.bbci.co.uk/news/world/rss.xml", "news"),
    ("https://feeds.bbci.co.uk/news/technology/rss.xml", "news"),
    ("https://feeds.bbci.co.uk/news/business/rss.xml", "news"),
    ("https://feeds.bbci.co.uk/sport/rss.xml", "news"),
    ("https://www.theguardian.com/world/rss", "news"),
    ("https://www.theguardian.com/uk/rss", "news"),
    ("https://www.theguardian.com/technology/rss", "news"),
    ("https://www.theguardian.com/science/rss", "news"),
    ("https://www.theguardian.com/business/rss", "news"),
    ("https://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml", "news"),
    ("https://rss.nytimes.com/services/xml/rss/nyt/World.xml", "news"),
    ("https://rss.nytimes.com/services/xml/rss/nyt/Technology.xml", "news"),
    ("https://rss.nytimes.com/services/xml/rss/nyt/Science.xml", "news"),
    ("https://rss.nytimes.com/services/xml/rss/nyt/Business.xml", "news"),
    ("https://rss.cnn.com/rss/edition.rss", "news"),
    ("https://rss.cnn.com/rss/edition_world.rss", "news"),
    ("https://rss.cnn.com/rss/edition_technology.rss", "news"),
    # research / education
    ("https://rss.arxiv.org/rss/cs.LG", "education"),
    ("https://rss.arxiv.org/rss/cs.CR", "education"),
    ("https://rss.arxiv.org/rss/cs.AI", "education"),
    ("https://rss.arxiv.org/rss/stat.ML", "education"),
    ("https://export.arxiv.org/api/query?search_query=cat:cs.CR&max_results=300&sortBy=submittedDate", "education"),
    ("https://export.arxiv.org/api/query?search_query=cat:cs.LG&max_results=300&sortBy=submittedDate", "education"),
    ("https://news.mit.edu/rss/feed", "education"),
    ("https://news.stanford.edu/feed/", "education"),
    ("https://news.harvard.edu/gazette/feed/", "education"),
    # development
    ("https://stackoverflow.com/feeds/tag?tagnames=python&sort=newest", "development"),
    ("https://stackoverflow.com/feeds/tag?tagnames=javascript&sort=newest", "development"),
    ("https://stackoverflow.com/feeds/tag?tagnames=machine-learning&sort=newest", "development"),
    ("https://peps.python.org/peps.rss", "development"),
    ("https://hnrss.org/frontpage?count=100", "open_web"),
    ("https://hnrss.org/newest?points=50&count=100", "open_web"),
    ("https://www.openstreetmap.org/diary/rss", "other"),
    # government
    ("https://www.nasa.gov/feed/", "government"),
    ("https://www.gov.uk/search/news-and-communications.atom", "government"),
    # social / media
    ("https://www.reddit.com/r/python/.rss", "social"),
    ("https://www.reddit.com/r/programming/.rss", "social"),
    ("https://www.reddit.com/r/worldnews/.rss", "social"),
    ("https://www.reddit.com/r/technology/.rss", "social"),
    ("https://www.reddit.com/r/science/.rss", "social"),
    ("https://www.youtube.com/feeds/videos.xml?channel_id=UC8butISFwT-Wl7EV0hUK0BQ", "video_media"),
    ("https://www.youtube.com/feeds/videos.xml?channel_id=UCsBjURrPoezykLs9EqgamOA", "video_media"),
    ("https://www.youtube.com/feeds/videos.xml?channel_id=UCAuUUnT6oDeKwE6v1NGQxug", "video_media"),
    ("https://www.youtube.com/feeds/videos.xml?channel_id=UCHnyfMqiRRG1u-2MsSQLbXA", "video_media"),
    # Wikipedia recent changes (diff/oldid URLs with multiple query params)
    ("https://en.wikipedia.org/w/api.php?action=feedrecentchanges&feedformat=atom&limit=500&namespace=0", "search"),
    ("https://de.wikipedia.org/w/api.php?action=feedrecentchanges&feedformat=atom&limit=500&namespace=0", "search"),
    ("https://fr.wikipedia.org/w/api.php?action=feedrecentchanges&feedformat=atom&limit=500&namespace=0", "search"),
    ("https://es.wikipedia.org/w/api.php?action=feedrecentchanges&feedformat=atom&limit=500&namespace=0", "search"),
]
for _repo in ["python/cpython", "pallets/flask", "facebook/react", "pytorch/pytorch",
              "scikit-learn/scikit-learn", "vitejs/vite", "microsoft/vscode",
              "kubernetes/kubernetes", "nodejs/node", "tensorflow/tensorflow",
              "huggingface/transformers", "django/django"]:
    FEEDS.append((f"https://github.com/{_repo}/releases.atom", "development"))
    FEEDS.append((f"https://github.com/{_repo}/tags.atom", "development"))

# ----------------------------------------------------------------------------
# Domain -> category map (longest-suffix match; falls back to the source category)
# ----------------------------------------------------------------------------
SUFFIX_MAP = {}
ALL_SEEDS = []
for _cat, _doms in SEEDS.items():
    for _d in _doms:
        if _d not in SUFFIX_MAP:
            SUFFIX_MAP[_d] = _cat
            ALL_SEEDS.append((_d, _cat))
for _extra in ["aws.amazon.com", "youtu.be", "wikimedia.org", "wikidata.org"]:
    SUFFIX_MAP.setdefault(_extra, "development" if "aws" in _extra else "video_media" if "youtu" in _extra else "search")


def category_for_host(host):
    labels = host.split(".")
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        if cand in SUFFIX_MAP:
            return SUFFIX_MAP[cand]
    return None


# ----------------------------------------------------------------------------
# Validation / normalization
# ----------------------------------------------------------------------------
BAD_CHARS = re.compile(r'[\s\x00-\x1f\x7f<>"\\{}^`]')
LABEL_RE = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
TLD_RE = re.compile(r'^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$')
INTERNAL_TLDS = {"local", "localhost", "internal", "lan", "home", "corp", "intranet", "test",
                 "example", "invalid", "localdomain", "arpa", "onion", "private", "lab"}
PCT_RE = re.compile(r'%[0-9a-fA-F]{2}')
SAFE_CHARS = "/%:@!$&'()*+,;=-._~"


def to_ascii(url):
    try:
        url.encode("ascii")
        return url
    except UnicodeEncodeError:
        pass
    s = urlsplit(url)
    netloc = s.netloc.encode("idna").decode("ascii")
    return urlunsplit((s.scheme, netloc, quote(s.path, safe=SAFE_CHARS),
                       quote(s.query, safe=SAFE_CHARS + "?"),
                       quote(s.fragment, safe=SAFE_CHARS + "?")))


def validate(raw):
    """Return (clean_url, None) if acceptable, else (None, reason)."""
    if not raw or not isinstance(raw, str):
        return None, "empty"
    url = raw.strip()
    if len(url) < 10:
        return None, "too_short"
    if len(url) > 2048:
        return None, "too_long"
    if not re.match(r'^https?://', url, re.I):
        return None, "non_http_scheme"
    try:
        url = to_ascii(url)
    except Exception:
        return None, "encoding_error"
    if BAD_CHARS.search(url):
        return None, "malformed_chars"
    try:
        s = urlsplit(url)
        port = s.port
        host = s.hostname
    except ValueError:
        return None, "parse_error"
    if not host:
        return None, "no_host"
    if "@" in s.netloc:
        return None, "userinfo_in_url"
    if port == 0:
        return None, "bad_port"
    host = host.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        return None, ("private_or_reserved_ip" if not ip.is_global else "ip_literal_host")
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2 or len(host) > 253:
        return None, "bad_host"
    if not all(LABEL_RE.match(x) for x in labels) or not TLD_RE.match(labels[-1]):
        return None, "bad_host"
    if labels[-1] in INTERNAL_TLDS:
        return None, "internal_host"
    return url, None


def _up(m):
    return m.group(0).upper()


def normalize_url(url):
    s = urlsplit(url)
    scheme = s.scheme.lower()
    host = s.hostname.lower().rstrip(".")
    port = s.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host += f":{port}"
    path = PCT_RE.sub(_up, s.path) or "/"
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    out = f"{scheme}://{host}{path}"
    if s.query:
        out += "?" + PCT_RE.sub(_up, s.query)
    if s.fragment:
        out += "#" + PCT_RE.sub(_up, s.fragment)
    return out


# ----------------------------------------------------------------------------
# Structure classification
# ----------------------------------------------------------------------------
TRACKING_KEYS = {"fbclid", "gclid", "msclkid", "dclid", "yclid", "igshid", "mc_cid", "mc_eid",
                 "_ga", "_gl", "ref", "ref_src", "ref_url", "referrer", "trk", "trkid",
                 "trackingid", "tracking_id", "spm", "scid", "sc_cid", "ocid", "ito", "xtor",
                 "cmpid", "si", "feature", "pf_rd_r", "pf_rd_p", "pd_rd_r", "pd_rd_w",
                 "pd_rd_wg", "ved", "ei", "sxsrf", "sca_esv", "source", "src", "campaign"}
SEARCH_KEYS = {"q", "query", "search", "search_query", "searchterm", "keyword", "keywords",
               "k", "_nkw", "term", "wd"}
PAGE_KEYS = {"page", "p", "pg", "paged", "pagenum", "start", "offset", "skip", "cursor", "after"}
REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "huggingface.co")
MEDIA_SEGS = {"watch", "video", "videos", "embed", "track", "tracks", "album", "playlist",
              "podcast", "podcasts", "shorts", "reel", "reels", "photo", "photos", "image",
              "images", "audio", "live", "clip", "clips", "episode", "episodes", "stream"}
MEDIA_EXT = {"mp4", "mp3", "webm", "m4a", "mov", "jpg", "jpeg", "png", "gif", "webp", "svg",
             "wav", "ogg", "m3u8"}
MEDIA_HOSTS = ("youtu.be", "youtube.com", "vimeo.com", "twitch.tv", "soundcloud.com",
               "spotify.com", "tiktok.com", "instagram.com")
ARTICLE_RE = re.compile(r'/(news|article|articles|blog|blogs|story|stories|post|posts|wiki|press|'
                        r'press-releases|magazine|opinion|world|science|technology|business|politics)(/|$)')
DATE_RE = re.compile(r'/(19|20)\d{2}/\d{1,2}(/\d{1,2})?(/|$)')
PRODUCT_SEGS = {"dp", "product", "products", "item", "itm", "ip", "sku", "listing", "listings"}
PROFILE_SEGS = {"user", "users", "u", "profile", "profiles", "in", "channel", "c", "people",
                "author", "authors", "member", "members"}
DOC_SEGS = {"docs", "doc", "documentation", "reference", "manual", "guide", "guides", "tutorial",
            "tutorials", "learn", "handbook", "howto", "library"}
LOGIN_SEGS = {"login", "signin", "sign-in", "log-in", "logon", "sso", "oauth", "oauth2",
              "authorize", "auth", "signup", "sign-up", "register"}
ACCOUNT_SEGS = {"account", "accounts", "myaccount", "my-account", "billing", "dashboard",
                "subscription", "subscriptions"}
SETTINGS_SEGS = {"settings", "setting", "preferences", "preference", "options",
                 "privacy-settings", "config", "configuration"}
API_SEGS = {"api", "rest", "graphql", "ajax", "oembed", "wp-json", "_api"}


def structure_types(url):
    s = urlsplit(url)
    host = (s.hostname or "").lower()
    path = s.path or "/"
    low = path.lower()
    segs = [x.lower() for x in path.split("/") if x]
    params = parse_qsl(s.query, keep_blank_values=True)
    keys = [k.lower() for k, _ in params]
    seg_set = set(segs)
    t = []
    if not segs and not s.query and not s.fragment:
        t.append("homepage")
    if segs:
        t.append("path")
    if len(segs) >= 2:
        t.append("multi_path")
    if len(segs) >= 3:
        t.append("deep_path")
    if s.query:
        t.append("query")
    if len(params) >= 2:
        t.append("multi_query")
    if any(k.startswith("utm_") or k in TRACKING_KEYS for k in keys):
        t.append("tracking")
    if s.fragment:
        t.append("fragment")
    if PCT_RE.search(url):
        t.append("encoded")
    if len(url) > 120:
        t.append("long_url")
    if len(url) > 200:
        t.append("very_long_url")
    if (any(re.fullmatch(r"\d{3,}", x) and not re.fullmatch(r"(19|20)\d{2}", x) for x in segs)
            or re.search(r"\d{5,}", path)
            or any(re.fullmatch(r"\d{3,}", v) for _, v in params)):
        t.append("numeric_id")
    if (set(keys) & SEARCH_KEYS or re.search(r"(^|/)(search|find|results)(/|$)", low)
            or host.startswith("search.")):
        t.append("search")
    if ARTICLE_RE.search(low + "/") or DATE_RE.search(low + "/"):
        t.append("article")
    if seg_set & PRODUCT_SEGS:
        t.append("product")
    if (segs and segs[0] in PROFILE_SEGS) or any(x.startswith("@") for x in segs) or \
            (host.endswith(("github.com", "gitlab.com")) and len(segs) == 1):
        t.append("profile")
    if (seg_set & DOC_SEGS or host.startswith(("docs.", "developer.", "developers.", "learn."))
            or "readthedocs" in host):
        t.append("documentation")
    if (host.endswith(REPO_HOSTS) and len(segs) >= 2) or \
            seg_set & {"tree", "blob", "commit", "commits", "pull", "pulls", "issues", "releases", "tags"} or \
            (host.endswith("pypi.org") and segs[:1] == ["project"]) or \
            (host.endswith("npmjs.com") and segs[:1] == ["package"]):
        t.append("repository")
    if seg_set & LOGIN_SEGS or host.startswith(("login.", "signin.", "sso.", "auth.")):
        t.append("login")
    if seg_set & ACCOUNT_SEGS or host.startswith(("account.", "accounts.", "myaccount.")):
        t.append("account")
    if seg_set & SETTINGS_SEGS:
        t.append("settings")
    last = segs[-1] if segs else ""
    ext = last.rsplit(".", 1)[-1] if "." in last else ""
    if segs and (seg_set & MEDIA_SEGS or ext in MEDIA_EXT or host.endswith(MEDIA_HOSTS)):
        t.append("media")
    if set(keys) & PAGE_KEYS or re.search(r"/page[/-]\d+", low):
        t.append("pagination")
    if (seg_set & API_SEGS or re.search(r"/v\d+(\.\d+)?(/|$)", low) or ext in ("json", "xml")
            or host.startswith("api.") or set(keys) & {"callback", "jsonp"}):
        t.append("api_like")
    return t


# ----------------------------------------------------------------------------
# Collector (thread-safe)
# ----------------------------------------------------------------------------
class Collector:
    def __init__(self, existing, target):
        self.lock = threading.Lock()
        self.existing = existing
        self.target = target
        self.stop = threading.Event()
        self.seen = set()
        self.rows = []
        self.total_candidates = 0
        self.rejected = 0
        self.reject_reasons = Counter()
        self.duplicates = 0
        self.existing_overlap = 0
        self.per_source = Counter()
        self.per_source_seen = Counter()
        self.per_method = Counter()
        self.sources = {}
        self.task_failures = 0

    def register(self, source, method):
        with self.lock:
            self.sources.setdefault(source, {"method": method, "errors": Counter()})

    def note_error(self, source, msg):
        with self.lock:
            self.sources.setdefault(source, {"method": "?", "errors": Counter()})["errors"][msg] += 1

    def add(self, raw, source, method, fallback_category):
        if self.stop.is_set():
            return False
        url, reason = validate(raw)
        if url is None:
            with self.lock:
                self.total_candidates += 1
                self.per_source_seen[source] += 1
                self.rejected += 1
                self.reject_reasons[reason] += 1
            return False
        norm = normalize_url(url)
        host = urlsplit(norm).hostname
        category = category_for_host(host) or fallback_category
        types = structure_types(url)
        with self.lock:
            self.total_candidates += 1
            self.per_source_seen[source] += 1
            if norm in self.existing:
                self.existing_overlap += 1
                return False
            if norm in self.seen:
                self.duplicates += 1
                return False
            self.seen.add(norm)
            self.rows.append({"url": url, "normalized_url": norm, "label": 0, "source": source,
                              "category": category, "structure_type": "|".join(types),
                              "collection_method": method, "_host": host})
            self.per_source[source] += 1
            self.per_method[method] += 1
            if len(self.rows) >= self.target:
                self.stop.set()
        return True


# ----------------------------------------------------------------------------
# HTTP with per-host rate limiting
# ----------------------------------------------------------------------------
class HostLimiter:
    def __init__(self, default_interval, overrides):
        self.default = default_interval
        self.overrides = overrides
        self.lock = threading.Lock()
        self.next_time = {}

    def wait(self, host):
        interval = self.overrides.get(host, self.default)
        with self.lock:
            now = time.monotonic()
            t = max(now, self.next_time.get(host, 0.0))
            self.next_time[host] = t + interval
        delay = t - now
        if delay > 0:
            time.sleep(delay)


class Http:
    def __init__(self, ua, limiter, timeout, collector):
        self.ua = ua
        self.limiter = limiter
        self.timeout = timeout
        self.collector = collector
        self.local = threading.local()

    def _session(self):
        s = getattr(self.local, "s", None)
        if s is None:
            s = requests.Session()
            s.headers.update({"User-Agent": self.ua, "Accept": "*/*"})
            self.local.s = s
        return s

    def get(self, url, params=None, source="", max_bytes=25_000_000, retries=2,
            timeout=None, headers=None):
        host = urlsplit(url).hostname
        last = "unknown"
        for attempt in range(retries + 1):
            if self.collector.stop.is_set():
                return None
            self.limiter.wait(host)
            try:
                r = self._session().get(url, params=params, headers=headers, stream=True,
                                        timeout=timeout or self.timeout)
            except requests.RequestException as e:
                last = type(e).__name__
                time.sleep(1.5 * (attempt + 1))
                continue
            if r.status_code in (429, 503):
                ra = r.headers.get("Retry-After", "")
                wait = min(int(ra) if ra.isdigit() else 5 * (attempt + 1), 60)
                last = f"HTTP {r.status_code}"
                r.close()
                time.sleep(wait)
                continue
            if r.status_code != 200:
                self.collector.note_error(source, f"HTTP {r.status_code}")
                r.close()
                return None
            body = bytearray()
            try:
                for chunk in r.iter_content(65536):
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        break
            except requests.RequestException as e:
                last = type(e).__name__
                r.close()
                continue
            r.close()
            return bytes(body)
        self.collector.note_error(source, last)
        return None

    def get_json(self, url, **kw):
        body = self.get(url, **kw)
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8", errors="replace"))
        except ValueError:
            self.collector.note_error(kw.get("source", ""), "bad_json")
            return None


def decode_body(data):
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.GzipFile(fileobj=io.BytesIO(data)).read(200_000_000)
        except Exception:
            return ""
    return data.decode("utf-8", errors="replace")


# ----------------------------------------------------------------------------
# Source tasks
# ----------------------------------------------------------------------------
LOC_RE = re.compile(r"<loc>\s*(?:<!\[CDATA\[)?\s*(.*?)\s*(?:\]\]>)?\s*</loc>", re.I | re.S)
ITEM_RE = re.compile(r"<(item|entry)\b.*?</\1>", re.I | re.S)
LINKTAG_RE = re.compile(r"<link\b[^>]*>", re.I)
HREF_RE = re.compile(r"""href=["']([^"']+)["']""", re.I)
LINKTEXT_RE = re.compile(r"<link\b[^>]*>\s*(?:<!\[CDATA\[)?\s*(https?://[^<\]\s]+)", re.I)


def task_sitemap(ctx, domain, category):
    source = f"sitemap:{domain}"
    col, http = ctx.collector, ctx.http
    col.register(source, "sitemap")
    bases = [f"https://{domain}"]
    if domain.count(".") == 1:
        bases.append(f"https://www.{domain}")
    candidates, robots = [], None
    for base in bases:
        robots = http.get(base + "/robots.txt", source=source, max_bytes=500_000, retries=1)
        if robots:
            for line in robots.decode("utf-8", errors="replace").splitlines():
                if line.lower().startswith("sitemap:"):
                    candidates.append(line.split(":", 1)[1].strip())
        candidates += [base + "/sitemap.xml", base + "/sitemap_index.xml"]
        if robots:
            break
    queue, visited, fetched, got = [], set(), 0, 0
    for u in dict.fromkeys(candidates):
        queue.append((u, 0))
    cap = ctx.args.sitemap_cap
    per_file = max(50, cap // 3)
    while queue and got < cap and fetched < ctx.args.max_sitemap_files and not col.stop.is_set():
        u, depth = queue.pop(0)
        if u in visited:
            continue
        visited.add(u)
        data = http.get(u, source=source, max_bytes=30_000_000, retries=1)
        if not data:
            continue
        text = decode_body(data)
        locs = [html.unescape(x).strip() for x in LOC_RE.findall(text)]
        if not locs:
            continue
        fetched += 1
        if "<sitemapindex" in text[:5000].lower():
            if depth < 2:
                ctx.rng.shuffle(locs)
                queue = [(x, depth + 1) for x in locs[:30]] + queue
            continue
        if len(locs) > per_file:
            locs = ctx.rng.sample(locs, per_file)
        for loc in locs:
            if got >= cap:
                break
            if col.add(loc, source, "sitemap", category):
                got += 1


def extract_feed_links(text):
    links = []
    for m in ITEM_RE.finditer(text):
        block = m.group(0)
        link = None
        for tag in LINKTAG_RE.findall(block):
            if "rel=" in tag.lower() and "alternate" not in tag.lower():
                continue
            h = HREF_RE.search(tag)
            if h:
                link = h.group(1)
                break
        if not link:
            t = LINKTEXT_RE.search(block)
            if t:
                link = t.group(1)
        if link:
            links.append(html.unescape(link).strip())
    return links


def task_feed(ctx, feed_url, category):
    host = urlsplit(feed_url).hostname
    source = f"feed:{host}"
    ctx.collector.register(source, "feed")
    data = ctx.http.get(feed_url, source=source, max_bytes=10_000_000, retries=1)
    if not data:
        return
    for link in extract_feed_links(decode_body(data)):
        ctx.collector.add(link, source, "feed", category)


def task_hackernews(ctx):
    source = "hackernews:algolia"
    ctx.collector.register(source, "hackernews")
    now, window = int(time.time()), 3 * 86400
    for i in range(ctx.args.hn_windows):
        if ctx.collector.stop.is_set():
            return
        hi = now - i * window
        data = ctx.http.get_json(
            "https://hn.algolia.com/api/v1/search_by_date", source=source,
            params={"tags": "story", "hitsPerPage": 1000,
                    "numericFilters": f"created_at_i>{hi - window},created_at_i<{hi}"})
        if not data:
            continue
        for hit in data.get("hits", []):
            if hit.get("url"):
                ctx.collector.add(hit["url"], source, "hackernews", "open_web")


def task_wiki_extlinks(ctx, domain, category):
    source = f"wikipedia_extlinks:{domain}"
    ctx.collector.register(source, "wikipedia_extlinks")
    params = {"action": "query", "list": "exturlusage", "euquery": f"*.{domain}",
              "euprotocol": "https", "eulimit": 500, "eunamespace": 0,
              "euprop": "url", "format": "json"}
    got, pages = 0, 0
    while got < ctx.args.wiki_cap and pages < 6 and not ctx.collector.stop.is_set():
        data = ctx.http.get_json("https://en.wikipedia.org/w/api.php", params=params,
                                 source=source, retries=1)
        if not data:
            return
        pages += 1
        for item in data.get("query", {}).get("exturlusage", []):
            if ctx.collector.add(item.get("url", ""), source, "wikipedia_extlinks", category):
                got += 1
        cont = data.get("continue")
        if not cont:
            return
        params.update(cont)


def task_github(ctx):
    source = "github_api:search_repositories"
    ctx.collector.register(source, "github_api")
    queries = ["stars:>20000", "language:python stars:>3000", "language:javascript stars:>3000",
               "language:typescript stars:>2000", "topic:machine-learning stars:>1000",
               "topic:security stars:>1000"]
    for q in queries:
        for page in range(1, ctx.args.github_pages + 1):
            if ctx.collector.stop.is_set():
                return
            data = ctx.http.get_json(
                "https://api.github.com/search/repositories", source=source, retries=0,
                params={"q": q, "sort": "stars", "order": "desc", "per_page": 100, "page": page},
                headers={"Accept": "application/vnd.github+json"})
            items = (data or {}).get("items", [])
            if not items:
                break
            for it in items:
                ctx.collector.add(it.get("html_url", ""), source, "github_api", "development")
                hp = it.get("homepage") or ""
                if hp.lower().startswith(("http://", "https://")):
                    ctx.collector.add(hp, source, "github_api", "open_web")


def task_wayback(ctx, domain, category):
    source = f"wayback:{domain}"
    ctx.collector.register(source, "wayback_cdx")
    lim = ctx.args.wayback_limit
    modes = [(lim, []),
             (max(20, lim // 2), [("filter", "original:.*[?].*")]),
             (max(20, lim // 2),
              [("filter", "original:.*(login|signin|sign-in|account|settings|preferences).*")])]
    for limit, extra in modes:
        if ctx.collector.stop.is_set():
            return
        params = [("url", domain), ("matchType", "domain"), ("fl", "original"),
                  ("collapse", "urlkey"), ("filter", "statuscode:200"),
                  ("filter", "mimetype:text/html"), ("limit", str(limit))] + extra
        data = ctx.http.get("https://web.archive.org/cdx/search/cdx", params=params,
                            source=source, max_bytes=20_000_000, retries=1, timeout=90)
        if not data:
            continue
        for line in data.decode("utf-8", errors="replace").splitlines():
            ctx.collector.add(line.strip(), source, "wayback_cdx", category)


def task_commoncrawl(ctx, domain, category):
    source = f"commoncrawl:{domain}"
    ctx.collector.register(source, "commoncrawl")
    lim = ctx.args.cc_limit
    modes = [(lim, []), (max(20, lim // 2), [("filter", "~url:[?]")])]
    for limit, extra in modes:
        if ctx.collector.stop.is_set():
            return
        params = [("url", domain), ("matchType", "domain"), ("output", "json"), ("fl", "url"),
                  ("filter", "=status:200"), ("filter", "=mime:text/html"),
                  ("limit", str(limit))] + extra
        data = ctx.http.get(ctx.cc_api, params=params, source=source, max_bytes=20_000_000,
                            retries=1, timeout=90)
        if not data:
            continue
        for line in data.decode("utf-8", errors="replace").splitlines():
            try:
                u = json.loads(line).get("url")
            except ValueError:
                continue
            if u:
                ctx.collector.add(u, source, "commoncrawl", category)


# ----------------------------------------------------------------------------
# Existing dataset loading (read-only)
# ----------------------------------------------------------------------------
def load_existing(path):
    existing = set()
    if not path:
        return existing
    if not os.path.isfile(path):
        print(f"[warn] existing dataset not found: {path} (continuing without it)")
        return existing
    csv.field_size_limit(min(sys.maxsize, 2 ** 31 - 1))
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header is None:
            return existing
        col, rows = 0, []
        names = [h.strip().lower() for h in header]
        found = next((names.index(n) for n in ("normalized_url", "url", "urls", "link")
                      if n in names), None)
        if found is not None:
            col = found
        elif header and re.match(r"^https?://", header[0].strip(), re.I):
            rows.append(header)
        for row in list(rows) + list(reader):
            if len(row) > col:
                u, _ = validate(row[col])
                if u:
                    existing.add(normalize_url(u))
    print(f"[info] loaded {len(existing):,} URLs from existing dataset (read-only)")
    return existing


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------
def compute_stats(rows):
    st = Counter()
    cats, structs, hosts = Counter(), Counter(), set()
    for r in rows:
        types = r["structure_type"].split("|") if r["structure_type"] else []
        tset = set(types)
        hosts.add(r["_host"][4:] if r["_host"].startswith("www.") else r["_host"])
        cats[r["category"]] += 1
        for t in types:
            structs[t] += 1
        st["with_path"] += "path" in tset
        st["with_query"] += "query" in tset
        st["with_fragment"] += "fragment" in tset
        st["with_tracking"] += "tracking" in tset
        st["with_percent_encoding"] += "encoded" in tset
        st["over_120_chars"] += "long_url" in tset
        st["over_200_chars"] += "very_long_url" in tset
        st["multi_path"] += "multi_path" in tset
        st["search"] += "search" in tset
        st["login_account_settings"] += bool(tset & {"login", "account", "settings"})
    return st, cats, structs, len(hosts)


def print_report(c, rows, st, cats, structs, n_hosts):
    n = len(rows)
    print("\n" + "=" * 62)
    print("QUALITY REPORT")
    print("=" * 62)
    print(f"total collected (candidates seen)   : {c.total_candidates:,}")
    print(f"unique normalized URLs              : {n:,}")
    print(f"unique domains (hosts, www stripped): {n_hosts:,}")
    for label, key in [("URLs containing paths", "with_path"),
                       ("URLs containing queries", "with_query"),
                       ("URLs containing fragments", "with_fragment"),
                       ("URLs with tracking parameters", "with_tracking"),
                       ("URLs with percent encoding", "with_percent_encoding"),
                       ("URLs > 120 characters", "over_120_chars"),
                       ("URLs > 200 characters", "over_200_chars"),
                       ("multi-path URLs (>=2 segments)", "multi_path"),
                       ("search URLs", "search"),
                       ("login/account/settings URLs", "login_account_settings")]:
        pct = (100.0 * st[key] / n) if n else 0.0
        print(f"{label:<36}: {st[key]:,} ({pct:.1f}%)")
    print(f"rejected URLs                       : {c.rejected:,}")
    print(f"duplicates within run               : {c.duplicates:,}")
    print(f"overlap with existing dataset       : {c.existing_overlap:,}")
    print("\nCounts by category:")
    for k, v in cats.most_common():
        print(f"  {k:<22}{v:>9,}")
    print("\nCounts by structure_type:")
    for k, v in structs.most_common():
        print(f"  {k:<22}{v:>9,}")
    print("\nCounts by collection_method:")
    for k, v in c.per_method.most_common():
        print(f"  {k:<22}{v:>9,}")
    if n < 50_000:
        print(f"\n[warn] only {n:,} URLs collected (< 50,000). Re-run with larger caps, e.g. "
              f"--sitemap-cap 1500 --wayback-limit 1000 --cc-limit 1000 --hn-windows 120, "
              f"or check network access to the sources.")


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Collect real legitimate URLs (label=0).")
    p.add_argument("--existing", help="optional existing legitimate dataset CSV (read-only) for overlap detection")
    p.add_argument("--output-dir", default=".", help="where to write the CSV/JSON (default: current dir)")
    p.add_argument("--target", type=int, default=150000, help="stop early after this many unique URLs")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--delay", type=float, default=1.0, help="min seconds between requests to the same host")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--contact", default="student-research-project",
                   help="contact string placed in the User-Agent (e.g. your email)")
    p.add_argument("--sitemap-cap", type=int, default=700, help="max URLs per domain from sitemaps")
    p.add_argument("--max-sitemap-files", type=int, default=8)
    p.add_argument("--wayback-limit", type=int, default=400)
    p.add_argument("--cc-limit", type=int, default=400)
    p.add_argument("--wiki-cap", type=int, default=400)
    p.add_argument("--hn-windows", type=int, default=60, help="3-day windows of HN stories (~1000 each)")
    p.add_argument("--github-pages", type=int, default=3)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--quick", action="store_true", help="small smoke-test run")
    for name in ("sitemaps", "feeds", "open-web", "wayback", "commoncrawl", "github"):
        p.add_argument(f"--no-{name}", action="store_true", help=f"skip {name}")
    return p.parse_args()


def main():
    args = parse_args()
    seeds, feeds = list(ALL_SEEDS), list(FEEDS)
    if args.quick:
        args.sitemap_cap, args.wayback_limit, args.cc_limit = 100, 50, 50
        args.wiki_cap, args.hn_windows, args.github_pages = 100, 3, 1
        per_cat, seeds = Counter(), []
        for d, cat in ALL_SEEDS:
            if per_cat[cat] < 2:
                seeds.append((d, cat))
                per_cat[cat] += 1
        feeds = feeds[:10]
    os.makedirs(args.output_dir, exist_ok=True)
    started = datetime.now(timezone.utc)

    existing = load_existing(args.existing)
    col = Collector(existing, args.target)
    limiter = HostLimiter(args.delay, {"web.archive.org": max(2.0, args.delay),
                                       "index.commoncrawl.org": max(1.5, args.delay),
                                       "api.github.com": 6.5, "hn.algolia.com": 0.5})
    ua = f"LegitURLCollector/1.0 (phishing-detector dataset research; contact: {args.contact})"
    http = Http(ua, limiter, args.timeout, col)
    ctx = SimpleNamespace(http=http, collector=col, args=args, rng=random.Random(args.seed), cc_api=None)

    if not args.no_commoncrawl:
        info = http.get_json("https://index.commoncrawl.org/collinfo.json", source="commoncrawl:collinfo")
        if info:
            ctx.cc_api = info[0].get("cdx-api")
        if not ctx.cc_api:
            print("[warn] Common Crawl index unavailable; skipping it")

    tasks = []
    if not args.no_feeds:
        tasks += [(task_feed, (ctx, u, c)) for u, c in feeds]
    if not args.no_open_web:
        tasks.append((task_hackernews, (ctx,)))
    if not args.no_github:
        tasks.append((task_github, (ctx,)))
    if not args.no_open_web:
        seed_doms = {d for d, _ in seeds}
        for d, c in seeds:
            if any(d != o and d.endswith("." + o) for o in seed_doms):
                continue  # parent domain query already covers subdomains
            tasks.append((task_wiki_extlinks, (ctx, d, c)))
    if not args.no_sitemaps:
        tasks += [(task_sitemap, (ctx, d, c)) for d, c in seeds]
    if not args.no_wayback:
        tasks += [(task_wayback, (ctx, d, c)) for d, c in seeds]
    if ctx.cc_api and not args.no_commoncrawl:
        tasks += [(task_commoncrawl, (ctx, d, c)) for d, c in seeds]

    print(f"[info] {len(tasks)} collection tasks queued, {args.workers} workers. "
          f"A full run can take 30-90+ minutes (Ctrl+C saves partial results).")

    def safe_run(fn, a):
        try:
            fn(*a)
        except Exception as e:  # keep going on any source failure
            with col.lock:
                col.task_failures += 1
            print(f"[warn] task {fn.__name__} failed: {type(e).__name__}: {e}", file=sys.stderr)

    ex = ThreadPoolExecutor(max_workers=args.workers)
    futs = [ex.submit(safe_run, fn, a) for fn, a in tasks]
    done, last = 0, time.time()
    try:
        for _ in as_completed(futs):
            done += 1
            if time.time() - last > 10 or done == len(futs):
                print(f"[progress] tasks {done}/{len(futs)} | unique {len(col.rows):,} | "
                      f"rejected {col.rejected:,} | dupes {col.duplicates:,}")
                last = time.time()
    except KeyboardInterrupt:
        print("\n[info] interrupted - saving partial results ...")
        col.stop.set()
        for f in futs:
            f.cancel()
    finally:
        ex.shutdown(wait=True, cancel_futures=True)

    rows = col.rows
    csv_path = os.path.join(args.output_dir, OUT_CSV)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    st, cats, structs, n_hosts = compute_stats(rows)
    print_report(col, rows, st, cats, structs, n_hosts)

    sources = []
    for name, info in sorted(col.sources.items()):
        sources.append({"source": name, "method": info["method"],
                        "candidates_seen": col.per_source_seen.get(name, 0),
                        "accepted_unique": col.per_source.get(name, 0),
                        "errors": dict(info["errors"])})
    report = {
        "started_utc": started.isoformat(),
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "parameters": {k: v for k, v in vars(args).items()},
        "collection_sources": sources,
        "counts_per_source": dict(col.per_source.most_common()),
        "counts_per_collection_method": dict(col.per_method.most_common()),
        "total_candidates_seen": col.total_candidates,
        "rejected_url_count": col.rejected,
        "rejection_reasons": dict(col.reject_reasons.most_common()),
        "duplicate_count": col.duplicates,
        "existing_dataset_urls_loaded": len(existing),
        "existing_dataset_overlap_count": col.existing_overlap,
        "task_failures": col.task_failures,
        "unique_domains": n_hosts,
        "category_distribution": dict(cats.most_common()),
        "structure_distribution": dict(structs.most_common()),
        "quality_summary": dict(st),
        "final_dataset_size": len(rows),
    }
    json_path = os.path.join(args.output_dir, OUT_JSON)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n[done] wrote {csv_path} ({len(rows):,} rows)")
    print(f"[done] wrote {json_path}")


if __name__ == "__main__":
    main()