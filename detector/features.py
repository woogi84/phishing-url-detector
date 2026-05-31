import re
import urllib.parse
import tldextract

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "paypal", "apple", "amazon", "google", "microsoft",
    "password", "credential", "confirm", "wallet", "support"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "short.link", "rebrand.ly", "cutt.ly"
]


def extract_features(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    ext = tldextract.extract(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full_url = url.lower()

    features = {
        "url_length": len(url),
        "has_ip": _is_ip(hostname),
        "has_https": parsed.scheme == "https",
        "dot_count": url.count("."),
        "hyphen_count": hostname.count("-"),
        "at_symbol": "@" in url,
        "double_slash": url.count("//") > 1,
        "subdomain_count": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "suspicious_keywords": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_url),
        "is_shortened": any(s in hostname for s in URL_SHORTENERS),
        "special_char_count": len(re.findall(r"[%=?&]", url)),
        "digit_in_domain": sum(c.isdigit() for c in ext.domain),
    }
    return features


def _is_ip(hostname: str) -> bool:
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return bool(re.match(pattern, hostname))
