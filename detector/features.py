import re
import urllib.parse
import tldextract

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "paypal", "apple", "amazon", "google", "microsoft",
    "password", "credential", "confirm", "wallet", "support",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "short.link", "rebrand.ly", "cutt.ly",
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "click", "work", "loan",
    "online", "site", "win", "download", "racing",
}

BRAND_NAMES = [
    "paypal", "apple", "amazon", "google", "microsoft", "facebook",
    "instagram", "netflix", "bankofamerica", "chase", "wellsfargo",
    "kakao", "naver", "samsung", "coupang", "toss",
]

_TYPO_TABLE = str.maketrans("013458@", "oieasba")


def extract_features(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    ext = tldextract.extract(url)
    hostname = parsed.hostname or ""
    full_url = url.lower()

    return {
        "url_length":          len(url),
        "has_ip":              _is_ip(hostname),
        "no_https":            parsed.scheme != "https",
        "dot_count":           url.count("."),
        "hyphen_count":        hostname.count("-"),
        "at_symbol":           "@" in url,
        "double_slash":        url.count("//") > 1,
        "subdomain_count":     len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "suspicious_keywords": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_url),
        "is_shortened":        any(s in hostname for s in URL_SHORTENERS),
        "special_char_count":  len(re.findall(r"[%=?&]", url)),
        "digit_in_domain":     sum(c.isdigit() for c in ext.domain),
        # v2 신규
        "suspicious_tld":      ext.suffix.lower() in SUSPICIOUS_TLDS,
        "brand_in_subdomain":  _check_brand_in_subdomain(ext),
        "punycode":            "xn--" in hostname,
        "non_standard_port":   _check_non_standard_port(parsed),
        "typosquatting":       _check_typosquatting(ext.domain.lower()),
    }


def _is_ip(hostname: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))


def _check_brand_in_subdomain(ext) -> bool:
    subdomain = ext.subdomain.lower()
    domain = ext.domain.lower()
    return any(
        brand in subdomain and brand not in domain
        for brand in BRAND_NAMES
    )


def _check_non_standard_port(parsed) -> bool:
    port = parsed.port
    return port is not None and port not in (80, 443)


def _check_typosquatting(domain: str) -> bool:
    normalized = domain.translate(_TYPO_TABLE)
    return any(
        normalized == brand and domain != brand
        for brand in BRAND_NAMES
    )
