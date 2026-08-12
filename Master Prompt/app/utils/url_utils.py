from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse

SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "rebrand.ly", "is.gd", "cutt.ly", "ow.ly"
}
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "secure", "account", "password", "wallet",
    "bank", "payment", "update", "confirm", "signin",
}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    return urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, ""))


def extract_hostname(url: str) -> str:
    return urlparse(normalize_url(url)).hostname or ""


def is_ip_address_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False

