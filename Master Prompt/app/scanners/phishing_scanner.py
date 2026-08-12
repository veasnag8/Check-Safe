from __future__ import annotations

from dataclasses import dataclass

from app.utils.url_utils import SHORTENER_DOMAINS, SUSPICIOUS_KEYWORDS, extract_hostname, is_ip_address_hostname, normalize_url


@dataclass
class PhishingResult:
    score: int
    reasons: list[str]
    indicators: list[dict]
    checks: dict
    verdict: str | None = None


def scan_url(url: str, weights: dict[str, int] | None = None) -> PhishingResult:
    weights = weights or {
        "punycode": 20,
        "ip_address": 25,
        "shortener": 10,
        "keyword": 5,
        "subdomains": 10,
        "suspicious_tld": 10,
        "http_login": 15,
        "hyphen": 5,
    }
    normalized = normalize_url(url)
    hostname = extract_hostname(normalized)
    score = 0
    reasons: list[str] = []
    indicators: list[dict] = []
    checks = {"https": normalized.startswith("https://"), "hostname": hostname}
    if hostname.startswith("xn--") or "xn--" in hostname:
        score += weights["punycode"]; reasons.append("Punycode / Unicode domain"); indicators.append({"indicator_type": "punycode", "description": hostname, "severity": "medium", "score": weights["punycode"]})
    if is_ip_address_hostname(hostname):
        score += weights["ip_address"]; reasons.append("IP address used instead of domain"); indicators.append({"indicator_type": "ip", "description": hostname, "severity": "high", "score": weights["ip_address"]})
    if any(hostname.endswith(d) for d in SHORTENER_DOMAINS):
        score += weights["shortener"]; reasons.append("URL shortener detected"); indicators.append({"indicator_type": "shortener", "description": hostname, "severity": "low", "score": weights["shortener"]})
    if sum(1 for p in hostname.split(".") if p) > 4:
        score += weights["subdomains"]; reasons.append("Excessive subdomains"); indicators.append({"indicator_type": "subdomains", "description": hostname, "severity": "medium", "score": weights["subdomains"]})
    if any(k in normalized.lower() for k in SUSPICIOUS_KEYWORDS):
        score += weights["keyword"]; reasons.append("Suspicious keyword detected"); indicators.append({"indicator_type": "keyword", "description": normalized, "severity": "low", "score": weights["keyword"]})
    if "-" in hostname:
        score += weights["hyphen"]; reasons.append("Hyphenated domain"); indicators.append({"indicator_type": "hyphen", "description": hostname, "severity": "low", "score": weights["hyphen"]})
    if normalized.startswith("http://") and any(k in normalized.lower() for k in ("login", "signin", "verify", "account", "payment")):
        score += weights["http_login"]; reasons.append("HTTP login-like page"); indicators.append({"indicator_type": "http_login", "description": normalized, "severity": "medium", "score": weights["http_login"]})
    verdict = "SAFE" if score < 30 else "SUSPICIOUS" if score < 60 else "PHISHING"
    return PhishingResult(score=min(score, 100), reasons=reasons, indicators=indicators, checks=checks, verdict=verdict)

