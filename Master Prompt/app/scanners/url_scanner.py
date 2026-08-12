from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from app.scanners.phishing_scanner import scan_url as phishing_scan
from app.services.dns_service import DNSService
from app.services.safe_browsing import SafeBrowsingService
from app.services.virustotal import VirusTotalService
from app.utils.url_utils import extract_hostname, is_ip_address_hostname, normalize_url


@dataclass
class URLScanResult:
    target: str
    normalized_url: str
    score: int
    verdict: str
    reasons: list[str]
    indicators: list[dict]
    checks: dict
    recommendation: str


def validate_url(url: str) -> bool:
    try:
        parsed = urlparse(normalize_url(url))
        return bool(parsed.scheme and parsed.netloc)
    except Exception:
        return False


async def scan_url(url: str, dns: DNSService, vt: VirusTotalService, sb: SafeBrowsingService) -> URLScanResult:
    normalized = normalize_url(url)
    hostname = extract_hostname(normalized)
    score = 0
    reasons: list[str] = []
    indicators: list[dict] = []
    checks = {"url_syntax": validate_url(url), "https": normalized.startswith("https://"), "hostname": hostname, "dns": "not_checked", "reputation": "not_configured"}
    if not checks["url_syntax"]:
        reasons.append("Invalid URL syntax")
        score += 20
    if not normalized.startswith("https://"):
        score += 5; reasons.append("No HTTPS")
    if is_ip_address_hostname(hostname):
        score += 25; reasons.append("IP address URL")
    if len(hostname.split(".")) > 4:
        score += 10; reasons.append("Too many subdomains")
    if len(normalized) > 120:
        score += 5; reasons.append("Very long URL")
    if re.search(r":\d{3,5}", normalized):
        score += 5; reasons.append("Suspicious port")
    phishing = phishing_scan(normalized)
    score += phishing.score
    reasons.extend(phishing.reasons)
    indicators.extend(phishing.indicators)
    dns_result = await dns.lookup(hostname)
    checks["dns"] = dns_result["status"]
    if dns_result["status"] == "ok" and dns_result.get("suspicious"):
        score += 10; reasons.append("DNS lookup indicates unusual result")
    vt_result = await vt.check_url(normalized)
    checks["reputation"] = vt_result["status"]
    if vt_result.get("score", 0) > 0:
        score += min(50, vt_result["score"])
        reasons.append(vt_result["message"])
    sb_result = await sb.check_url(normalized)
    if sb_result["status"] == "malicious":
        score = max(score, 90)
        reasons.append("Google Safe Browsing flagged the URL")
    if "malicious" in (vt_result.get("status", ""), sb_result.get("status", "")):
        verdict = "PHISHING" if score < 90 else "MALWARE"
    elif score < 30:
        verdict = "SAFE"
    elif score < 60:
        verdict = "SUSPICIOUS"
    else:
        verdict = "HIGH RISK"
    recommendation = (
        "មិនឃើញមានការគំរាមកំហែងច្បាស់លាស់ទេ។ សូមប្រុងប្រយ័ត្នមុនបញ្ចូលព័ត៌មានសំខាន់ៗ។"
        if verdict == "SAFE"
        else "កុំបញ្ចូលពាក្យសម្ងាត់ ព័ត៌មានធនាគារ ឬព័ត៌មានផ្ទាល់ខ្លួន។"
    )
    return URLScanResult(target=url, normalized_url=normalized, score=min(score, 100), verdict=verdict, reasons=reasons, indicators=indicators, checks=checks, recommendation=recommendation)
