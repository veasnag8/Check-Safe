from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

from app.scanners.hash_scanner import scan_hashes
from app.services.virustotal import VirusTotalService
from app.utils.hashing import compute_hashes

SAFE_CLICKABLE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".pdf",
    ".txt",
    ".md",
    ".csv",
    ".json",
}


@dataclass
class FileScanResult:
    target: str
    filename: str
    extension: str
    mime_type: str
    size: int
    hashes: dict
    entropy: float
    verdict: str
    score: int
    reasons: list[str]
    indicators: list[dict]
    checks: dict
    recommendation: str


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [data.count(byte) / len(data) for byte in set(data)]
    return -sum(p * math.log2(p) for p in freq)


async def scan_file(path: str, vt: VirusTotalService) -> FileScanResult:
    p = Path(path)
    data = p.read_bytes()
    hashes = compute_hashes(data)
    hash_result = await scan_hashes(data, vt)
    ext = p.suffix.lower()
    reasons = []
    score = 0
    indicators = []
    checks = {"file_type_mismatch": False, "virus_total": hash_result["virustotal"]["status"]}
    if ext in {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".apk"}:
        score += 40; reasons.append("ករណីសង្ស័យ"); indicators.append({"indicator_type": "extension", "description": ext, "severity": "high", "score": 40})
    entropy = shannon_entropy(data[:1000000])
    if entropy > 7.2:
        score += 10; reasons.append("កម្រិត entropy ខ្ពស់")
    if hash_result["verdict"] == "MALWARE":
        verdict = "MALWARE"
    elif score >= 90:
        verdict = "MALWARE"
    elif score >= 60:
        verdict = "HIGH RISK"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
    if verdict == "SAFE":
        if ext in SAFE_CLICKABLE_EXTENSIONS:
            recommendation = "ឯកសារនេះមើលទៅសុវត្ថិភាព សូមបើកតែបើអ្នកទុកចិត្តលើប្រភព។"
        else:
            recommendation = "មិនឃើញមានការគំរាមកំហែងច្បាស់លាស់ទេ។ សូមផ្ទៀងផ្ទាត់ប្រភពមុនបើក។"
    elif verdict == "SUSPICIOUS":
        recommendation = "សូមប្រុងប្រយ័ត្នជាមួយឯកសារនេះ ហើយកុំបើក លុះត្រាតែអ្នកទុកចិត្តលើប្រភព។"
    elif verdict == "HIGH RISK":
        recommendation = "ឯកសារនេះមានហានិភ័យខ្ពស់។ សូមជៀសវាងការបើក រហូតដល់បានផ្ទៀងផ្ទាត់។"
    else:
        recommendation = "កុំបើក ឬRunឯកសារនេះ។ សូមរក្សាវាឲ្យនៅដាច់ដោយឡែក ឬលុបចោល។"
    return FileScanResult(
        target=str(p),
        filename=p.name,
        extension=ext,
        mime_type="application/octet-stream",
        size=len(data),
        hashes=hashes,
        entropy=entropy,
        verdict=verdict,
        score=min(score, 100),
        reasons=reasons,
        indicators=indicators,
        checks=checks,
        recommendation=recommendation,
    )
