from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RiskResult:
    score: int
    verdict: str
    severity: str
    reasons: list[str] = field(default_factory=list)
    recommendation: str = ""
    indicators: list[dict] = field(default_factory=list)
    checks: dict = field(default_factory=dict)


def severity_for_score(score: int) -> str:
    if score < 30:
        return "safe"
    if score < 60:
        return "suspicious"
    if score < 90:
        return "high_risk"
    return "critical"


def verdict_for_score(score: int) -> str:
    if score < 30:
        return "SAFE"
    if score < 60:
        return "SUSPICIOUS"
    if score < 90:
        return "HIGH RISK"
    return "MALWARE"


def merge_risk(base_score: int, reasons: list[str], indicators: list[dict], checks: dict, override_verdict: str | None = None) -> RiskResult:
    score = max(0, min(100, base_score))
    verdict = override_verdict or verdict_for_score(score)
    severity = severity_for_score(score)
    recommendation = {
        "SAFE": "មិនឃើញមានការគំរាមកំហែងច្បាស់លាស់ទេ។ សូមនៅតែប្រុងប្រយ័ត្នមុនបើក។",
        "SUSPICIOUS": "សូមប្រុងប្រយ័ត្ន ហើយផ្ទៀងផ្ទាត់ប្រភពមុនធ្វើអន្តរកម្ម។",
        "HIGH RISK": "សូមជៀសវាងការបើក ឬចូលប្រើ រហូតដល់បានផ្ទៀងផ្ទាត់ដោយឯករាជ្យ។",
        "PHISHING": "កុំបញ្ចូលពាក្យសម្ងាត់ ឬព័ត៌មានផ្ទាល់ខ្លួន។",
        "MALWARE": "កុំបើក ឬរត់ឯកសារនេះ។ សូមដាក់ឲ្យនៅដាច់ដោយឡែក ឬលុបចោល។",
        "UNKNOWN": "សូមប្រើការប្រុងប្រយ័ត្ន និងកុំបើកវា លុះត្រាតែអ្នកទុកចិត្តលើប្រភព។",
    }.get(verdict, "សូមប្រើការប្រុងប្រយ័ត្ន។")
    return RiskResult(score=score, verdict=verdict, severity=severity, reasons=reasons, recommendation=recommendation, indicators=indicators, checks=checks)
