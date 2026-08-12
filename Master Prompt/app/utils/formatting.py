from __future__ import annotations

from typing import Iterable


KHMER_LABELS = {
    "title_url": "🛡️ លទ្ធផលត្រួតពិនិត្យសុវត្ថិភាព",
    "title_file": "🚨 ការព្រមានសុវត្ថិភាព",
    "verdict": "លទ្ធផល",
    "risk_score": "ពិន្ទុហានិភ័យ",
    "reasons": "មូលហេតុ",
    "details": "ព័ត៌មានលម្អិត",
    "recommendation": "អនុសាសន៍",
    "none": "គ្មាន",
}


def _format_list(items: Iterable[str], empty_label: str = "None") -> str:
    values = [item for item in items if item]
    if not values:
        return empty_label
    return "\n".join(f"• {item}" for item in values)


def _verdict_badge(verdict: str, locale: str = "en") -> str:
    verdict_key = verdict.upper()
    if locale == "km":
        mapping = {
            "SAFE": "✅ សុវត្ថិភាព",
            "SUSPICIOUS": "⚠️ គួរឲ្យសង្ស័យ",
            "HIGH RISK": "🟠 ហានិភ័យខ្ពស់",
            "PHISHING": "🚨 បន្លំទិន្នន័យ",
            "MALWARE": "🚨 មេរោគ",
            "UNKNOWN": "❓ មិនទាន់ដឹង",
        }
    else:
        mapping = {
            "SAFE": "✅ SAFE",
            "SUSPICIOUS": "⚠️ SUSPICIOUS",
            "HIGH RISK": "🟠 HIGH RISK",
            "PHISHING": "🚨 PHISHING",
            "MALWARE": "🚨 MALWARE",
            "UNKNOWN": "❓ UNKNOWN",
        }
    return mapping.get(verdict_key, verdict)


def _recommendation_text(verdict: str, locale: str = "en") -> str:
    verdict_key = verdict.upper()
    if locale == "km":
        return {
            "SAFE": "ឯកសារនេះមើលទៅសុវត្ថិភាព ប៉ុន្តែសូមបើកតែបើអ្នកទុកចិត្តលើប្រភព។",
            "SUSPICIOUS": "សូមប្រុងប្រយ័ត្នចំពោះឯកសារនេះ ហើយកុំបើកលុះត្រាតែអ្នកទុកចិត្តលើប្រភព។",
            "HIGH RISK": "សូមជៀសវាងការបើកឯកសារនេះ រហូតដល់បានផ្ទៀងផ្ទាត់ដោយឯករាជ្យ។",
            "PHISHING": "កុំបញ្ចូលពាក្យសម្ងាត់ ឬព័ត៌មានផ្ទាល់ខ្លួននៅលើតំណ ឬឯកសារនេះ។",
            "MALWARE": "កុំបើក ឬរត់ឯកសារនេះ។ សូមរក្សាវាឲ្យនៅដាច់ដោយឡែក ឬលុបចោល។",
            "UNKNOWN": "សូមប្រើការប្រុងប្រយ័ត្ន ហើយកុំបើកវាលុះត្រាតែអ្នកទុកចិត្តលើប្រភព។",
        }.get(verdict_key, "សូមប្រើការប្រុងប្រយ័ត្ន។")
    return {
        "SAFE": "មិនឃើញមានការគំរាមកំហែងច្បាស់លាស់ទេ។ សូមផ្ទៀងផ្ទាត់ប្រភពមុនបើក។",
        "SUSPICIOUS": "សូមប្រុងប្រយ័ត្នជាមួយឯកសារនេះ ហើយកុំបើក លុះត្រាតែអ្នកទុកចិត្តលើប្រភព។",
        "HIGH RISK": "ឯកសារនេះមានហានិភ័យខ្ពស់។ សូមជៀសវាងការបើក រហូតដល់បានផ្ទៀងផ្ទាត់។",
        "PHISHING": "កុំបញ្ចូលពាក្យសម្ងាត់ ឬព័ត៌មានផ្ទាល់ខ្លួន។",
        "MALWARE": "កុំបើក ឬរត់ឯកសារនេះ។ សូមរក្សាវាឲ្យនៅដាច់ដោយឡែក ឬលុបចោល។",
        "UNKNOWN": "សូមប្រើការប្រុងប្រយ័ត្ន និងកុំបើកវាលុះត្រាតែអ្នកទុកចិត្តលើប្រភព។",
    }.get(verdict_key, "សូមប្រើការប្រុងប្រយ័ត្ន។")


def format_scan_summary(
    *,
    title: str,
    verdict: str,
    score: int,
    reasons: list[str] | None = None,
    recommendation: str = "",
    target_label: str | None = None,
    target_value: str | None = None,
    extra_details: list[tuple[str, str]] | None = None,
    locale: str = "en",
) -> str:
    details = extra_details or []
    labels = KHMER_LABELS if locale == "km" else {
        "verdict": "Verdict",
        "risk_score": "Risk Score",
        "reasons": "Reasons",
        "details": "Details",
        "recommendation": "Recommendation",
        "none": "None",
    }

    target_line = f"\n{target_label}: {target_value}" if target_label and target_value else ""
    detail_lines = [f"• {label}: {value}" for label, value in details if value]
    details_block = "\n".join(detail_lines) if detail_lines else labels["none"]
    reasons_block = _format_list(reasons or [], labels["none"])

    return (
        f"{title}\n"
        f"{'─' * 24}\n"
        f"{labels['verdict']}: {_verdict_badge(verdict, locale)}\n"
        f"{labels['risk_score']}: {score}/100{target_line}\n"
        f"{'─' * 24}\n"
        f"{labels['reasons']}:\n{reasons_block}\n"
        f"\n{labels['details']}:\n{details_block}\n"
        f"{'─' * 24}\n"
        f"{labels['recommendation']}:\n{recommendation or _recommendation_text(verdict, locale)}"
    )
