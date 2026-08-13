from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from app.config import get_settings
from app.database.database import init_db
from app.scanners.file_scanner import scan_file
from app.scanners.url_scanner import scan_url
from app.services.dns_service import DNSService
from app.services.safe_browsing import SafeBrowsingService
from app.services.virustotal import VirusTotalService
from app.utils.formatting import format_scan_summary
from app.utils.logging_config import configure_logging
import uvicorn


async def _cli_url(url: str) -> None:
    settings = get_settings()
    result = await scan_url(
        url,
        DNSService(),
        VirusTotalService(settings.virustotal_api_key),
        SafeBrowsingService(settings.google_safe_browsing_api_key),
    )
    print(
        format_scan_summary(
            title="🛡️ SECURITY SCAN RESULT",
            verdict=result.verdict,
            score=result.score,
            reasons=result.reasons,
            recommendation=result.recommendation,
            target_label="URL",
            target_value=result.normalized_url,
            extra_details=[
                ("HTTPS", "Yes" if result.normalized_url.startswith("https://") else "No"),
                ("DNS", str(result.checks.get("dns", "unknown")).upper()),
                ("Reputation", str(result.checks.get("reputation", "unknown")).upper()),
            ],
        )
    )


async def _cli_file(file_path: str) -> None:
    settings = get_settings()
    result = await scan_file(file_path, VirusTotalService(settings.virustotal_api_key))
    print(
        format_scan_summary(
            title="🚨 SECURITY ALERT",
            verdict=result.verdict,
            score=result.score,
            reasons=result.reasons,
            recommendation="Do not open or execute this file. Keep it isolated until verified.",
            target_label="File",
            target_value=result.filename,
            extra_details=[
                ("Extension", result.extension or "unknown"),
                ("MIME Type", result.mime_type or "unknown"),
                ("Size", f"{result.size} bytes"),
                ("Entropy", f"{result.entropy:.2f}"),
                ("SHA256", result.hashes.get("sha256", "unknown")),
            ],
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url")
    parser.add_argument("--file")
    parser.add_argument("--mode", choices=("auto", "bot", "api"), default="auto")
    args = parser.parse_args()
    settings = get_settings()
    configure_logging(settings.log_level)
    init_db()
    if args.url:
        asyncio.run(_cli_url(args.url))
    elif args.file:
        asyncio.run(_cli_file(args.file))
    elif args.mode == "api" or (args.mode == "auto" and os.getenv("PORT")):
        port = int(os.getenv("PORT", "8000"))
        uvicorn.run(
            "app.api.routes:create_app",
            factory=True,
            host="0.0.0.0",
            port=port,
            log_level=settings.log_level.lower(),
        )
    else:
        from app.main import main as app_main
        app_main()


if __name__ == "__main__":
    main()
