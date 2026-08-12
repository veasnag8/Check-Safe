from __future__ import annotations

import asyncio
import logging

import httpx

logger = logging.getLogger(__name__)


class VirusTotalService:
    def __init__(self, api_key: str = "", allow_file_upload: bool = False) -> None:
        self.api_key = api_key
        self.allow_file_upload = allow_file_upload

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    async def check_url(self, url: str) -> dict:
        if not self.configured:
            return {"status": "NOT_CONFIGURED", "score": 0, "message": "VirusTotal: NOT CONFIGURED"}
        headers = {"x-apikey": self.api_key}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get("https://www.virustotal.com/api/v3/urls", headers=headers, params={"url": url})
                if resp.status_code == 429:
                    return {"status": "UNAVAILABLE", "score": 0, "message": "VirusTotal rate limit reached"}
                if resp.is_error:
                    return {"status": "UNAVAILABLE", "score": 0, "message": "VirusTotal API unavailable"}
                return {"status": "ok", "score": 0, "message": "clean"}
        except Exception as exc:
            logger.warning("VirusTotal URL check failed: %s", exc)
            return {"status": "UNAVAILABLE", "score": 0, "message": "VirusTotal API unavailable"}

    async def check_hash(self, sha256: str) -> dict:
        if not self.configured:
            return {"status": "NOT_CONFIGURED", "message": "VirusTotal: NOT CONFIGURED"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": self.api_key})
                if resp.status_code == 429:
                    return {"status": "UNAVAILABLE", "message": "VirusTotal rate limit reached"}
                if resp.status_code == 404:
                    return {"status": "ok", "message": "unknown", "malicious": False}
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0) > 0
                return {"status": "ok", "message": "malicious" if malicious else "clean", "malicious": malicious}
        except Exception as exc:
            logger.warning("VirusTotal hash check failed: %s", exc)
            return {"status": "UNAVAILABLE", "message": "VirusTotal API unavailable"}

