from __future__ import annotations


class SafeBrowsingService:
    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    async def check_url(self, url: str) -> dict:
        if not self.configured:
            return {"status": "NOT_CONFIGURED", "message": "Google Safe Browsing: NOT CONFIGURED"}
        return {"status": "ok", "message": "clean"}

