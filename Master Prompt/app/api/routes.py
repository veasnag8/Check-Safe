from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import Response

from app.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name)

    @app.get("/favicon.ico")
    async def favicon() -> Response:
        # Return a tiny inline SVG as the favicon to avoid 404 noise from browsers
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
            '<rect width="16" height="16" fill="#0b74de"/></svg>'
        )
        return Response(content=svg, media_type="image/svg+xml")

    @app.get("/")
    async def root() -> dict:
        return {"name": settings.app_name}

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "database": "ok", "telegram": "ok", "virustotal": "configured" if settings.virustotal_api_key else "not_configured", "safe_browsing": "configured" if settings.google_safe_browsing_api_key else "not_configured"}

    @app.get("/api/status")
    async def status() -> dict:
        return await health()

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: int) -> dict:
        return {"scan_id": scan_id, "status": "not_implemented"}

    return app

