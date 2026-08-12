from __future__ import annotations

import asyncio
import socket
from typing import Any

try:
    import dns.asyncresolver  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    dns = None
else:  # pragma: no cover - optional dependency
    dns = dns


class DNSService:
    """Perform a small set of safe DNS lookups.

    The service prefers dnspython when available, but falls back to the
    standard library so the application can start even if the optional
    dependency is missing.
    """

    async def lookup(self, hostname: str) -> dict[str, Any]:
        if not hostname:
            return {"status": "error", "error": "empty hostname"}

        if dns is None:
            return await self._lookup_with_socket(hostname)

        resolver = dns.asyncresolver.Resolver()
        results: dict[str, list[str]] = {}
        suspicious = False
        for record in ("A", "AAAA", "MX", "NS", "CNAME"):
            try:
                answer = await asyncio.wait_for(resolver.resolve(hostname, record), timeout=3)
                results[record] = [str(item) for item in answer]
            except Exception:
                results[record] = []
        if not results["A"] and not results["AAAA"]:
            suspicious = True
        return {"status": "ok", "records": results, "suspicious": suspicious, "resolver": "dnspython"}

    async def _lookup_with_socket(self, hostname: str) -> dict[str, Any]:
        def resolve() -> dict[str, list[str]]:
            results: dict[str, list[str]] = {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []}
            try:
                infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
                addresses = []
                for info in infos:
                    address = info[4][0]
                    if address not in addresses:
                        addresses.append(address)
                for address in addresses:
                    if ":" in address:
                        results["AAAA"].append(address)
                    else:
                        results["A"].append(address)
            except Exception:
                pass
            return results

        results = await asyncio.to_thread(resolve)
        suspicious = not results["A"] and not results["AAAA"]
        return {"status": "ok", "records": results, "suspicious": suspicious, "resolver": "socket"}
