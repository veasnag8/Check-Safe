from __future__ import annotations

from app.services.virustotal import VirusTotalService
from app.utils.hashing import compute_hashes


async def scan_hashes(data: bytes, vt: VirusTotalService) -> dict:
    hashes = compute_hashes(data)
    vt_result = await vt.check_hash(hashes["sha256"])
    verdict = "MALWARE" if vt_result.get("malicious") else "UNKNOWN" if vt_result["status"] != "ok" else "SAFE"
    return {"hashes": hashes, "virustotal": vt_result, "verdict": verdict}

