import asyncio

from app.scanners.file_scanner import scan_file
from app.services.virustotal import VirusTotalService


def test_file_type_detection(tmp_path):
    p = tmp_path / "invoice.exe"
    p.write_bytes(b"hello")
    result = asyncio.run(scan_file(str(p), VirusTotalService()))
    assert result.extension == ".exe"
