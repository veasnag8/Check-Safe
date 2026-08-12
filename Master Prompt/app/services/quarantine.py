from __future__ import annotations

from pathlib import Path


class QuarantineService:
    def __init__(self, base_dir: str = "storage/quarantine") -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, filename: str) -> Path:
        safe_name = Path(filename).name
        return self.base_dir / safe_name

