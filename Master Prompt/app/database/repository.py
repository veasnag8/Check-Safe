from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.models import Scan, ScanIndicator, User


class Repository:
    def get_or_create_user(self, session: Session, telegram_user_id: int, username: str | None, first_name: str | None) -> User:
        user = session.scalar(select(User).where(User.telegram_user_id == telegram_user_id))
        if user:
            user.username = username
            user.first_name = first_name
            user.last_seen_at = datetime.utcnow()
            return user
        user = User(telegram_user_id=telegram_user_id, username=username, first_name=first_name, last_seen_at=datetime.utcnow())
        session.add(user)
        session.flush()
        return user

    def create_scan(self, session: Session, **kwargs) -> Scan:
        scan = Scan(**kwargs)
        session.add(scan)
        session.flush()
        return scan

    def add_indicators(self, session: Session, scan: Scan, indicators: list[dict]) -> None:
        for item in indicators:
            session.add(ScanIndicator(scan_id=scan.id, **item))

    def stats(self, session: Session) -> dict[str, int]:
        total_users = session.scalar(select(func.count(User.id))) or 0
        total_scans = session.scalar(select(func.count(Scan.id))) or 0
        verdicts = {row[0]: row[1] for row in session.execute(select(Scan.verdict, func.count(Scan.id)).group_by(Scan.verdict))}
        return {"total_users": total_users, "total_scans": total_scans, **verdicts}

