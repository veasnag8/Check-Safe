from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = Field(default="Telegram Security Scanner", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    telegram_bot_token: str = Field(default="", alias="TELEGRAM_BOT_TOKEN")
    database_url: str = Field(default="sqlite:///./security_scanner.db", alias="DATABASE_URL")
    virustotal_api_key: str = Field(default="", alias="VIRUSTOTAL_API_KEY")
    google_safe_browsing_api_key: str = Field(default="", alias="GOOGLE_SAFE_BROWSING_API_KEY")
    admin_telegram_ids: str = Field(default="", alias="ADMIN_TELEGRAM_IDS")
    public_base_url: str = Field(default="", alias="PUBLIC_BASE_URL")
    telegram_webhook_path: str = Field(default="/telegram/webhook", alias="TELEGRAM_WEBHOOK_PATH")
    telegram_webhook_secret: str = Field(default="", alias="TELEGRAM_WEBHOOK_SECRET")
    max_file_size_mb: int = Field(default=20, alias="MAX_FILE_SIZE_MB")
    max_archive_size_mb: int = Field(default=50, alias="MAX_ARCHIVE_SIZE_MB")
    max_extracted_files: int = Field(default=1000, alias="MAX_EXTRACTED_FILES")
    max_extraction_size_mb: int = Field(default=100, alias="MAX_EXTRACTION_SIZE_MB")
    max_archive_depth: int = Field(default=3, alias="MAX_ARCHIVE_DEPTH")
    max_scans_per_minute: int = Field(default=5, alias="MAX_SCANS_PER_MINUTE")
    max_scans_per_hour: int = Field(default=50, alias="MAX_SCANS_PER_HOUR")
    allow_external_file_upload: bool = Field(default=False, alias="ALLOW_EXTERNAL_FILE_UPLOAD")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    @property
    def admin_ids(self) -> List[int]:
        if not self.admin_telegram_ids.strip():
            return []
        return [int(value.strip()) for value in self.admin_telegram_ids.split(",") if value.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
