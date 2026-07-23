"""Runtime configuration, environment-driven (12-factor)."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FASOSHIELD_", env_file=".env", extra="ignore")

    # Storage
    data_dir: Path = PROJECT_ROOT / "data"
    signatures_dir: Path = PROJECT_ROOT / "signatures"
    database_url: str = ""  # defaults to sqlite in data_dir when empty

    # API
    api_keys: str = ""  # comma-separated agent API keys; empty disables auth (dev only)
    max_upload_bytes: int = 200 * 1024 * 1024  # APKs above 200 MB are rejected

    @property
    def hashdb_path(self) -> Path:
        return self.data_dir / "signatures.db"

    @property
    def yara_dir(self) -> Path:
        return self.signatures_dir / "yara"

    @property
    def sqlalchemy_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{self.data_dir / 'fasoshield.db'}"

    @property
    def api_key_set(self) -> set[str]:
        return {key.strip() for key in self.api_keys.split(",") if key.strip()}


settings = Settings()
