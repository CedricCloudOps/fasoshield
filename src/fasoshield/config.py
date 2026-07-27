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
    quarantine_url: str = ""  # file:// path or s3://bucket/prefix; empty = data_dir/quarantine

    # API
    api_keys: str = ""  # comma-separated agent API keys; empty disables auth (dev only)
    max_upload_bytes: int = 200 * 1024 * 1024  # APKs above 200 MB are rejected
    async_scan_threshold_bytes: int = 16 * 1024 * 1024  # bigger uploads are queued, not inline

    # Path to the EC P-256 private key signing the signature bundles served to
    # agents (`fasoshield keys generate`). Empty leaves bundles unsigned, which
    # is a development-only posture: an agent built with a public key rejects
    # unsigned bundles outright.
    signature_signing_key: str = ""

    # Analyst identity (console and intel exports; separate from agent keys)
    session_ttl_minutes: int = 12 * 60
    session_cookie_name: str = "fs_session"
    session_cookie_secure: bool = True  # set false only for plain-HTTP local development
    # Header carrying the authenticated analyst when an SSO gateway terminates
    # OIDC in front of the API. Empty disables the mode; see docs/DEPLOYMENT.md
    # for the mandatory network isolation it requires.
    sso_user_header: str = ""
    sso_role_header: str = ""
    sso_default_role: str = "viewer"

    # Threat intelligence sharing
    intel_org_name: str = "FasoShield — CERT national"
    intel_tlp: str = "amber"  # tlp marking applied to MISP events and STIX bundles

    # Hardening
    rate_limit_per_minute: int = 120  # per API key, or per client IP when anonymous
    rate_limit_burst: int = 30
    cors_origins: str = ""  # comma-separated; empty means no cross-origin access
    hsts_enabled: bool = True
    trusted_proxy_count: int = 0  # X-Forwarded-For entries to trust for client IP

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

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def effective_quarantine_url(self) -> str:
        if self.quarantine_url:
            return self.quarantine_url
        return (self.data_dir / "quarantine").as_uri()


settings = Settings()
