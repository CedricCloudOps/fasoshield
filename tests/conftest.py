from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from fasoshield.config import PROJECT_ROOT, settings
from fasoshield.engine.hashdb import HashDB
from fasoshield.engine.scanner import ScanEngine
from fasoshield.engine.yara_scanner import YaraScanner

# Split so that the test suite itself is not flagged by desktop AV products.
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture()
def hashdb(tmp_path: Path) -> HashDB:
    return HashDB(tmp_path / "signatures.db")


@pytest.fixture(scope="session")
def yara_scanner() -> YaraScanner:
    return YaraScanner(PROJECT_ROOT / "signatures" / "yara")


@pytest.fixture()
def engine(hashdb: HashDB, yara_scanner: YaraScanner) -> ScanEngine:
    return ScanEngine(hashdb=hashdb, yara_scanner=yara_scanner)


def write_eicar(path: Path) -> Path:
    """Write the EICAR test string, skipping the test if the host antivirus
    removes or locks it.

    EICAR is the industry-standard way to prove a scan pipeline works
    end-to-end, but a developer workstation running a desktop AV product will
    quarantine the file between the write and the scan. Skipping there keeps
    the local suite usable; CI runs on a clean image where these tests execute
    for real.
    """
    path.write_bytes(EICAR.encode())
    try:
        if path.read_bytes() != EICAR.encode():
            raise OSError("content altered")
    except OSError as exc:
        pytest.skip(f"host antivirus removed the EICAR test file ({exc})")
    return path


@pytest.fixture()
def eicar_file(tmp_path: Path) -> Path:
    return write_eicar(tmp_path / "eicar.com")


def make_fake_apk(path: Path, dex_payload: bytes) -> Path:
    """Build a ZIP that mimics an APK layout with a synthetic classes.dex.
    Androguard will reject it (no binary manifest), which also exercises the
    engine's degraded mode on malformed containers."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"not-a-real-binary-manifest")
        archive.writestr("classes.dex", dex_payload)
    path.write_bytes(buffer.getvalue())
    return path


def make_dex(*strings: str) -> bytes:
    """Synthetic DEX: correct magic followed by embedded string constants."""
    body = b"\x00".join(s.encode() for s in strings)
    return b"dex\n035\x00" + body


def malicious_apk(path: Path) -> Path:
    """A synthetic sample the engine convicts through the YARA layer.

    Unlike EICAR it is not recognised by desktop antivirus products, so tests
    that only need "a file the engine flags as malicious" use this and stay
    reliable on any workstation.
    """
    return make_fake_apk(
        path,
        make_dex(
            "android.provider.Telephony.SMS_RECEIVED",
            "getMessageBody",
            "getOriginatingAddress",
            "abortBroadcast",
            "https://c2.example.net/collect",
            "SmsManager",
            "sendTextMessage",
        ),
    )


@pytest.fixture()
def malicious_apk_file(tmp_path: Path) -> Path:
    return malicious_apk(tmp_path / "fake-mobile-money.apk")


@pytest.fixture()
def isolated_settings(tmp_path: Path, monkeypatch):
    """Point the runtime settings at a per-test data directory and reset the
    API dependency singletons."""
    from fasoshield.api import deps
    from fasoshield.db import session as db_session

    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "database_url", "")
    monkeypatch.setattr(settings, "quarantine_url", "")
    monkeypatch.setattr(settings, "api_keys", "")
    # Bundles are unsigned unless a test configures a key of its own.
    monkeypatch.setattr(settings, "signature_signing_key", "")
    # Plain HTTP in the test client: a Secure cookie would never be sent back.
    monkeypatch.setattr(settings, "session_cookie_secure", False)
    monkeypatch.setattr(settings, "sso_user_header", "")
    # Rate limiting is exercised by its own test, not by every other one.
    monkeypatch.setattr(settings, "rate_limit_per_minute", 100000)
    monkeypatch.setattr(settings, "rate_limit_burst", 100000)
    deps.get_hashdb.cache_clear()
    deps.get_scan_engine.cache_clear()
    deps.get_quarantine.cache_clear()
    deps.get_bundle_signer.cache_clear()
    monkeypatch.setattr(db_session, "_engine", None)
    monkeypatch.setattr(db_session, "_SessionLocal", None)
    yield settings
    deps.get_hashdb.cache_clear()
    deps.get_scan_engine.cache_clear()
    deps.get_quarantine.cache_clear()
    deps.get_bundle_signer.cache_clear()


@pytest.fixture()
def db_session(isolated_settings):
    """A platform DB session bound to the isolated per-test database."""
    from fasoshield.db.session import get_session, init_db

    init_db()
    session = get_session()
    yield session
    session.close()


# Shared throwaway credential for the console fixtures. Long enough to pass
# the password policy; it never leaves the test database.
TEST_PASSWORD = "Correct-Horse-42"  # noqa: S105


def make_analyst(
    session, username: str, role: str = "analyst", password: str = TEST_PASSWORD
) -> str:
    """Create a console account and return its password."""
    from fasoshield.accounts import create_account
    from fasoshield.security import Role

    create_account(session, username=username, password=password, role=Role(role))
    return password


def login(client, username: str, password: str = TEST_PASSWORD) -> None:
    """Authenticate a TestClient; the session cookie is kept by the client."""
    response = client.post(
        "/v1/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
