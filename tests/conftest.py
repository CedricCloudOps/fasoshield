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


@pytest.fixture()
def eicar_file(tmp_path: Path) -> Path:
    path = tmp_path / "eicar.com"
    path.write_bytes(EICAR.encode())
    return path


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


@pytest.fixture()
def isolated_settings(tmp_path: Path, monkeypatch):
    """Point the runtime settings at a per-test data directory and reset the
    API dependency singletons."""
    from fasoshield.api import deps
    from fasoshield.db import session as db_session

    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "database_url", "")
    monkeypatch.setattr(settings, "api_keys", "")
    deps.get_hashdb.cache_clear()
    deps.get_scan_engine.cache_clear()
    monkeypatch.setattr(db_session, "_engine", None)
    monkeypatch.setattr(db_session, "_SessionLocal", None)
    yield settings
    deps.get_hashdb.cache_clear()
    deps.get_scan_engine.cache_clear()
