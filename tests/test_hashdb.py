from __future__ import annotations

from pathlib import Path

from fasoshield.engine.hashdb import HashDB

from .conftest import EICAR_SHA256


def test_lookup_unknown(hashdb: HashDB):
    assert hashdb.lookup("0" * 64) is None


def test_add_and_lookup_is_case_insensitive(hashdb: HashDB):
    hashdb.add(EICAR_SHA256.upper(), "EICAR-Test-File", source="unit-test")
    hit = hashdb.lookup(EICAR_SHA256)
    assert hit is not None
    assert hit["threat_name"] == "EICAR-Test-File"
    assert hit["source"] == "unit-test"


def test_import_csv_skips_malformed_rows(hashdb: HashDB, tmp_path: Path):
    feed = tmp_path / "feed.csv"
    feed.write_text(
        "sha256,threat_name,source\n"
        f"{EICAR_SHA256},EICAR-Test-File,eicar.org\n"
        "not-a-hash,Broken,feed\n"
        f"{'a' * 64},Trojan.FakeOM,cert-bf\n"
    )
    assert hashdb.import_csv(feed) == 2
    assert hashdb.lookup("a" * 64)["threat_name"] == "Trojan.FakeOM"
    assert hashdb.stats()["blocklist"] == 2


def test_version_bumps_on_write(hashdb: HashDB):
    initial = hashdb.version()
    assert initial == "0"
    hashdb.add("b" * 64, "Test.Threat")
    assert hashdb.version() != initial


def test_entries_since_returns_delta(hashdb: HashDB):
    hashdb.add("c" * 64, "Old.Threat")
    version_after_first = hashdb.version()
    assert hashdb.entries_since(version_after_first) == []
    # A second insert lands after the recorded version.
    import time

    time.sleep(1.1)  # version granularity is one second
    hashdb.add("d" * 64, "New.Threat")
    delta = hashdb.entries_since(version_after_first)
    assert [e["sha256"] for e in delta] == ["d" * 64]


def test_official_apps_roundtrip(hashdb: HashDB, tmp_path: Path):
    feed = tmp_path / "official.csv"
    feed.write_text(
        "package_name,label,cert_sha256\n"
        "com.orange.money,Orange Money,abcd1234\n"
        "com.wave.personal,Wave,\n"
    )
    assert hashdb.import_official_csv(feed) == 2
    entry = hashdb.official_app("com.orange.money")
    assert entry["label"] == "Orange Money"
    assert entry["cert_sha256"] == "abcd1234"
    # Empty cert stays None so the cert-mismatch heuristic stays inactive.
    assert hashdb.official_app("com.wave.personal")["cert_sha256"] is None
    assert hashdb.official_app("com.unknown.app") is None
