from __future__ import annotations

from fasoshield.engine.models import Verdict
from fasoshield.engine.scanner import ScanEngine, sha256_file

from .conftest import EICAR_SHA256, make_dex, make_fake_apk


def test_sha256_matches_known_vector(eicar_file):
    assert sha256_file(eicar_file) == EICAR_SHA256


def test_eicar_detected_by_blocklist_and_yara(engine: ScanEngine, eicar_file):
    engine.hashdb.add(EICAR_SHA256, "EICAR-Test-File", source="eicar.org")
    report = engine.scan_file(eicar_file)
    assert report.verdict is Verdict.MALICIOUS
    assert report.threat_name == "EICAR-Test-File"
    ids = {f.rule_id for f in report.findings}
    assert "sig.hash_blocklist" in ids
    assert "yara.EICAR_Test_File" in ids


def test_eicar_detected_by_yara_alone(engine: ScanEngine, eicar_file):
    # Even with an empty blocklist the YARA layer classifies EICAR.
    report = engine.scan_file(eicar_file)
    assert report.verdict is Verdict.MALICIOUS
    assert report.threat_name == "yara.EICAR_Test_File"


def test_dex_inside_apk_is_scanned(engine: ScanEngine, tmp_path):
    apk = make_fake_apk(
        tmp_path / "stealer.apk",
        make_dex(
            "android.provider.Telephony.SMS_RECEIVED",
            "getMessageBody",
            "abortBroadcast",
            "https://c2.example.net/collect",
        ),
    )
    report = engine.scan_file(apk)
    ids = {f.rule_id for f in report.findings}
    # The DEFLATE-compressed DEX is only visible through entry extraction.
    assert "yara.Android_SMS_Stealer_Generic" in ids
    assert report.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
    # Malformed manifest: androguard degrades gracefully.
    assert report.facts is not None
    assert report.facts.is_valid_apk is False


def test_clean_text_file_report(engine: ScanEngine, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("meeting notes, nothing interesting")
    report = engine.scan_file(path)
    assert report.verdict is Verdict.CLEAN
    assert report.score == 0
    assert report.findings == []
    assert report.facts is None  # not a ZIP container


def test_findings_are_deduplicated(engine: ScanEngine, tmp_path):
    # The same rule matching the raw file and a DEX entry must appear once.
    payload = make_dex("SmsManager", "sendTextMessage")
    apk = make_fake_apk(tmp_path / "sender.apk", payload)
    report = engine.scan_file(apk)
    sender_hits = [
        f for f in report.findings if f.rule_id == "yara.Android_SMS_Silent_Sender"
    ]
    assert len(sender_hits) == 1
