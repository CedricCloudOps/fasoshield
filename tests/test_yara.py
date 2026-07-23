from __future__ import annotations

from fasoshield.engine.models import Severity
from fasoshield.engine.yara_scanner import YaraScanner

from .conftest import EICAR, make_dex


def test_rules_compile(yara_scanner: YaraScanner):
    assert yara_scanner.rule_count >= 5


def test_eicar_rule_matches(yara_scanner: YaraScanner, tmp_path):
    path = tmp_path / "eicar.com"
    path.write_bytes(EICAR.encode())
    findings = yara_scanner.scan_file(path)
    assert any(f.rule_id == "yara.EICAR_Test_File" for f in findings)
    assert findings[0].severity is Severity.CRITICAL


def test_sms_stealer_rule_on_dex_bytes(yara_scanner: YaraScanner):
    dex = make_dex(
        "android.provider.Telephony.SMS_RECEIVED",
        "getMessageBody",
        "abortBroadcast",
        "https://c2.example.net/collect",
    )
    findings = yara_scanner.scan_bytes(dex, context="classes.dex")
    ids = {f.rule_id for f in findings}
    assert "yara.Android_SMS_Stealer_Generic" in ids
    hit = next(f for f in findings if f.rule_id == "yara.Android_SMS_Stealer_Generic")
    assert hit.evidence.startswith("[classes.dex]")


def test_clean_dex_does_not_match(yara_scanner: YaraScanner):
    dex = make_dex("Lcom/example/app/MainActivity;", "onCreate", "setContentView")
    assert yara_scanner.scan_bytes(dex) == []


def test_smishing_rule_needs_brand_and_lures(yara_scanner: YaraScanner):
    text = (
        b"Votre compte a ete suspendu. Entrez votre code de validation "
        b"Orange Money pour reactiver."
    )
    findings = yara_scanner.scan_bytes(text)
    assert any(f.rule_id == "yara.Android_Smishing_MobileMoney_FR" for f in findings)
    # Brand alone must not fire.
    assert yara_scanner.scan_bytes(b"Payez avec Orange Money dans notre boutique") == []
