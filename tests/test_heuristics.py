from __future__ import annotations

from fasoshield.engine.heuristics import P, run_heuristics
from fasoshield.engine.models import ApkFacts, Severity, Verdict, compute_verdict


def facts(**kwargs) -> ApkFacts:
    defaults = {"is_valid_apk": True, "package_name": "com.example.app"}
    defaults.update(kwargs)
    return ApkFacts(**defaults)


def register_official(hashdb, package="com.orange.money", label="Orange Money", cert="ff" * 32):
    import csv

    path = hashdb.path.parent / "official.csv"
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["package_name", "label", "cert_sha256"])
        writer.writerow([package, label, cert or ""])
    hashdb.import_official_csv(path)


def rule_ids(findings):
    return {f.rule_id for f in findings}


def test_invalid_apk_yields_no_heuristics(hashdb):
    assert run_heuristics(ApkFacts(is_valid_apk=False), hashdb) == []


def test_official_app_with_matching_cert_short_circuits(hashdb):
    register_official(hashdb, cert="aa" * 32)
    result = run_heuristics(
        facts(
            package_name="com.orange.money",
            cert_sha256="aa" * 32,
            permissions=[P + "READ_SMS", P + "INTERNET"],  # would otherwise fire
        ),
        hashdb,
    )
    assert rule_ids(result) == {"heur.official_app"}
    assert result[0].severity is Severity.INFO


def test_cert_mismatch_is_critical(hashdb):
    register_official(hashdb, cert="aa" * 32)
    result = run_heuristics(
        facts(package_name="com.orange.money", cert_sha256="bb" * 32),
        hashdb,
    )
    assert "heur.cert_mismatch" in rule_ids(result)
    verdict, _ = compute_verdict(result)
    assert verdict is Verdict.MALICIOUS


def test_package_lookalike_detected(hashdb):
    register_official(hashdb, package="com.orange.money", cert=None)
    result = run_heuristics(facts(package_name="com.orange.rnoney"), hashdb)
    assert "heur.package_lookalike" in rule_ids(result)


def test_brand_in_label_from_unofficial_package(hashdb):
    register_official(hashdb)
    result = run_heuristics(
        facts(package_name="com.freeapps.bonus", app_name="Orange Money Bonus"),
        hashdb,
    )
    assert "heur.brand_in_label" in rule_ids(result)


def test_sms_exfiltration_combo(hashdb):
    result = run_heuristics(
        facts(permissions=[P + "RECEIVE_SMS", P + "INTERNET"]),
        hashdb,
    )
    assert "heur.sms_exfiltration" in rule_ids(result)


def test_spyware_combo_and_verdict(hashdb):
    result = run_heuristics(
        facts(
            permissions=[
                P + "RECORD_AUDIO",
                P + "INTERNET",
                P + "ACCESS_FINE_LOCATION",
                P + "RECEIVE_SMS",
            ]
        ),
        hashdb,
    )
    ids = rule_ids(result)
    assert {"heur.spyware_combo", "heur.sms_exfiltration"} <= ids
    verdict, score = compute_verdict(result)
    assert verdict is Verdict.MALICIOUS  # two HIGH findings cross the threshold
    assert score >= 70


def test_legacy_target_sdk_flagged(hashdb):
    result = run_heuristics(facts(target_sdk=19), hashdb)
    assert "heur.legacy_target_sdk" in rule_ids(result)


def test_benign_profile_stays_clean(hashdb):
    result = run_heuristics(
        facts(permissions=[P + "INTERNET", P + "ACCESS_NETWORK_STATE"], target_sdk=34),
        hashdb,
    )
    verdict, score = compute_verdict(result)
    assert verdict is Verdict.CLEAN
    assert score == 0
