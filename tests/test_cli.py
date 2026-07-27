"""Analyst command-line interface.

The CLI is the surface an operator uses on a server with no browser, and the
one that creates the very first console account — so it is exercised here as a
first-class interface, not as a convenience wrapper.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from fasoshield.cli import cli

from .conftest import TEST_PASSWORD, malicious_apk


@pytest.fixture()
def runner(isolated_settings) -> CliRunner:
    return CliRunner()


def run(runner: CliRunner, *args, **kwargs):
    return runner.invoke(cli, list(args), **kwargs)


# -- scanning --------------------------------------------------------------


def test_scan_exit_code_is_two_for_malicious(runner, tmp_path):
    """Shell-friendly codes let the CLI drive a pipeline: 0 clean, 1 suspicious,
    2 malicious."""
    sample = malicious_apk(tmp_path / "fake-om.apk")
    result = run(runner, "scan", str(sample))
    assert result.exit_code == 2
    assert "MALICIOUS" in result.output


def test_scan_exit_code_is_zero_for_clean(runner, tmp_path):
    clean = tmp_path / "notes.txt"
    clean.write_text("contenu parfaitement anodin", encoding="utf-8")
    result = run(runner, "scan", str(clean))
    assert result.exit_code == 0
    assert "CLEAN" in result.output


def test_scan_json_output_is_parsable(runner, tmp_path):
    sample = malicious_apk(tmp_path / "fake-om.apk")
    result = run(runner, "scan", str(sample), "--json")
    report = json.loads(result.output)
    assert report["verdict"] == "MALICIOUS"
    assert report["findings"]


def test_scan_missing_file_is_a_usage_error(runner):
    assert run(runner, "scan", "no-such-file.apk").exit_code == 2


# -- signature database ----------------------------------------------------


def test_db_import_and_stats(runner, tmp_path):
    feed = tmp_path / "feed.csv"
    feed.write_text(
        "sha256,threat_name,source\n"
        f"{'a' * 64},Trojan.FakeOM,cert-bf\n"
        f"{'b' * 64},Spy.SmsThief,partner\n",
        encoding="utf-8",
    )
    assert "2 entries imported" in run(runner, "db", "import", str(feed)).output
    assert "blocklist entries : 2" in run(runner, "db", "stats").output


def test_db_import_skips_malformed_rows(runner, tmp_path):
    """A partner feed with a bad line must not abort the whole import."""
    feed = tmp_path / "feed.csv"
    feed.write_text(
        "sha256,threat_name,source\n"
        f"{'a' * 64},Trojan.FakeOM,cert-bf\n"
        "pas-un-hash,Broken.Entry,cert-bf\n",
        encoding="utf-8",
    )
    assert "1 entries imported" in run(runner, "db", "import", str(feed)).output


def test_db_import_carries_certificate_indicators(runner, tmp_path):
    feed = tmp_path / "feed.csv"
    feed.write_text(
        "sha256,threat_name,source,cert_sha256\n"
        f"{'a' * 64},Trojan.FakeOM,cert-bf,{'c' * 64}\n",
        encoding="utf-8",
    )
    run(runner, "db", "import", str(feed))
    result = run(runner, "lookup", "c" * 64)
    assert result.exit_code == 2
    assert "Trojan.FakeOM" in result.output


def test_lookup_unknown_hash(runner):
    result = run(runner, "lookup", "f" * 64)
    assert result.exit_code == 0
    assert "UNKNOWN" in result.output


def test_import_official_registry(runner, tmp_path):
    registry = tmp_path / "official.csv"
    registry.write_text(
        "package_name,label,cert_sha256\ncom.wave.personal,Wave,\n", encoding="utf-8"
    )
    assert "1 official apps" in run(runner, "db", "import-official", str(registry)).output


# -- accounts --------------------------------------------------------------


def test_account_create_and_list(runner):
    created = run(
        runner, "account", "create", "--username", "alice", "--role", "admin",
        "--password", TEST_PASSWORD,
    )
    assert created.exit_code == 0
    listed = run(runner, "account", "list").output
    assert "alice" in listed
    assert "admin" in listed
    assert "active" in listed


def test_account_create_rejects_weak_password(runner):
    result = run(
        runner, "account", "create", "--username", "bob", "--password", "court",
    )
    assert result.exit_code != 0
    assert "12 characters" in result.output


def test_account_create_rejects_duplicates(runner):
    run(runner, "account", "create", "--username", "carol", "--password", TEST_PASSWORD)
    second = run(
        runner, "account", "create", "--username", "carol", "--password", TEST_PASSWORD
    )
    assert second.exit_code != 0
    assert "already exists" in second.output


def test_account_disable(runner):
    run(runner, "account", "create", "--username", "dave", "--password", TEST_PASSWORD)
    assert run(runner, "account", "disable", "--username", "dave").exit_code == 0
    assert "disabled" in run(runner, "account", "list").output


def test_account_disable_unknown_user(runner):
    result = run(runner, "account", "disable", "--username", "ghost")
    assert result.exit_code != 0
    assert "Unknown account" in result.output


def test_account_list_when_empty(runner):
    assert "no account defined" in run(runner, "account", "list").output


def test_account_passwd(runner):
    run(runner, "account", "create", "--username", "erin", "--password", TEST_PASSWORD)
    result = run(
        runner, "account", "passwd", "--username", "erin", "--password", "un-autre-mot-de-passe",
    )
    assert result.exit_code == 0
    assert "password updated" in result.output


# -- governance ------------------------------------------------------------


def test_proposal_list_and_show(runner, db_session):
    from fasoshield.governance import create_proposal

    proposal = create_proposal(
        db_session,
        actor="alice",
        indicator_type="sha256",
        value="a" * 64,
        threat_name="Trojan.FakeOM",
        source="cert-bf",
        justification="Clone d'Orange Money qui capture le PIN et l'exfiltre.",
    )

    listed = run(runner, "proposal", "list").output
    assert "DRAFT" in listed
    assert "Trojan.FakeOM" in listed

    shown = run(runner, "proposal", "show", str(proposal.id)).output
    assert "Clone d'Orange Money" in shown
    assert "alice" in shown


def test_proposal_list_when_empty(runner):
    assert "no proposal" in run(runner, "proposal", "list").output


def test_proposal_show_unknown_id(runner):
    result = run(runner, "proposal", "show", "999")
    assert result.exit_code != 0
    assert "unknown proposal" in result.output


# -- intelligence exports --------------------------------------------------


def test_intel_stix_writes_a_bundle(runner, tmp_path):
    feed = tmp_path / "feed.csv"
    feed.write_text(
        f"sha256,threat_name,source\n{'a' * 64},Trojan.FakeOM,cert-bf\n", encoding="utf-8"
    )
    run(runner, "db", "import", str(feed))

    output = tmp_path / "bundle.json"
    result = run(runner, "intel", "stix", "-o", str(output))
    assert result.exit_code == 0

    bundle = json.loads(output.read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle"
    patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
    assert f"[file:hashes.'SHA-256' = '{'a' * 64}']" in patterns


def test_intel_misp_to_stdout(runner, tmp_path):
    feed = tmp_path / "feed.csv"
    feed.write_text(
        f"sha256,threat_name,source\n{'b' * 64},Spy.SmsThief,partner\n", encoding="utf-8"
    )
    run(runner, "db", "import", str(feed))

    event = json.loads(run(runner, "intel", "misp").output)
    assert event["Event"]["Attribute"][0]["value"] == "b" * 64


# -- deferred worker -------------------------------------------------------


def test_worker_once_drains_the_queue(runner, tmp_path, db_session):
    from fasoshield import jobs

    staged = malicious_apk(tmp_path / "queued.apk")
    jobs.enqueue(db_session, "queued.apk", staged.stat().st_size, staged, None)

    result = run(runner, "worker", "--once")
    assert result.exit_code == 0
    assert "1 job(s) processed" in result.output


def test_worker_once_on_empty_queue(runner):
    assert "0 job(s) processed" in run(runner, "worker", "--once").output
