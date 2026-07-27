"""Analyst command-line interface.

    fasoshield scan sample.apk [--json]
    fasoshield lookup <sha256>
    fasoshield db import signatures/hashes/blocklist.seed.csv
    fasoshield db import-official signatures/hashes/official_apps.seed.csv
    fasoshield db stats
    fasoshield account create --username alice --role analyst
    fasoshield proposal list [--status REVIEW]
    fasoshield intel stix --output bundle.json
    fasoshield worker [--once]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from . import __version__
from .config import settings
from .engine.hashdb import HashDB
from .engine.models import ScanReport, Verdict
from .engine.scanner import ScanEngine
from .engine.yara_scanner import YaraScanner

VERDICT_COLORS = {
    Verdict.CLEAN: "green",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.MALICIOUS: "red",
    Verdict.ERROR: "magenta",
}


def _hashdb() -> HashDB:
    return HashDB(settings.hashdb_path)


def _engine() -> ScanEngine:
    return ScanEngine(hashdb=_hashdb(), yara_scanner=YaraScanner(settings.yara_dir))


def _db():
    """Open a platform database session, creating the schema on first use."""
    from .db.session import get_session, init_db

    init_db()
    return get_session()


@click.group()
@click.version_option(version=__version__, prog_name="fasoshield")
def cli() -> None:
    """FasoShield — national mobile threat analysis engine."""


@cli.command()
@click.argument("apk_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Emit the full report as JSON.")
def scan(apk_path: Path, as_json: bool) -> None:
    """Scan an APK (or any file) and print the verdict."""
    report = _engine().scan_file(apk_path)
    if as_json:
        click.echo(report.model_dump_json(indent=2))
    else:
        _print_report(report)
    # Shell-friendly exit codes: 0 clean, 1 suspicious, 2 malicious.
    sys.exit({Verdict.CLEAN: 0, Verdict.SUSPICIOUS: 1}.get(report.verdict, 2))


@cli.command()
@click.argument("sha256")
def lookup(sha256: str) -> None:
    """Look up a SHA-256 in the national blocklist."""
    db = _hashdb()
    hit = db.lookup(sha256) or db.lookup_cert(sha256)
    if hit:
        click.echo(f"MALICIOUS  {hit['threat_name']}  (source: {hit['source']})")
        sys.exit(2)
    click.echo("UNKNOWN")


@cli.group()
def db() -> None:
    """Signature database management."""


@db.command("import")
@click.argument("csv_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def db_import(csv_path: Path) -> None:
    """Import a blocklist CSV feed (sha256,threat_name,source[,cert_sha256])."""
    count = _hashdb().import_csv(csv_path)
    click.echo(f"{count} entries imported, db version {_hashdb().version()}")


@db.command("import-official")
@click.argument("csv_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def db_import_official(csv_path: Path) -> None:
    """Import the official apps registry (package_name,label,cert_sha256)."""
    count = _hashdb().import_official_csv(csv_path)
    click.echo(f"{count} official apps registered")


@db.command("stats")
def db_stats() -> None:
    """Show signature database statistics."""
    stats = _hashdb().stats()
    click.echo(f"blocklist entries : {stats['blocklist']}")
    click.echo(f"official apps     : {stats['official_apps']}")
    click.echo(f"db version        : {stats['version']}")


# -- analyst accounts ------------------------------------------------------


@cli.group()
def account() -> None:
    """Console account administration."""


@account.command("create")
@click.option("--username", required=True)
@click.option("--role", type=click.Choice(["viewer", "analyst", "admin"]), default="analyst")
@click.option("--display-name", default=None)
@click.password_option("--password", confirmation_prompt=True)
def account_create(username: str, role: str, display_name: str | None, password: str) -> None:
    """Create a console account (this is how the first administrator is made)."""
    from .accounts import AccountError, create_account
    from .security import PasswordPolicyError, Role

    session = _db()
    try:
        create_account(
            session,
            username=username,
            password=password,
            role=Role(role),
            display_name=display_name,
        )
    except (AccountError, PasswordPolicyError) as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        session.close()
    click.echo(f"account '{username}' created with role {role}")


@account.command("list")
def account_list() -> None:
    """List console accounts."""
    from .accounts import list_accounts

    session = _db()
    try:
        accounts = list_accounts(session)
        if not accounts:
            click.echo("no account defined")
            return
        for acc in accounts:
            state = "active" if acc.is_active else "disabled"
            click.echo(f"{acc.username:20} {acc.role:8} {state:9} {acc.display_name}")
    finally:
        session.close()


@account.command("passwd")
@click.option("--username", required=True)
@click.password_option("--password", confirmation_prompt=True)
def account_passwd(username: str, password: str) -> None:
    """Reset a password (also revokes that analyst's live sessions)."""
    from .accounts import AccountError, set_password
    from .security import PasswordPolicyError

    session = _db()
    try:
        set_password(session, username, password)
    except (AccountError, PasswordPolicyError) as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        session.close()
    click.echo(f"password updated for '{username}'")


@account.command("disable")
@click.option("--username", required=True)
def account_disable(username: str) -> None:
    """Disable an account and revoke its sessions."""
    from .accounts import AccountError, set_active

    session = _db()
    try:
        set_active(session, username, False)
    except AccountError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        session.close()
    click.echo(f"account '{username}' disabled")


# -- signature governance --------------------------------------------------


@cli.group()
def proposal() -> None:
    """Signature review workflow."""


@proposal.command("list")
@click.option(
    "--status", "status_filter", default=None,
    help="DRAFT | REVIEW | PUBLISHED | REJECTED",
)
def proposal_list(status_filter: str | None) -> None:
    """List signature proposals."""
    from .governance import list_proposals

    session = _db()
    try:
        proposals = list_proposals(session, status=status_filter)
        if not proposals:
            click.echo("no proposal")
            return
        for p in proposals:
            reviewer = p.reviewed_by or "-"
            click.echo(
                f"#{p.id:<4} {p.status:<10} {p.indicator_type:<12} {p.value[:16]}… "
                f"{p.threat_name[:28]:<28} by {p.created_by} / reviewed {reviewer}"
            )
    finally:
        session.close()


@proposal.command("show")
@click.argument("proposal_id", type=int)
def proposal_show(proposal_id: int) -> None:
    """Show a proposal in full, including its justification."""
    from .db.models import SignatureProposal

    session = _db()
    try:
        p = session.get(SignatureProposal, proposal_id)
        if p is None:
            raise click.ClickException(f"unknown proposal {proposal_id}")
        click.echo(f"id            : {p.id}")
        click.echo(f"status        : {p.status}")
        click.echo(f"indicator     : {p.indicator_type} {p.value}")
        click.echo(f"threat        : {p.threat_name}  (source {p.source})")
        click.echo(f"proposed by   : {p.created_by} on {p.created_at}")
        click.echo(f"reviewed by   : {p.reviewed_by or '-'} {p.reviewed_at or ''}")
        if p.review_note:
            click.echo(f"review note   : {p.review_note}")
        click.echo(f"justification :\n{p.justification}")
    finally:
        session.close()


# -- intelligence sharing --------------------------------------------------


@cli.group()
def intel() -> None:
    """Threat-intelligence exports for partner CERTs."""


@intel.command("stix")
@click.option("--since", default="0", help="Signature DB version to export from.")
@click.option("--limit", default=1000, show_default=True)
@click.option("--output", "-o", type=click.Path(dir_okay=False, path_type=Path), default=None)
def intel_stix(since: str, limit: int, output: Path | None) -> None:
    """Export a STIX 2.1 bundle."""
    from .intel import stix_bundle

    entries = _export_entries(since, limit)
    payload = stix_bundle(entries, org_name=settings.intel_org_name, tlp=settings.intel_tlp)
    _emit(payload, output, f"{len(entries)} indicators")


@intel.command("misp")
@click.option("--since", default="0", help="Signature DB version to export from.")
@click.option("--limit", default=1000, show_default=True)
@click.option("--output", "-o", type=click.Path(dir_okay=False, path_type=Path), default=None)
def intel_misp(since: str, limit: int, output: Path | None) -> None:
    """Export a MISP event."""
    from .intel import misp_event

    entries = _export_entries(since, limit)
    payload = misp_event(entries, org_name=settings.intel_org_name, tlp=settings.intel_tlp)
    _emit(payload, output, f"{len(entries)} indicators")


def _export_entries(since: str, limit: int) -> list[dict]:
    hashdb = _hashdb()
    if since and since != "0":
        return hashdb.entries_since(since)[:limit]
    return hashdb.entries(limit=limit)


def _emit(payload: dict, output: Path | None, summary: str) -> None:
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if output is None:
        click.echo(text)
        return
    output.write_text(text, encoding="utf-8")
    click.echo(f"{summary} written to {output}")


# -- deferred scan worker --------------------------------------------------


@cli.command()
@click.option("--once", is_flag=True, help="Drain the queue and exit instead of polling.")
@click.option("--poll", default=2.0, show_default=True, help="Seconds between polls.")
def worker(once: bool, poll: float) -> None:
    """Process queued scan jobs (standalone worker for scaled-out installs)."""
    from .api.deps import get_quarantine
    from .db.session import init_db
    from .jobs import ScanWorker

    init_db()
    runner = ScanWorker(engine=_engine(), quarantine=get_quarantine(), poll_seconds=poll)
    if once:
        click.echo(f"{runner.drain_once()} job(s) processed")
        return
    click.echo("worker started, press Ctrl-C to stop")
    runner.start()
    try:
        while True:
            import time

            time.sleep(1)
    except KeyboardInterrupt:
        runner.stop()
        click.echo("worker stopped")


def _print_report(report: ScanReport) -> None:
    color = VERDICT_COLORS.get(report.verdict, "white")
    click.echo(f"file    : {report.file_name} ({report.file_size} bytes)")
    click.echo(f"sha256  : {report.sha256}")
    click.echo(f"engine  : {report.engine_version} / db {report.signature_db_version}")
    click.secho(f"verdict : {report.verdict.value} (score {report.score}/100)", fg=color, bold=True)
    if report.threat_name:
        click.echo(f"threat  : {report.threat_name}")
    facts = report.facts
    if facts and facts.is_valid_apk:
        click.echo(f"package : {facts.package_name}  ({facts.app_name})")
        click.echo(f"version : {facts.version_name}  targetSdk={facts.target_sdk}")
        click.echo(f"cert    : {facts.cert_sha256}")
        click.echo(f"perms   : {len(facts.permissions)} requested")
    if report.findings:
        click.echo("findings:")
        for finding in report.findings:
            click.echo(f"  [{finding.severity.value:8}] {finding.rule_id}: {finding.title}")
            if finding.evidence:
                click.echo(f"             evidence: {finding.evidence}")


if __name__ == "__main__":
    cli()
