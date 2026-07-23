"""Analyst command-line interface.

    fasoshield scan sample.apk [--json]
    fasoshield lookup <sha256>
    fasoshield db import signatures/hashes/blocklist.seed.csv
    fasoshield db import-official signatures/hashes/official_apps.seed.csv
    fasoshield db stats
"""

from __future__ import annotations

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
    hit = _hashdb().lookup(sha256)
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
    """Import a blocklist CSV feed (sha256,threat_name,source)."""
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
