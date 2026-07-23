"""SHA-256 signature database.

Two datasets are maintained:

- a blocklist of known-malicious sample hashes (fed by the national CERT,
  MISP exports or partner feeds), stored in SQLite for O(1) lookups;
- an allowlist of official application packages (mobile money, banking)
  mapping a package name to the SHA-256 of its legitimate signing
  certificate, used by the impersonation heuristics.

CSV import format for the blocklist (header required):
    sha256,threat_name,source
"""

from __future__ import annotations

import csv
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS blocklist (
    sha256      TEXT PRIMARY KEY,
    threat_name TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'local',
    added_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS official_apps (
    package_name TEXT PRIMARY KEY,
    label        TEXT NOT NULL,
    cert_sha256  TEXT,
    added_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class HashDB:
    """SQLite-backed signature store. Thread-safe for reads (one conn per call)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    # -- blocklist ---------------------------------------------------------

    def lookup(self, sha256: str) -> dict | None:
        """Return the blocklist entry for a hash, or None if unknown."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT sha256, threat_name, source, added_at FROM blocklist WHERE sha256 = ?",
                (sha256.lower(),),
            ).fetchone()
        return dict(row) if row else None

    def add(self, sha256: str, threat_name: str, source: str = "local") -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO blocklist (sha256, threat_name, source, added_at) "
                "VALUES (?, ?, ?, ?)",
                (sha256.lower(), threat_name, source, now),
            )
        self._bump_version()

    def import_csv(self, csv_path: Path) -> int:
        """Bulk-import a CSV feed. Returns the number of imported entries."""
        now = datetime.now(timezone.utc).isoformat()
        count = 0
        with open(csv_path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = []
            for row in reader:
                sha256 = (row.get("sha256") or "").strip().lower()
                if len(sha256) != 64:
                    continue  # skip malformed lines rather than aborting the feed
                rows.append(
                    (
                        sha256,
                        (row.get("threat_name") or "Unknown").strip(),
                        (row.get("source") or "csv-import").strip(),
                        now,
                    )
                )
            with self._connect() as conn:
                conn.executemany(
                    "INSERT OR REPLACE INTO blocklist (sha256, threat_name, source, added_at) "
                    "VALUES (?, ?, ?, ?)",
                    rows,
                )
            count = len(rows)
        if count:
            self._bump_version()
        return count

    # -- official apps allowlist ------------------------------------------

    def official_app(self, package_name: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT package_name, label, cert_sha256 FROM official_apps "
                "WHERE package_name = ?",
                (package_name,),
            ).fetchone()
        return dict(row) if row else None

    def official_packages(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT package_name, label, cert_sha256 FROM official_apps"
            ).fetchall()
        return [dict(r) for r in rows]

    def import_official_csv(self, csv_path: Path) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with open(csv_path, newline="", encoding="utf-8") as fh:
            rows = [
                (
                    row["package_name"].strip(),
                    row["label"].strip(),
                    (row.get("cert_sha256") or "").strip().lower() or None,
                    now,
                )
                for row in csv.DictReader(fh)
                if row.get("package_name")
            ]
        with self._connect() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO official_apps (package_name, label, cert_sha256, added_at) "
                "VALUES (?, ?, ?, ?)",
                rows,
            )
        if rows:
            self._bump_version()
        return len(rows)

    # -- versioning --------------------------------------------------------

    def version(self) -> str:
        """Monotonic signature DB version, used by agents for delta updates."""
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()
        return row["value"] if row else "0"

    def _bump_version(self) -> None:
        # Timestamp-based version: strictly increasing and human-readable.
        version = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('version', ?)", (version,)
            )

    def entries_since(self, version: str) -> list[dict]:
        """Blocklist entries added after a given version (for agent delta sync).

        Versions have one-second granularity: entries written in the same
        second as the client's version are considered already delivered.
        """
        try:
            floor = datetime.strptime(version, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            floor = datetime.fromtimestamp(0, tz=timezone.utc)
        # Cheap SQL prefilter (lexicographic >= catches the same-second edge),
        # then a precise datetime comparison truncated to the second.
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT sha256, threat_name, source, added_at FROM blocklist "
                "WHERE added_at >= ?",
                (floor.isoformat(),),
            ).fetchall()
        return [
            dict(r)
            for r in rows
            if datetime.fromisoformat(r["added_at"]).replace(microsecond=0) > floor
        ]

    def stats(self) -> dict:
        with self._connect() as conn:
            blocklist = conn.execute("SELECT COUNT(*) AS n FROM blocklist").fetchone()["n"]
            official = conn.execute("SELECT COUNT(*) AS n FROM official_apps").fetchone()["n"]
        return {"blocklist": blocklist, "official_apps": official, "version": self.version()}
