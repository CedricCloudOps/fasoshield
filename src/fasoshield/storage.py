"""Quarantine storage backends.

Detected samples are kept so analysts can re-examine them and build the
national corpus. A single-server deployment keeps them on disk; a scaled-out
one puts them in object storage so any API instance can retrieve any sample.

The backend is chosen from a URL:

    file:///var/lib/fasoshield/quarantine
    s3://fasoshield-quarantine/samples          (requires the 's3' extra)

S3 support is optional on purpose: the platform must remain deployable on an
air-gapped national infrastructure with no cloud dependency.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse
from urllib.request import url2pathname


class QuarantineStore(Protocol):
    """Content-addressed store: a sample is written under its SHA-256."""

    def put(self, sha256: str, source: Path) -> str:
        """Store the file and return its location. Idempotent."""

    def exists(self, sha256: str) -> bool: ...

    def location(self, sha256: str) -> str:
        """Human-readable location, recorded in reports and the audit trail."""


class LocalQuarantine:
    """Filesystem backend. Files are fanned out over two levels of hash
    prefix so a single directory never holds millions of entries."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, sha256: str) -> Path:
        return self.root / sha256[:2] / sha256[2:4] / f"{sha256}.bin"

    def put(self, sha256: str, source: Path) -> str:
        target = self._path(sha256)
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            # Copy rather than move: the caller still owns the staged upload.
            target.write_bytes(Path(source).read_bytes())
        return str(target)

    def exists(self, sha256: str) -> bool:
        return self._path(sha256).exists()

    def location(self, sha256: str) -> str:
        return str(self._path(sha256))


class S3Quarantine:
    """S3-compatible backend (AWS S3, MinIO, Ceph RGW).

    Endpoint, region and credentials come from the standard AWS environment
    variables, so no secret is ever read from the application configuration.
    """

    def __init__(self, bucket: str, prefix: str = "") -> None:
        try:
            import boto3  # noqa: PLC0415 - optional dependency, imported on demand
        except ImportError as exc:  # pragma: no cover - depends on the install extra
            raise RuntimeError(
                "S3 quarantine requires the 's3' extra: pip install 'fasoshield[s3]'"
            ) from exc
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self._client = boto3.client("s3")

    def _key(self, sha256: str) -> str:
        parts = [self.prefix] if self.prefix else []
        parts += [sha256[:2], sha256[2:4], f"{sha256}.bin"]
        return "/".join(parts)

    def put(self, sha256: str, source: Path) -> str:
        if not self.exists(sha256):
            self._client.upload_file(str(source), self.bucket, self._key(sha256))
        return self.location(sha256)

    def exists(self, sha256: str) -> bool:
        from botocore.exceptions import ClientError  # noqa: PLC0415

        try:
            self._client.head_object(Bucket=self.bucket, Key=self._key(sha256))
        except ClientError:
            return False
        return True

    def location(self, sha256: str) -> str:
        return f"s3://{self.bucket}/{self._key(sha256)}"


def open_quarantine(url: str) -> QuarantineStore:
    """Instantiate the backend described by ``url``."""
    parsed = urlparse(url)
    if parsed.scheme in ("", "file"):
        # url2pathname turns /C:/... back into a usable Windows path and
        # decodes percent-escapes on POSIX.
        raw = parsed.path or url
        return LocalQuarantine(Path(url2pathname(raw)))
    if parsed.scheme == "s3":
        return S3Quarantine(bucket=parsed.netloc, prefix=parsed.path)
    raise ValueError(f"Unsupported quarantine URL scheme: {parsed.scheme!r}")
