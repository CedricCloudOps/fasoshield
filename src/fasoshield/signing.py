"""Detached signature over the signature bundle served to mobile agents.

The blocklist an agent applies decides what gets flagged on the handset. If it
can be tampered with in transit, an attacker either whitelists their own
malware or makes the genuine mobile money application be reported as malicious
on every phone in the country — the second outcome is unrecoverable in terms of
public trust. TLS alone does not cover it: it protects the channel, not the
payload, and leaves a compromised CA, a terminating proxy or a poisoned mirror
in the trust path.

So the platform signs the bundle itself and the agent verifies it with a public
key compiled into the APK, independently of how the bytes travelled.

**ECDSA P-256, not Ed25519.** Ed25519 is the better modern default, but
``java.security`` only exposes it from API 33 and the agent's minSdk is 24;
pulling in a crypto provider to cover the gap would add megabytes to an APK
distributed over metered mobile data. ``SHA256withECDSA`` on the NIST P-256
curve has been available on every Android release the agent targets, and is
sound.

The canonical form below is the wire contract between this module and
``BundleVerifier`` in the Android agent. Both sides rebuild it from parsed
fields rather than signing raw JSON, because neither side can guarantee a
byte-identical re-serialisation of the other's JSON. Any change here is a
breaking change and must land on both sides at once — the fixture in
``tests/test_signing.py`` and the one in ``BundleVerifierTest.kt`` are
deliberately identical so a drift fails the build on whichever side moved.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

_FIELD_SEPARATOR = "|"
_RECORD_SEPARATOR = "\n"


def canonical_bundle(version: str, entries: list[dict]) -> bytes:
    """Deterministic byte representation of a signature bundle.

    Layout — the version, then one record per entry, sorted by hash so the
    server's SQL ordering cannot influence the signature::

        <version>\\n
        <sha256>|<threat_name>|<source>|<added_at>|<cert_sha256>\\n

    ``cert_sha256`` is the empty string when absent. Every record, including
    the last, is newline-terminated.
    """
    lines = [version]
    for entry in sorted(entries, key=lambda e: e["sha256"]):
        lines.append(
            _FIELD_SEPARATOR.join(
                (
                    entry["sha256"],
                    entry["threat_name"],
                    entry["source"],
                    entry["added_at"],
                    entry.get("cert_sha256") or "",
                )
            )
        )
    return (_RECORD_SEPARATOR.join(lines) + _RECORD_SEPARATOR).encode("utf-8")


def key_id(public_key: ec.EllipticCurvePublicKey) -> str:
    """Short, stable identifier for a key, so a rotation is diagnosable from a
    log line rather than by comparing full keys."""
    spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()[:16]


def public_key_b64(public_key: ec.EllipticCurvePublicKey) -> str:
    """Base64 SubjectPublicKeyInfo — the form the agent embeds and feeds to
    ``KeyFactory``/``X509EncodedKeySpec``."""
    spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(spki).decode("ascii")


def generate_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def private_key_pem(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Unencrypted PKCS#8. The file is the secret: the deployment guide
    requires 0600 and an operator-owned path, and production keeps the real key
    in an HSM rather than on the API host."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("signature signing key must be an EC private key (P-256)")
    return key


def sign_bundle(
    private_key: ec.EllipticCurvePrivateKey, version: str, entries: list[dict]
) -> str:
    """Base64 DER ECDSA signature over the canonical bundle."""
    signature = private_key.sign(
        canonical_bundle(version, entries), ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode("ascii")


def verify_bundle(
    public_key: ec.EllipticCurvePublicKey,
    version: str,
    entries: list[dict],
    signature_b64: str,
) -> bool:
    """Counterpart of :func:`sign_bundle`. The agent runs the equivalent check;
    this one exists so the contract is covered by the platform's own tests."""
    try:
        public_key.verify(
            base64.b64decode(signature_b64),
            canonical_bundle(version, entries),
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


class BundleSigner:
    """Signing key loaded once at startup, held for the process lifetime."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self._private_key = private_key
        self.key_id = key_id(private_key.public_key())

    @classmethod
    def from_path(cls, path: Path) -> BundleSigner:
        return cls(load_private_key(path))

    def sign(self, version: str, entries: list[dict]) -> str:
        return sign_bundle(self._private_key, version, entries)
