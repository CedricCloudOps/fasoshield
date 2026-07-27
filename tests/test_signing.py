"""Signature bundle signing.

The canonical-form test is the important one: it pins the exact bytes both
implementations must agree on. Its fixture is duplicated verbatim in the
agent's BundleVerifierTest — if either side changes the layout, one of the two
suites fails and the drift is caught before a release ships an agent that
rejects every bundle the platform serves.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization

from fasoshield.signing import (
    BundleSigner,
    canonical_bundle,
    generate_key,
    key_id,
    load_private_key,
    private_key_pem,
    public_key_b64,
    sign_bundle,
    verify_bundle,
)

ENTRIES = [
    {
        "sha256": "bb" * 32,
        "threat_name": "Android.Fake.OrangeMoney",
        "source": "cert-nat",
        "added_at": "2026-07-27T10:00:00+00:00",
        "cert_sha256": "cc" * 32,
    },
    {
        "sha256": "aa" * 32,
        "threat_name": "Android.SmsStealer",
        "source": "misp",
        "added_at": "2026-07-26T09:30:00+00:00",
        "cert_sha256": None,
    },
]


def test_canonical_form_is_the_documented_layout():
    canonical = canonical_bundle("20260727120000", ENTRIES).decode()
    assert canonical == (
        "20260727120000\n"
        + "aa" * 32
        + "|Android.SmsStealer|misp|2026-07-26T09:30:00+00:00|\n"
        + "bb" * 32
        + "|Android.Fake.OrangeMoney|cert-nat|2026-07-27T10:00:00+00:00|"
        + "cc" * 32
        + "\n"
    )


def test_canonical_form_is_independent_of_entry_order():
    assert canonical_bundle("1", ENTRIES) == canonical_bundle("1", list(reversed(ENTRIES)))


def test_empty_bundle_still_binds_the_version():
    assert canonical_bundle("20260727120000", []) == b"20260727120000\n"


def test_sign_then_verify_roundtrip():
    key = generate_key()
    signature = sign_bundle(key, "20260727120000", ENTRIES)
    assert verify_bundle(key.public_key(), "20260727120000", ENTRIES, signature)


def test_tampered_entry_fails_verification():
    key = generate_key()
    signature = sign_bundle(key, "20260727120000", ENTRIES)

    forged = [dict(entry) for entry in ENTRIES]
    forged[0]["threat_name"] = "Harmless.Utility"

    assert not verify_bundle(key.public_key(), "20260727120000", forged, signature)


def test_added_entry_fails_verification():
    """The attack that matters: injecting an indicator that would make the
    genuine mobile money app be reported as malicious nationwide."""
    key = generate_key()
    signature = sign_bundle(key, "20260727120000", ENTRIES)

    injected = ENTRIES + [
        {
            "sha256": "dd" * 32,
            "threat_name": "Fake",
            "source": "attacker",
            "added_at": "2026-07-27T11:00:00+00:00",
            "cert_sha256": "ee" * 32,
        }
    ]
    assert not verify_bundle(key.public_key(), "20260727120000", injected, signature)


def test_version_is_bound_to_the_signature():
    key = generate_key()
    signature = sign_bundle(key, "20260727120000", ENTRIES)
    assert not verify_bundle(key.public_key(), "20260101000000", ENTRIES, signature)


def test_another_key_fails_verification():
    signature = sign_bundle(generate_key(), "20260727120000", ENTRIES)
    assert not verify_bundle(generate_key().public_key(), "20260727120000", ENTRIES, signature)


def test_malformed_signature_is_rejected_not_raised():
    key = generate_key()
    assert not verify_bundle(key.public_key(), "1", ENTRIES, "not-base64-at-all!!")


def test_key_id_is_stable_and_short():
    key = generate_key()
    assert key_id(key.public_key()) == key_id(key.public_key())
    assert len(key_id(key.public_key())) == 16


def test_public_key_b64_is_spki_parsable():
    """The agent feeds this exact string to X509EncodedKeySpec, which only
    accepts SubjectPublicKeyInfo."""
    key = generate_key()
    spki = base64.b64decode(public_key_b64(key.public_key()))
    assert serialization.load_der_public_key(spki).public_numbers() == (
        key.public_key().public_numbers()
    )


def test_private_key_roundtrips_through_pem(tmp_path):
    key = generate_key()
    path = tmp_path / "signing.pem"
    path.write_bytes(private_key_pem(key))

    signer = BundleSigner.from_path(path)
    signature = signer.sign("20260727120000", ENTRIES)

    assert signer.key_id == key_id(key.public_key())
    assert verify_bundle(key.public_key(), "20260727120000", ENTRIES, signature)


def test_rsa_key_is_rejected(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import rsa

    path = tmp_path / "rsa.pem"
    path.write_bytes(
        rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="EC private key"):
        load_private_key(path)


# Golden vector shared with the Android agent. The public half of a key whose
# private part never left the machine that produced the signature below, over
# the ENTRIES fixture at this version. The identical vector is asserted from
# Kotlin in BundleVerifierTest — the two implementations never meet in CI, so
# this pair is what proves they serialise a bundle the same way.
GOLDEN_PUBLIC_KEY = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVqFhI34r+TILg1HzRDBiPx62V6SnySwPKR+7gFMxMCPM"
    "q2tJbxQA5wfMRXScTFFMk8kvXhg41SBbcz2cRT8tBQ=="
)
GOLDEN_SIGNATURE = (
    "MEQCIAmL+DS30I3fVbZKz1NxamBMLCFv2s+ez4SFD46r2zo5AiBVE/XhbdRuxIRFJvvpuUU4GkjRCcZc"
    "Fv1R8DED2qAwxA=="
)
GOLDEN_VERSION = "20260727120000"


def _golden_public_key():
    return serialization.load_der_public_key(base64.b64decode(GOLDEN_PUBLIC_KEY))


def test_golden_vector_still_verifies():
    assert verify_bundle(_golden_public_key(), GOLDEN_VERSION, ENTRIES, GOLDEN_SIGNATURE)


def test_golden_vector_is_bound_to_its_version():
    assert not verify_bundle(_golden_public_key(), "20260101000000", ENTRIES, GOLDEN_SIGNATURE)
