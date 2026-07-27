package bf.fasoshield.agent

import bf.fasoshield.agent.network.SignatureEntry
import bf.fasoshield.agent.network.SignatureUpdateResponse
import bf.fasoshield.agent.security.BundleVerifier
import com.google.common.truth.Truth.assertThat
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import okio.ByteString.Companion.toByteString
import org.junit.Test

/**
 * Verification of the signature bundle the platform serves to agents.
 *
 * The canonical-form test is the load-bearing one: its fixture is duplicated
 * verbatim in the platform's tests/test_signing.py. The two implementations
 * never talk to each other in CI, so this pair of assertions is what keeps
 * them byte-compatible — change the layout on one side and the other's suite
 * goes red, instead of a release shipping an agent that rejects every bundle.
 */
class BundleVerifierTest {

    private val entries = listOf(
        SignatureEntry(
            sha256 = "bb".repeat(32),
            threatName = "Android.Fake.OrangeMoney",
            source = "cert-nat",
            addedAt = "2026-07-27T10:00:00+00:00",
            certSha256 = "cc".repeat(32),
        ),
        SignatureEntry(
            sha256 = "aa".repeat(32),
            threatName = "Android.SmsStealer",
            source = "misp",
            addedAt = "2026-07-26T09:30:00+00:00",
            certSha256 = null,
        ),
    )

    private fun keyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

    private fun publicKeyBase64(keys: KeyPair) = keys.public.encoded.toByteString().base64()

    private fun sign(keys: KeyPair, version: String, entries: List<SignatureEntry>): String =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(keys.private)
            update(BundleVerifier.canonical(version, entries))
            sign().toByteString().base64()
        }

    private fun update(
        version: String = "20260727120000",
        entries: List<SignatureEntry> = this.entries,
        signature: String?,
        keyId: String? = "0011223344556677",
    ) = SignatureUpdateResponse(
        since = "0",
        version = version,
        entries = entries,
        signature = signature,
        keyId = keyId,
    )

    @Test
    fun canonicalFormMatchesTheDocumentedLayout() {
        val canonical = String(BundleVerifier.canonical("20260727120000", entries))
        assertThat(canonical).isEqualTo(
            "20260727120000\n" +
                "aa".repeat(32) + "|Android.SmsStealer|misp|2026-07-26T09:30:00+00:00|\n" +
                "bb".repeat(32) + "|Android.Fake.OrangeMoney|cert-nat|2026-07-27T10:00:00+00:00|" +
                "cc".repeat(32) + "\n"
        )
    }

    @Test
    fun canonicalFormIsIndependentOfEntryOrder() {
        assertThat(BundleVerifier.canonical("1", entries))
            .isEqualTo(BundleVerifier.canonical("1", entries.reversed()))
    }

    @Test
    fun emptyBundleStillBindsTheVersion() {
        assertThat(String(BundleVerifier.canonical("20260727120000", emptyList())))
            .isEqualTo("20260727120000\n")
    }

    @Test
    fun genuineBundleIsAccepted() {
        val keys = keyPair()
        val verifier = BundleVerifier(publicKeyBase64(keys))
        assertThat(verifier.accepts(update(signature = sign(keys, "20260727120000", entries))))
            .isTrue()
    }

    @Test
    fun tamperedEntryIsRejected() {
        val keys = keyPair()
        val signature = sign(keys, "20260727120000", entries)
        val forged = entries.toMutableList().apply {
            this[0] = this[0].copy(threatName = "Harmless.Utility")
        }
        assertThat(BundleVerifier(publicKeyBase64(keys)).accepts(update(entries = forged, signature = signature)))
            .isFalse()
    }

    /** The attack that matters: injecting an indicator that would convict the
     *  genuine mobile money application on every handset in the country. */
    @Test
    fun injectedEntryIsRejected() {
        val keys = keyPair()
        val signature = sign(keys, "20260727120000", entries)
        val injected = entries + SignatureEntry(
            sha256 = "dd".repeat(32),
            threatName = "Injected",
            source = "attacker",
            addedAt = "2026-07-27T11:00:00+00:00",
            certSha256 = "ee".repeat(32),
        )
        assertThat(BundleVerifier(publicKeyBase64(keys)).accepts(update(entries = injected, signature = signature)))
            .isFalse()
    }

    @Test
    fun versionIsBoundToTheSignature() {
        val keys = keyPair()
        val signature = sign(keys, "20260727120000", entries)
        assertThat(BundleVerifier(publicKeyBase64(keys)).accepts(update(version = "20260101000000", signature = signature)))
            .isFalse()
    }

    @Test
    fun signatureFromAnotherKeyIsRejected() {
        val signature = sign(keyPair(), "20260727120000", entries)
        assertThat(BundleVerifier(publicKeyBase64(keyPair())).accepts(update(signature = signature)))
            .isFalse()
    }

    /** A stripping proxy produces exactly this: a well-formed bundle with the
     *  signature removed. It must be as unacceptable as a wrong one. */
    @Test
    fun unsignedBundleIsRejectedWhenEnforcing() {
        val verifier = BundleVerifier(publicKeyBase64(keyPair()))
        assertThat(verifier.enforced).isTrue()
        assertThat(verifier.accepts(update(signature = null, keyId = null))).isFalse()
    }

    @Test
    fun malformedSignatureIsRejectedNotThrown() {
        assertThat(BundleVerifier(publicKeyBase64(keyPair())).accepts(update(signature = "not-base64!!")))
            .isFalse()
    }

    @Test
    fun malformedPublicKeyIsRejectedNotThrown() {
        val keys = keyPair()
        val signature = sign(keys, "20260727120000", entries)
        assertThat(BundleVerifier("this-is-not-a-key").accepts(update(signature = signature))).isFalse()
    }

    /**
     * Golden vector: this signature was produced by the platform's Python
     * signer over the fixture above, and only its public half is recorded here.
     *
     * The other tests sign with a JVM key, so they would still pass if both
     * sides of the canonical form drifted together within this codebase. This
     * one cannot: the bytes were signed by the other implementation, and the
     * same vector is asserted from Python in tests/test_signing.py. If either
     * language changes how a bundle is serialised, this test goes red.
     */
    @Test
    fun signatureProducedByThePlatformVerifiesHere() {
        val platformPublicKey =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVqFhI34r+TILg1HzRDBiPx62V6Sny" +
                "SwPKR+7gFMxMCPMq2tJbxQA5wfMRXScTFFMk8kvXhg41SBbcz2cRT8tBQ=="
        val platformSignature =
            "MEQCIAmL+DS30I3fVbZKz1NxamBMLCFv2s+ez4SFD46r2zo5AiBVE/XhbdRuxIRFJ" +
                "vvpuUU4GkjRCcZcFv1R8DED2qAwxA=="

        val verifier = BundleVerifier(platformPublicKey)
        assertThat(verifier.accepts(update(signature = platformSignature))).isTrue()
        assertThat(
            verifier.accepts(
                update(version = "20260101000000", signature = platformSignature)
            )
        ).isFalse()
    }

    /** A build with no key embedded targets a local platform that signs
     *  nothing; it must not refuse to sync. */
    @Test
    fun buildWithoutAKeyDoesNotEnforce() {
        val verifier = BundleVerifier("")
        assertThat(verifier.enforced).isFalse()
        assertThat(verifier.accepts(update(signature = null, keyId = null))).isTrue()
    }
}
