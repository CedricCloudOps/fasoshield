package bf.fasoshield.agent.security

import bf.fasoshield.agent.network.SignatureEntry
import bf.fasoshield.agent.network.SignatureUpdateResponse
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import okio.ByteString.Companion.decodeBase64

/**
 * Verifies the detached signature the platform puts on every signature bundle.
 *
 * The blocklist the agent applies decides what gets flagged on this handset.
 * TLS protects the channel the bundle travelled through, not the bundle
 * itself, and leaves a compromised CA, a terminating proxy or a poisoned
 * mirror inside the trust path. So the payload is signed at the source and
 * checked here, against a key compiled into the APK — an attacker who controls
 * the transport still cannot make the agent whitelist their malware, nor make
 * it convict the genuine mobile money application on every phone in the
 * country.
 *
 * ECDSA over NIST P-256 rather than Ed25519: `java.security` only exposes
 * Ed25519 from API 33 and this agent's minSdk is 24, and bundling a crypto
 * provider to close the gap would add megabytes to an APK distributed over
 * metered mobile data. `SHA256withECDSA` has been present on every Android
 * release the agent supports.
 *
 * The canonical form below is a wire contract with `fasoshield.signing` on the
 * platform: both sides rebuild it from parsed fields, because neither can
 * guarantee a byte-identical re-serialisation of the other's JSON. Any change
 * is breaking and must land on both sides at once — the fixture in
 * BundleVerifierTest is duplicated verbatim in the platform's test_signing.py
 * so that a one-sided change fails a build.
 */
class BundleVerifier(private val publicKeyBase64: String) {

    /** False when no key was built into the APK: development builds sync
     *  against a local platform that has no signing key configured. A release
     *  build always carries the key, and an attacker cannot remove it from a
     *  signed APK, so this cannot be turned off in the field. */
    val enforced: Boolean get() = publicKeyBase64.isNotBlank()

    /**
     * Whether a delta may be applied. An enforcing agent rejects a bundle that
     * arrives unsigned just as firmly as one whose signature does not check
     * out: "no signature" is exactly what a stripping proxy produces.
     */
    fun accepts(update: SignatureUpdateResponse): Boolean {
        if (!enforced) return true
        val signature = update.signature ?: return false
        return verify(update.version, update.entries, signature)
    }

    private fun verify(
        version: String,
        entries: List<SignatureEntry>,
        signatureBase64: String,
    ): Boolean {
        val keyBytes = publicKeyBase64.decodeBase64() ?: return false
        val signatureBytes = signatureBase64.decodeBase64() ?: return false
        return runCatching {
            val key = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(keyBytes.toByteArray()))
            Signature.getInstance("SHA256withECDSA").apply {
                initVerify(key)
                update(canonical(version, entries))
            }.verify(signatureBytes.toByteArray())
        }.getOrDefault(false)
    }

    companion object {
        /**
         * Deterministic byte representation of a bundle:
         *
         *     <version>\n
         *     <sha256>|<threat_name>|<source>|<added_at>|<cert_sha256>\n
         *
         * Entries are sorted by hash so the platform's SQL ordering cannot
         * influence the signature, `cert_sha256` is the empty string when
         * absent, and every record is newline-terminated. Sorting agrees with
         * Python's because the key is lowercase hexadecimal, where UTF-16 and
         * code-point ordering coincide.
         */
        fun canonical(version: String, entries: List<SignatureEntry>): ByteArray {
            val builder = StringBuilder(version).append('\n')
            entries.sortedBy { it.sha256 }.forEach { entry ->
                builder.append(entry.sha256).append('|')
                    .append(entry.threatName).append('|')
                    .append(entry.source).append('|')
                    .append(entry.addedAt).append('|')
                    .append(entry.certSha256.orEmpty()).append('\n')
            }
            return builder.toString().toByteArray(Charsets.UTF_8)
        }
    }
}

/**
 * Raised when a delta fails verification. It aborts the sync before anything
 * is written, so the agent keeps running on the last bundle it could trust
 * rather than on one it could not.
 */
class BundleVerificationException(keyId: String?) : SecurityException(
    "signature bundle rejected (key_id=${keyId ?: "absent"})"
)
