package bf.fasoshield.agent

import bf.fasoshield.agent.data.BlocklistEntry
import bf.fasoshield.agent.network.SignatureEntry
import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * The delta payload must carry the signing-certificate hash all the way into
 * the local Room table. Without it the agent's cheapest offline check — a
 * certificate lookup against the national blocklist — can never match, since
 * hashing every installed APK on device is not affordable.
 */
class SignatureSyncTest {

    /** Mirrors the mapping performed by AgentRepository.syncSignatures. */
    private fun toEntry(remote: SignatureEntry) = BlocklistEntry(
        sha256 = remote.sha256,
        threatName = remote.threatName,
        source = remote.source,
        certSha256 = remote.certSha256,
    )

    @Test
    fun `certificate indicator survives the mapping into local storage`() {
        val remote = SignatureEntry(
            sha256 = "a".repeat(64),
            threatName = "Trojan.FakeOM",
            source = "cert-bf/reviewed",
            addedAt = "2026-07-27T10:00:00+00:00",
            certSha256 = "b".repeat(64),
        )

        assertThat(toEntry(remote).certSha256).isEqualTo("b".repeat(64))
    }

    @Test
    fun `file-only indicator keeps a null certificate`() {
        val remote = SignatureEntry(
            sha256 = "c".repeat(64),
            threatName = "Spy.SmsThief",
            source = "partner-feed",
            addedAt = "2026-07-27T10:00:00+00:00",
        )

        assertThat(toEntry(remote).certSha256).isNull()
    }
}
