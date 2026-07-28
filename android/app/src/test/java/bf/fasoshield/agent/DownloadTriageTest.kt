package bf.fasoshield.agent

import bf.fasoshield.agent.network.ReputationResponse
import bf.fasoshield.agent.scan.DownloadTriage
import bf.fasoshield.agent.scan.TriageSource
import bf.fasoshield.agent.scan.Verdict
import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * Triage of files landing in the download folder — the step that moves the
 * agent ahead of the installation instead of behind it.
 */
class DownloadTriageTest {

    private val APK_MIME = "application/vnd.android.package-archive"

    private fun response(
        known: Boolean = true,
        verdict: String? = "MALICIOUS",
        threatName: String? = "Android.Fake.OrangeMoney",
    ) = ReputationResponse(
        sha256 = "ff".repeat(32),
        known = known,
        verdict = verdict,
        threatName = threatName,
        source = "blocklist",
        signatureDbVersion = "20260728100000",
    )

    // -- what is worth hashing ------------------------------------------------

    @Test
    fun apkMimeTypeIsACandidate() {
        assertThat(DownloadTriage.isApkCandidate("orange-money-bonus", APK_MIME)).isTrue()
    }

    /** Download servers routinely serve an APK as a generic binary stream, so
     *  the extension has to be enough on its own. */
    @Test
    fun apkExtensionIsACandidateWhateverTheMimeType() {
        assertThat(
            DownloadTriage.isApkCandidate("orange-money.apk", "application/octet-stream")
        ).isTrue()
        assertThat(DownloadTriage.isApkCandidate("bundle.xapk", null)).isTrue()
        assertThat(DownloadTriage.isApkCandidate("Setup.APK", null)).isTrue()
    }

    /** The agent has no business hashing the user's photos and documents. */
    @Test
    fun ordinaryDownloadsAreLeftAlone() {
        assertThat(DownloadTriage.isApkCandidate("facture.pdf", "application/pdf")).isFalse()
        assertThat(DownloadTriage.isApkCandidate("photo.jpg", "image/jpeg")).isFalse()
        assertThat(DownloadTriage.isApkCandidate("notes.apkalypse.txt", "text/plain")).isFalse()
        assertThat(DownloadTriage.isApkCandidate(null, null)).isFalse()
    }

    // -- what the verdict is --------------------------------------------------

    @Test
    fun blocklistHitConvictsWithoutTheNetwork() {
        val assessment = DownloadTriage.assess("Android.SmsStealer", null)

        assertThat(assessment.verdict).isEqualTo(Verdict.MALICIOUS)
        assertThat(assessment.source).isEqualTo(TriageSource.BLOCKLIST)
        assertThat(assessment.threatName).isEqualTo("Android.SmsStealer")
    }

    @Test
    fun platformConvictionIsUsedWhenTheLocalBaseIsSilent() {
        val assessment = DownloadTriage.assess(null, response())

        assertThat(assessment.verdict).isEqualTo(Verdict.MALICIOUS)
        assertThat(assessment.source).isEqualTo(TriageSource.PLATFORM)
        assertThat(assessment.isThreat).isTrue()
    }

    @Test
    fun platformSuspicionIsRecordedButDoesNotConvict() {
        val assessment = DownloadTriage.assess(null, response(verdict = "SUSPICIOUS"))

        assertThat(assessment.verdict).isEqualTo(Verdict.SUSPICIOUS)
        assertThat(assessment.isThreat).isFalse()
    }

    /** An unknown file is unknown, not safe: the agent has not looked at its
     *  code and cannot vouch for it. */
    @Test
    fun unknownFileIsNotPronouncedSafe() {
        val assessment = DownloadTriage.assess(null, response(known = false, verdict = null))

        assertThat(assessment.source).isEqualTo(TriageSource.UNKNOWN)
        assertThat(assessment.threatName).isNull()
        assertThat(assessment.isThreat).isFalse()
    }

    /** No network, nothing in the local base: the download proceeds, and the
     *  install-time scan remains the backstop. */
    @Test
    fun noAnswerAtAllIsNotAThreat() {
        assertThat(DownloadTriage.assess(null, null).isThreat).isFalse()
    }

    // -- when the user is interrupted -----------------------------------------

    @Test
    fun onlyAConvictionWarnsTheUser() {
        assertThat(DownloadTriage.shouldWarn(DownloadTriage.assess("Trojan.FakeOM", null))).isTrue()
        assertThat(
            DownloadTriage.shouldWarn(DownloadTriage.assess(null, response(verdict = "SUSPICIOUS")))
        ).isFalse()
        assertThat(DownloadTriage.shouldWarn(DownloadTriage.assess(null, null))).isFalse()
    }
}
