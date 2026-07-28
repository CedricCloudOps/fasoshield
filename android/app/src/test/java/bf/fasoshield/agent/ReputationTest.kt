package bf.fasoshield.agent

import bf.fasoshield.agent.network.ReputationResponse
import bf.fasoshield.agent.scan.AppFacts
import bf.fasoshield.agent.scan.Finding
import bf.fasoshield.agent.scan.Reputation
import bf.fasoshield.agent.scan.ScanResult
import bf.fasoshield.agent.scan.Scoring
import bf.fasoshield.agent.scan.Severity
import bf.fasoshield.agent.scan.Verdict
import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * The platform reputation lookup: which applications are worth asking about,
 * and what the answer does to the offline verdict.
 */
class ReputationTest {

    private fun facts(
        packageName: String = "com.example.app",
        installer: String? = null,
        isSystemApp: Boolean = false,
        installerIsSystemApp: Boolean = false,
    ) = AppFacts(
        packageName = packageName,
        label = "Example",
        versionName = "1.0",
        targetSdk = 34,
        debuggable = false,
        permissions = emptyList(),
        certSha256 = "aa".repeat(32),
        installerPackage = installer,
        apkSha256 = null,
        sourceDir = "/data/app/com.example.app/base.apk",
        isSystemApp = isSystemApp,
        installerIsSystemApp = installerIsSystemApp,
    )

    private fun result(
        facts: AppFacts = facts(),
        findings: List<Finding> = emptyList(),
    ): ScanResult {
        val (verdict, score) = Scoring.verdictOf(findings)
        return ScanResult(facts, verdict, score, null, findings)
    }

    private val overlay = Finding(
        "heur.overlay", "Superposition d'écran", Severity.MEDIUM, "…",
    )

    private fun response(
        known: Boolean = true,
        verdict: String? = "MALICIOUS",
        threatName: String? = "Android.Fake.OrangeMoney",
        source: String? = "blocklist",
    ) = ReputationResponse(
        sha256 = "ff".repeat(32),
        known = known,
        verdict = verdict,
        threatName = threatName,
        source = source,
        signatureDbVersion = "20260727120000",
    )

    // -- which applications are worth a lookup --------------------------------

    @Test
    fun sideloadedApplicationIsLookedUp() {
        assertThat(Reputation.needsLookup(result())).isTrue()
    }

    /** Hashing a hundred trusted APKs on a low-end handset is the cost this
     *  gate exists to avoid; the platform has nothing to add about them. */
    @Test
    fun playStoreApplicationIsNotLookedUp() {
        assertThat(Reputation.needsLookup(result(facts(installer = "com.android.vending")))).isFalse()
    }

    @Test
    fun preinstalledApplicationIsNotLookedUp() {
        assertThat(Reputation.needsLookup(result(facts(isSystemApp = true)))).isFalse()
    }

    @Test
    fun oemPreloadIsNotLookedUp() {
        val preload = facts(installer = "com.samsung.android.app.omcagent", installerIsSystemApp = true)
        assertThat(Reputation.needsLookup(result(preload))).isFalse()
    }

    /** Already convicted offline: the verdict cannot get worse, and an agent
     *  with no connectivity must reach the same conclusion. */
    @Test
    fun locallyMaliciousApplicationIsNotLookedUp() {
        val convicted = result(
            findings = listOf(
                Finding("sig.cert_blocklist", "Certificat malveillant", Severity.CRITICAL, "…"),
            ),
        )
        assertThat(convicted.verdict).isEqualTo(Verdict.MALICIOUS)
        assertThat(Reputation.needsLookup(convicted)).isFalse()
    }

    // -- what the answer does -------------------------------------------------

    @Test
    fun platformConvictionMakesTheResultMalicious() {
        val merged = Reputation.merge(result(), response())

        assertThat(merged.verdict).isEqualTo(Verdict.MALICIOUS)
        assertThat(merged.findings.map { it.ruleId }).contains("plat.reputation")
        assertThat(merged.threatName).isEqualTo("Android.Fake.OrangeMoney")
    }

    /** A platform suspicion is a nudge, not a conviction: on its own it must
     *  not be enough to flag an otherwise clean application. */
    @Test
    fun platformSuspicionAloneStaysBelowTheDetectionThreshold() {
        val merged = Reputation.merge(result(), response(verdict = "SUSPICIOUS"))

        assertThat(merged.score).isEqualTo(Severity.MEDIUM.weight)
        assertThat(merged.verdict).isEqualTo(Verdict.CLEAN)
    }

    /** Combined with a local indicator, the same suspicion tips the result. */
    @Test
    fun platformSuspicionTipsAnAlreadyDoubtfulApplication() {
        val doubtful = result(findings = listOf(overlay))
        assertThat(doubtful.verdict).isEqualTo(Verdict.CLEAN)

        val merged = Reputation.merge(doubtful, response(verdict = "SUSPICIOUS"))
        assertThat(merged.verdict).isEqualTo(Verdict.SUSPICIOUS)
    }

    @Test
    fun cleanReputationChangesNothing() {
        val local = result(findings = listOf(overlay))
        assertThat(Reputation.merge(local, response(verdict = "CLEAN"))).isEqualTo(local)
    }

    @Test
    fun unknownSampleChangesNothing() {
        val local = result(findings = listOf(overlay))
        val unknown = response(known = false, verdict = null, threatName = null, source = null)
        assertThat(Reputation.merge(local, unknown)).isEqualTo(local)
    }

    /** The offline path must survive a platform that is unreachable, throttling
     *  or returning something this agent version does not understand. */
    @Test
    fun noAnswerLeavesTheOfflineVerdictUntouched() {
        val local = result(findings = listOf(overlay))
        assertThat(Reputation.merge(local, null)).isEqualTo(local)
    }

    @Test
    fun unrecognisedVerdictLeavesTheOfflineVerdictUntouched() {
        val local = result(findings = listOf(overlay))
        assertThat(Reputation.merge(local, response(verdict = "QUARANTINED"))).isEqualTo(local)
    }

    /** A local threat name was established by evidence on the device; the
     *  platform's label complements it rather than replacing it. */
    @Test
    fun existingThreatNameIsNotOverwritten() {
        val local = result().copy(threatName = "Local.Verdict")
        assertThat(Reputation.merge(local, response()).threatName).isEqualTo("Local.Verdict")
    }
}
