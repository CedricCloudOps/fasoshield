package bf.fasoshield.agent

import bf.fasoshield.agent.scan.AppFacts
import bf.fasoshield.agent.scan.Heuristics
import bf.fasoshield.agent.scan.OfficialApp
import bf.fasoshield.agent.scan.Scoring
import bf.fasoshield.agent.scan.Severity
import bf.fasoshield.agent.scan.Verdict
import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * JVM unit tests for the on-device heuristics. These run without an emulator
 * and are the phase-3 counterpart of the server engine's heuristics tests, so
 * the two implementations stay behaviourally aligned.
 */
class HeuristicsTest {

    private val P = "android.permission."

    // Default provenance is a sideload (null installer, not a system app) so the
    // permission/hygiene heuristics are exercised; trusted-provenance cases pass
    // an official-store installer or isSystemApp = true explicitly.
    private fun facts(
        packageName: String = "com.example.app",
        label: String = "Example",
        permissions: List<String> = emptyList(),
        certSha256: String? = "aa".repeat(32),
        installer: String? = null,
        targetSdk: Int = 34,
        debuggable: Boolean = false,
        isSystemApp: Boolean = false,
    ) = AppFacts(
        packageName = packageName,
        label = label,
        versionName = "1.0",
        targetSdk = targetSdk,
        debuggable = debuggable,
        permissions = permissions,
        certSha256 = certSha256,
        installerPackage = installer,
        apkSha256 = null,
        isSystemApp = isSystemApp,
    )

    private val orangeOfficial = mapOf(
        "com.orange.money" to OfficialApp("com.orange.money", "Orange Money", "ff".repeat(32)),
    )

    private fun ruleIds(f: List<bf.fasoshield.agent.scan.Finding>) = f.map { it.ruleId }.toSet()

    @Test
    fun officialAppWithMatchingCertShortCircuits() {
        val findings = Heuristics.run(
            facts(
                packageName = "com.orange.money",
                certSha256 = "ff".repeat(32),
                permissions = listOf("${P}READ_SMS", "${P}INTERNET"),
            ),
            orangeOfficial,
        )
        assertThat(ruleIds(findings)).containsExactly("heur.official_app")
        assertThat(findings.first().severity).isEqualTo(Severity.INFO)
    }

    @Test
    fun certMismatchIsCritical() {
        val findings = Heuristics.run(
            facts(packageName = "com.orange.money", certSha256 = "bb".repeat(32)),
            orangeOfficial,
        )
        assertThat(ruleIds(findings)).contains("heur.cert_mismatch")
        val (verdict, _) = Scoring.verdictOf(findings)
        assertThat(verdict).isEqualTo(Verdict.MALICIOUS)
    }

    @Test
    fun packageLookalikeDetected() {
        val registry = mapOf(
            "com.orange.money" to OfficialApp("com.orange.money", "Orange Money", null),
        )
        val findings = Heuristics.run(facts(packageName = "com.orange.rnoney"), registry)
        assertThat(ruleIds(findings)).contains("heur.package_lookalike")
    }

    @Test
    fun brandInLabelFromUnofficialPackage() {
        val findings = Heuristics.run(
            facts(packageName = "com.freeapps.bonus", label = "Orange Money Bonus"),
            orangeOfficial,
        )
        assertThat(ruleIds(findings)).contains("heur.brand_in_label")
    }

    @Test
    fun smsExfiltrationCombo() {
        val findings = Heuristics.run(
            facts(permissions = listOf("${P}RECEIVE_SMS", "${P}INTERNET")),
            emptyMap(),
        )
        assertThat(ruleIds(findings)).contains("heur.sms_exfiltration")
    }

    @Test
    fun spywareComboCrossesMaliciousThreshold() {
        val findings = Heuristics.run(
            facts(
                permissions = listOf(
                    "${P}RECORD_AUDIO", "${P}INTERNET",
                    "${P}ACCESS_FINE_LOCATION", "${P}RECEIVE_SMS",
                ),
            ),
            emptyMap(),
        )
        assertThat(ruleIds(findings)).containsAtLeast("heur.spyware_combo", "heur.sms_exfiltration")
        val (verdict, score) = Scoring.verdictOf(findings)
        assertThat(verdict).isEqualTo(Verdict.MALICIOUS)
        assertThat(score).isAtLeast(70)
    }

    @Test
    fun sideloadFromUnknownInstallerFlagged() {
        val findings = Heuristics.run(facts(installer = null), emptyMap())
        assertThat(ruleIds(findings)).contains("heur.sideloaded")
    }

    @Test
    fun playStoreInstallNotFlaggedAsSideload() {
        val findings = Heuristics.run(facts(installer = "com.android.vending"), emptyMap())
        assertThat(ruleIds(findings)).doesNotContain("heur.sideloaded")
    }

    @Test
    fun legacyTargetSdkFlagged() {
        val findings = Heuristics.run(facts(targetSdk = 19), emptyMap())
        assertThat(ruleIds(findings)).contains("heur.legacy_target_sdk")
    }

    @Test
    fun benignPlayStoreAppStaysClean() {
        val findings = Heuristics.run(
            facts(
                installer = "com.android.vending",
                permissions = listOf("${P}INTERNET", "${P}ACCESS_NETWORK_STATE"),
            ),
            emptyMap(),
        )
        val (verdict, score) = Scoring.verdictOf(findings)
        assertThat(verdict).isEqualTo(Verdict.CLEAN)
        assertThat(score).isEqualTo(0)
    }

    // -- provenance gating: the fix for real-device false positives -----------

    /** A messaging app from the Play Store legitimately holds SMS, microphone,
     *  contacts and overlay permissions. Trusted provenance must keep it CLEAN
     *  (the WhatsApp/Telegram false-positive case). */
    @Test
    fun playStoreAppWithPowerfulPermissionsStaysClean() {
        val findings = Heuristics.run(
            facts(
                packageName = "com.whatsapp",
                label = "WhatsApp",
                installer = "com.android.vending",
                permissions = listOf(
                    "${P}RECEIVE_SMS", "${P}READ_SMS", "${P}INTERNET",
                    "${P}RECORD_AUDIO", "${P}READ_CONTACTS", "${P}SYSTEM_ALERT_WINDOW",
                ),
            ),
            emptyMap(),
        )
        assertThat(Scoring.verdictOf(findings).first).isEqualTo(Verdict.CLEAN)
    }

    /** Preinstalled OEM apps (Samsung Wallet, Health…) are trusted even when the
     *  installer is null and the system flag is under-reported. */
    @Test
    fun preinstalledSystemAppStaysClean() {
        val findings = Heuristics.run(
            facts(
                packageName = "com.samsung.android.spay",
                label = "Samsung Wallet",
                installer = null,
                isSystemApp = true,
                permissions = listOf("${P}RECEIVE_SMS", "${P}INTERNET", "${P}SYSTEM_ALERT_WINDOW"),
            ),
            emptyMap(),
        )
        assertThat(Scoring.verdictOf(findings).first).isEqualTo(Verdict.CLEAN)
    }

    @Test
    fun galaxyStoreAppIsTrusted() {
        val findings = Heuristics.run(
            facts(
                installer = "com.sec.android.app.samsungapps",
                permissions = listOf("${P}RECORD_AUDIO", "${P}INTERNET", "${P}READ_CONTACTS"),
            ),
            emptyMap(),
        )
        assertThat(ruleIds(findings)).isEmpty()
    }

    /** The same permission profile, sideloaded, is still caught. */
    @Test
    fun sideloadedSpywareProfileStillMalicious() {
        val findings = Heuristics.run(
            facts(
                installer = null,
                permissions = listOf(
                    "${P}RECEIVE_SMS", "${P}INTERNET",
                    "${P}RECORD_AUDIO", "${P}ACCESS_FINE_LOCATION",
                ),
            ),
            emptyMap(),
        )
        assertThat(Scoring.verdictOf(findings).first).isEqualTo(Verdict.MALICIOUS)
    }

    /** Impersonation is provenance-independent: a repackaged app claiming to be
     *  an official one is CRITICAL even when it comes from the Play Store. */
    @Test
    fun certMismatchFlaggedEvenFromOfficialStore() {
        val findings = Heuristics.run(
            facts(
                packageName = "com.orange.money",
                certSha256 = "bb".repeat(32),
                installer = "com.android.vending",
            ),
            orangeOfficial,
        )
        assertThat(ruleIds(findings)).contains("heur.cert_mismatch")
        assertThat(Scoring.verdictOf(findings).first).isEqualTo(Verdict.MALICIOUS)
    }
}
