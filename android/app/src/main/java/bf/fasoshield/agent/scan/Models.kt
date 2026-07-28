package bf.fasoshield.agent.scan

/**
 * On-device scan model. Mirrors the server engine's verdict scale so an
 * agent-side result and a platform result are directly comparable.
 */

enum class Verdict { CLEAN, SUSPICIOUS, MALICIOUS }

enum class Severity(val weight: Int) {
    INFO(0),
    LOW(10),
    MEDIUM(25),
    HIGH(45),
    CRITICAL(100),
}

/** A single detection produced by one of the on-device layers. */
data class Finding(
    val ruleId: String,
    val title: String,
    val severity: Severity,
    val description: String,
    val evidence: String? = null,
)

/** Static facts read from an installed package via PackageManager. */
data class AppFacts(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val targetSdk: Int,
    val debuggable: Boolean,
    val permissions: List<String>,
    val certSha256: String?,
    val installerPackage: String?,
    // SHA-256 of the base APK. Left null by the offline pass — hashing every
    // installed package would cost minutes of I/O — and filled in only for the
    // few untrusted-provenance apps sent to the platform for reputation.
    val apkSha256: String?,
    // Path of the base APK on disk, needed to hash it on demand.
    val sourceDir: String? = null,
    // Preinstalled / system-origin app. Together with the installer source this
    // establishes provenance: trusted apps are exempt from permission-based
    // heuristics, which only indicate malice for sideloaded software.
    val isSystemApp: Boolean = false,
    // Whether installerPackage is itself a preinstalled system application.
    // OEMs push their bundled apps through in-house channels (OMC/CSC agent,
    // update centre, Settings) whose package names cannot be enumerated ahead
    // of time; that the installer is part of the ROM is the generic signal.
    val installerIsSystemApp: Boolean = false,
)

/** Result of scanning one installed application. */
data class ScanResult(
    val facts: AppFacts,
    val verdict: Verdict,
    val score: Int,
    val threatName: String?,
    val findings: List<Finding>,
) {
    val isDetection: Boolean
        get() = verdict == Verdict.SUSPICIOUS || verdict == Verdict.MALICIOUS

    /**
     * Add a finding produced after the offline pass — today, the platform's
     * reputation answer — and re-derive the verdict from the whole set, so a
     * remote conviction goes through the same scoring as a local one instead
     * of overriding it.
     */
    fun withFinding(finding: Finding): ScanResult {
        val merged = findings + finding
        val (newVerdict, newScore) = Scoring.verdictOf(merged)
        return copy(
            findings = merged,
            verdict = newVerdict,
            score = newScore,
            threatName = threatName ?: finding.evidence,
        )
    }
}

object Scoring {
    const val SUSPICIOUS_THRESHOLD = 30
    const val MALICIOUS_THRESHOLD = 70

    /** Aggregate findings into a verdict, matching the server logic. */
    fun verdictOf(findings: List<Finding>): Pair<Verdict, Int> {
        val score = findings.sumOf { it.severity.weight }.coerceAtMost(100)
        val hasCritical = findings.any { it.severity == Severity.CRITICAL }
        return when {
            hasCritical || score >= MALICIOUS_THRESHOLD -> Verdict.MALICIOUS to score
            score >= SUSPICIOUS_THRESHOLD -> Verdict.SUSPICIOUS to score
            else -> Verdict.CLEAN to score
        }
    }
}
