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
    val apkSha256: String?,
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
