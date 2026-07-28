package bf.fasoshield.agent.scan

import bf.fasoshield.agent.network.ReputationResponse

/** Where a verdict on a downloaded file came from. */
enum class TriageSource { BLOCKLIST, PLATFORM, UNKNOWN }

/**
 * Conclusion on a file that has just landed in the download folder, before
 * anything is installed.
 */
data class DownloadAssessment(
    val verdict: Verdict,
    val threatName: String?,
    val source: TriageSource,
) {
    val isThreat: Boolean get() = verdict == Verdict.MALICIOUS
}

/**
 * Decides what to do with a file appearing in the download folder.
 *
 * The attack this addresses runs in four steps: a fraudulent SMS, a link, an
 * APK download, an install. Until now the agent only woke up at step four,
 * once the application was already on the device and the user had already been
 * persuaded to trust it. Watching the download folder moves the intervention
 * one step earlier, to the moment the file lands and before the user taps it —
 * which is also the last moment where doing nothing costs them nothing.
 *
 * The rules live here, free of any Android dependency, so they are covered by
 * the JVM suite like [Heuristics] and [Reputation].
 */
object DownloadTriage {

    private const val APK_MIME = "application/vnd.android.package-archive"

    /**
     * Whether a freshly indexed download is worth hashing.
     *
     * Both signals are checked because neither is reliable alone: a download
     * server routinely serves an APK as `application/octet-stream`, and a
     * MediaStore row can carry a mime type with a display name that has lost
     * its extension. Anything else is left alone — this agent has no business
     * hashing the user's photos and documents.
     */
    fun isApkCandidate(displayName: String?, mimeType: String?): Boolean {
        if (mimeType?.equals(APK_MIME, ignoreCase = true) == true) return true
        val name = displayName?.trim()?.lowercase() ?: return false
        return name.endsWith(".apk") || name.endsWith(".apkm") || name.endsWith(".xapk")
    }

    /**
     * Verdict on a downloaded APK, from the local blocklist first and the
     * platform second.
     *
     * The blocklist comes first because it answers offline, and a file already
     * in the national blocklist needs no confirmation. The platform is only
     * consulted when the local base says nothing, and its answer can only
     * convict — an unknown file stays unknown rather than being pronounced
     * safe, because the agent has not analysed its code and cannot vouch for
     * it. Saying "clean" here would be a promise the agent cannot keep.
     */
    fun assess(localThreat: String?, response: ReputationResponse?): DownloadAssessment {
        if (localThreat != null) {
            return DownloadAssessment(Verdict.MALICIOUS, localThreat, TriageSource.BLOCKLIST)
        }
        if (response != null && response.known && response.verdict == Verdict.MALICIOUS.name) {
            return DownloadAssessment(
                Verdict.MALICIOUS, response.threatName, TriageSource.PLATFORM,
            )
        }
        if (response != null && response.known && response.verdict == Verdict.SUSPICIOUS.name) {
            return DownloadAssessment(
                Verdict.SUSPICIOUS, response.threatName, TriageSource.PLATFORM,
            )
        }
        return DownloadAssessment(Verdict.CLEAN, null, TriageSource.UNKNOWN)
    }

    /**
     * Whether the user is warned. Only a conviction interrupts them: a warning
     * on every downloaded APK would train them to dismiss the one that matters,
     * and the agent will scan the application again at install time anyway.
     */
    fun shouldWarn(assessment: DownloadAssessment): Boolean = assessment.isThreat
}
