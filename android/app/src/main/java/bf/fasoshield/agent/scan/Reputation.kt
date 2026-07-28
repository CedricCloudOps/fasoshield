package bf.fasoshield.agent.scan

import bf.fasoshield.agent.network.ReputationResponse

/**
 * Decides what the platform's opinion on an application is worth, and folds it
 * into the offline verdict.
 *
 * This is the agent's bridge to the server engine — YARA, DEX analysis, scan
 * history — without ever uploading an APK: only a hash leaves the device. The
 * rules live here rather than in the repository so they hold no Android
 * dependency and are covered by the JVM suite, same as [Heuristics].
 */
object Reputation {

    /**
     * Whether an application is worth a lookup.
     *
     * Trusted provenance is excluded because the platform has nothing to add
     * about an app that came preinstalled or from an official store, and a
     * lookup per installed package would mean hashing a hundred APKs on a
     * low-end handset. On a real device this leaves a handful of candidates.
     *
     * Locally convicted applications are excluded too: the verdict cannot get
     * worse than MALICIOUS, and an agent with no connectivity must reach the
     * same conclusion as one with it.
     */
    fun needsLookup(result: ScanResult): Boolean =
        result.verdict != Verdict.MALICIOUS && !Heuristics.trustedProvenance(result.facts)

    /**
     * Merge a reputation answer into a result. A `null` response — no network,
     * a timeout, a rejected key — leaves the offline verdict untouched: the
     * lookup can only add to what the device already decided on its own.
     */
    fun merge(result: ScanResult, response: ReputationResponse?): ScanResult {
        val severity = response?.takeIf { it.known }?.let { severityOf(it.verdict) }
            ?: return result
        return result.withFinding(
            Finding(
                ruleId = "plat.reputation",
                title = "Connue de la base nationale",
                severity = severity,
                description = "La plateforme classe cette application en " +
                    "${response.verdict} (source : ${response.source ?: "inconnue"}).",
                evidence = response.threatName,
            )
        )
    }

    /**
     * A platform conviction is CRITICAL: it comes from layers the agent cannot
     * run on device, on a sample an analyst or the engine has actually looked
     * at. A platform suspicion is worth less than a local one — it may rest on
     * a single weak indicator — so it is MEDIUM, enough to push an already
     * doubtful application over the SUSPICIOUS threshold without convicting a
     * benign one on its own.
     */
    private fun severityOf(verdict: String?): Severity? = when (verdict) {
        Verdict.MALICIOUS.name -> Severity.CRITICAL
        Verdict.SUSPICIOUS.name -> Severity.MEDIUM
        else -> null // clean, or a verdict this agent version does not know
    }
}
