package bf.fasoshield.agent.data

import bf.fasoshield.agent.network.FasoShieldApi
import bf.fasoshield.agent.network.TelemetryRequest
import bf.fasoshield.agent.scan.AppScanner
import bf.fasoshield.agent.scan.ScanResult
import bf.fasoshield.agent.scan.Verdict
import bf.fasoshield.agent.security.BundleVerificationException
import bf.fasoshield.agent.security.BundleVerifier
import bf.fasoshield.agent.util.Prefs
import kotlinx.coroutines.flow.Flow

/**
 * Coordinates the three agent workflows: signature delta sync, on-device
 * scanning with persistence, and anonymised telemetry.
 */
class AgentRepository(
    private val api: FasoShieldApi,
    private val store: SignatureStore,
    private val scanner: AppScanner,
    private val detectionDao: DetectionDao,
    private val prefs: Prefs,
    private val verifier: BundleVerifier,
) {

    fun observeDetections(): Flow<List<DetectionEntry>> = detectionDao.observeAll()

    /**
     * Pull only the signatures added since the local version. Returns the
     * number of new blocklist entries applied. Safe to call offline: any
     * network error propagates to the caller (WorkManager retries).
     */
    suspend fun syncSignatures(): Int {
        val remote = api.signatureVersion()
        if (remote.version == store.localVersion) return 0

        val update = api.signatureUpdates(since = store.localVersion)
        // Checked before a single row is written, and before the local version
        // advances: a rejected bundle leaves the agent on the last one it could
        // trust rather than on one it could not.
        if (!verifier.accepts(update)) throw BundleVerificationException(update.keyId)

        val entries = update.entries.map {
            BlocklistEntry(
                sha256 = it.sha256,
                threatName = it.threatName,
                source = it.source,
                // Carrying the certificate through is what makes the offline
                // layer-1 lookup (blocklistByCert) able to match anything.
                certSha256 = it.certSha256,
            )
        }
        store.applyBlocklistDelta(entries)
        store.localVersion = update.version
        return entries.size
    }

    /**
     * Scan installed apps, persist detections and return them. New detections
     * are queued for telemetry (reported = false).
     */
    suspend fun scanAndPersist(): List<ScanResult> {
        val results = scanner.scanInstalledApps()
        val now = System.currentTimeMillis()
        results.filter { it.isDetection }.forEach { result ->
            detectionDao.insert(
                DetectionEntry(
                    packageName = result.facts.packageName,
                    label = result.facts.label,
                    verdict = result.verdict.name,
                    score = result.score,
                    threatName = result.threatName,
                    detectedAt = now,
                )
            )
        }
        return results
    }

    /** Scan a single freshly installed package (called from the receiver). */
    suspend fun scanNewPackage(packageName: String): ScanResult? {
        val result = scanner.scanPackage(packageName) ?: return null
        if (result.isDetection) {
            detectionDao.insert(
                DetectionEntry(
                    packageName = result.facts.packageName,
                    label = result.facts.label,
                    verdict = result.verdict.name,
                    score = result.score,
                    threatName = result.threatName,
                    detectedAt = System.currentTimeMillis(),
                )
            )
        }
        return result
    }

    /**
     * Push not-yet-reported detections as anonymised telemetry. Each success
     * flips the detection's reported flag so it is sent at most once.
     */
    suspend fun flushTelemetry() {
        val pending = detectionDao.unreported()
        for (detection in pending) {
            runCatching {
                api.telemetry(
                    TelemetryRequest(
                        agentId = prefs.agentId,
                        eventType = "detection",
                        packageName = detection.packageName,
                        verdict = detection.verdict,
                        threatName = detection.threatName,
                        region = prefs.region,
                    )
                )
            }.onSuccess { detectionDao.markReported(detection.id) }
        }
    }

    companion object {
        /** True when a result warrants a user-facing alert. */
        fun shouldAlert(result: ScanResult): Boolean = result.verdict == Verdict.MALICIOUS
    }
}
