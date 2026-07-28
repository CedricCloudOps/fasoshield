package bf.fasoshield.agent.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import bf.fasoshield.agent.ServiceLocator
import bf.fasoshield.agent.data.DetectionEntry
import bf.fasoshield.agent.scan.ScanResult
import bf.fasoshield.agent.scan.Verdict
import bf.fasoshield.agent.security.BundleVerificationException
import bf.fasoshield.agent.util.ScanSummary
import bf.fasoshield.agent.work.ApkDownloadWatcher
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * One detection as the screen needs it, whether it was just produced by a scan
 * or read back from the database on a later launch. A single shape here keeps
 * the card composable from having to know which of the two it is looking at.
 */
data class DetectionView(
    val packageName: String,
    val label: String,
    val verdict: Verdict,
    val score: Int,
    val reasons: List<String>,
)

data class ScanUiState(
    val scanning: Boolean = false,
    val lastSyncCount: Int? = null,
    val summary: ScanSummary = ScanSummary(),
    val detections: List<DetectionView> = emptyList(),
    val error: String? = null,
    /** All-files access, without which downloads cannot be watched. */
    val watchesDownloads: Boolean = false,
)

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val repo = ServiceLocator.repository(app)

    // Counts from the last completed scan, restored before anything is drawn:
    // an agent that shows three zeros on every launch reads as broken, even
    // though its detections were persisted all along.
    private val _state = MutableStateFlow(
        ScanUiState(
            summary = repo.lastSummary(),
            watchesDownloads = ApkDownloadWatcher.hasFileAccess(app),
        )
    )
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    /** True once a scan has run in this process, after which the live results
     *  are richer than the stored rows and take precedence. */
    private var showingLiveResults = false

    init {
        viewModelScope.launch {
            repo.observeDetections().collect { entries ->
                if (!showingLiveResults) {
                    _state.value = _state.value.copy(detections = entries.map(::toView))
                }
            }
        }
    }

    /**
     * Re-read the file access state. Called when the screen resumes, because
     * the user grants it in a system settings screen and comes back — nothing
     * notifies the application that it changed.
     */
    fun refreshFileAccess() {
        val granted = ApkDownloadWatcher.hasFileAccess(getApplication())
        if (granted != _state.value.watchesDownloads) {
            _state.value = _state.value.copy(watchesDownloads = granted)
        }
    }

    /** Manual scan triggered from the UI: sync then scan. */
    fun runScan() {
        if (_state.value.scanning) return
        _state.value = _state.value.copy(scanning = true, error = null)
        viewModelScope.launch {
            val sync = runCatching { repo.syncSignatures() }
            val outcome = runCatching { repo.scanAndPersist() }
            _state.value = outcome.fold(
                onSuccess = { results ->
                    showingLiveResults = true
                    ScanUiState(
                        scanning = false,
                        watchesDownloads = _state.value.watchesDownloads,
                        lastSyncCount = sync.getOrNull(),
                        summary = repo.lastSummary(),
                        detections = results
                            .filter { it.isDetection }
                            .sortedByDescending { it.score }
                            .map(::toView),
                        error = syncError(sync.exceptionOrNull()),
                    )
                },
                onFailure = { failure ->
                    _state.value.copy(
                        scanning = false,
                        error = failure.message ?: "échec de l'analyse",
                    )
                },
            )
            runCatching { repo.flushTelemetry() }
        }
    }

    /**
     * A network error during sync is routine and stays silent — the agent is
     * built to keep working offline. A rejected bundle is not: it means
     * something in the path served signatures the platform did not sign, and
     * the user is running on an older database than they believe.
     */
    private fun syncError(failure: Throwable?): String? =
        if (failure is BundleVerificationException) {
            "Mise à jour des signatures refusée : signature invalide."
        } else {
            null
        }

    private fun toView(result: ScanResult) = DetectionView(
        packageName = result.facts.packageName,
        label = result.facts.label,
        verdict = result.verdict,
        score = result.score,
        reasons = result.findings.map { it.title },
    )

    // Stored rows keep the verdict, the score and the threat name, not the full
    // finding list — enough to name what was found and let the user act on it,
    // with the detail one scan away.
    private fun toView(entry: DetectionEntry) = DetectionView(
        packageName = entry.packageName,
        label = entry.label,
        verdict = runCatching { Verdict.valueOf(entry.verdict) }.getOrDefault(Verdict.SUSPICIOUS),
        score = entry.score,
        reasons = listOfNotNull(entry.threatName),
    )
}
