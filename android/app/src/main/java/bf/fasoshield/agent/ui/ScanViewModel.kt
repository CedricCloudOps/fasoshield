package bf.fasoshield.agent.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import bf.fasoshield.agent.ServiceLocator
import bf.fasoshield.agent.scan.ScanResult
import bf.fasoshield.agent.scan.Verdict
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class ScanUiState(
    val scanning: Boolean = false,
    val lastSyncCount: Int? = null,
    val results: List<ScanResult> = emptyList(),
    val error: String? = null,
) {
    val malicious get() = results.count { it.verdict == Verdict.MALICIOUS }
    val suspicious get() = results.count { it.verdict == Verdict.SUSPICIOUS }
    val clean get() = results.count { it.verdict == Verdict.CLEAN }
}

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val repo = ServiceLocator.repository(app)

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    /** Manual scan triggered from the UI: sync then scan. */
    fun runScan() {
        if (_state.value.scanning) return
        _state.value = _state.value.copy(scanning = true, error = null)
        viewModelScope.launch {
            val synced = runCatching { repo.syncSignatures() }.getOrNull()
            val outcome = runCatching { repo.scanAndPersist() }
            _state.value = outcome.fold(
                onSuccess = { results ->
                    ScanUiState(
                        scanning = false,
                        lastSyncCount = synced,
                        results = results.sortedByDescending { it.score },
                    )
                },
                onFailure = { t ->
                    _state.value.copy(scanning = false, error = t.message ?: "scan failed")
                },
            )
            runCatching { repo.flushTelemetry() }
        }
    }
}
