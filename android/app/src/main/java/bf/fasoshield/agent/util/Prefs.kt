package bf.fasoshield.agent.util

import android.content.Context
import java.util.UUID

/**
 * Lightweight preferences wrapper. Holds the opaque agent identifier and the
 * local signature DB version.
 *
 * Privacy: the agent id is a locally generated UUID with no link to any device
 * identifier (no IMEI, no MSISDN). It is the only identifier ever sent with
 * telemetry.
 */
class Prefs(context: Context) {

    private val sp = context.getSharedPreferences("fasoshield", Context.MODE_PRIVATE)

    /** Stable opaque agent id, generated once on first launch. */
    val agentId: String
        get() = sp.getString(KEY_AGENT_ID, null) ?: UUID.randomUUID().toString().also {
            sp.edit().putString(KEY_AGENT_ID, it).apply()
        }

    var signatureVersion: String
        get() = sp.getString(KEY_SIG_VERSION, "0") ?: "0"
        set(value) {
            sp.edit().putString(KEY_SIG_VERSION, value).apply()
        }

    /** Coarse, user-declared region for national campaign mapping (optional). */
    var region: String?
        get() = sp.getString(KEY_REGION, null)
        set(value) {
            sp.edit().putString(KEY_REGION, value).apply()
        }

    /**
     * Watermark of the download watcher, in seconds since the epoch, matching
     * the unit MediaStore uses for DATE_ADDED. It moves forward only over rows
     * that were actually processed, so an interrupted pass re-examines files
     * rather than skipping them.
     */
    var lastDownloadScanSeconds: Long
        get() = sp.getLong(KEY_LAST_DOWNLOAD_SCAN, 0L)
        set(value) {
            sp.edit().putLong(KEY_LAST_DOWNLOAD_SCAN, value).apply()
        }

    /**
     * Counts from the last completed scan. The detections themselves live in
     * Room, but the number of clean applications is not a detection and would
     * otherwise be lost, leaving the screen unable to say anything but zero
     * until the user scans again.
     */
    fun lastSummary(): ScanSummary = ScanSummary(
        malicious = sp.getInt(KEY_LAST_MALICIOUS, 0),
        suspicious = sp.getInt(KEY_LAST_SUSPICIOUS, 0),
        clean = sp.getInt(KEY_LAST_CLEAN, 0),
        at = sp.getLong(KEY_LAST_SCAN_AT, 0L),
    )

    fun saveSummary(malicious: Int, suspicious: Int, clean: Int, at: Long) {
        sp.edit()
            .putInt(KEY_LAST_MALICIOUS, malicious)
            .putInt(KEY_LAST_SUSPICIOUS, suspicious)
            .putInt(KEY_LAST_CLEAN, clean)
            .putLong(KEY_LAST_SCAN_AT, at)
            .apply()
    }

    companion object {
        private const val KEY_AGENT_ID = "agent_id"
        private const val KEY_SIG_VERSION = "signature_version"
        private const val KEY_REGION = "region"
        private const val KEY_LAST_MALICIOUS = "last_malicious"
        private const val KEY_LAST_SUSPICIOUS = "last_suspicious"
        private const val KEY_LAST_CLEAN = "last_clean"
        private const val KEY_LAST_SCAN_AT = "last_scan_at"
        private const val KEY_LAST_DOWNLOAD_SCAN = "last_download_scan"
    }
}

/** Counts and timestamp of the last completed scan. */
data class ScanSummary(
    val malicious: Int = 0,
    val suspicious: Int = 0,
    val clean: Int = 0,
    /** Epoch millis; 0 when no scan has ever completed on this device. */
    val at: Long = 0L,
) {
    val hasRun: Boolean get() = at > 0L
}
