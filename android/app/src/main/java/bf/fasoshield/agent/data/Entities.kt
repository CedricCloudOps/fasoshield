package bf.fasoshield.agent.data

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Local mirror of the national blocklist. Populated by delta sync from
 * GET /v1/signatures/updates and queried entirely offline.
 */
@Entity(tableName = "blocklist", indices = [Index("certSha256")])
data class BlocklistEntry(
    @PrimaryKey val sha256: String,
    val threatName: String,
    val source: String,
    // Certificate hash, when the IOC is expressed at signing-key granularity;
    // this is what the on-device scanner matches against.
    val certSha256: String? = null,
)

/** Local mirror of the official financial apps registry (allowlist). */
@Entity(tableName = "official_apps")
data class OfficialAppEntry(
    @PrimaryKey val packageName: String,
    val label: String,
    val certSha256: String?,
)

/** Persisted history of every detection, shown in the UI and fed to telemetry. */
@Entity(tableName = "detections")
data class DetectionEntry(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val packageName: String,
    val label: String,
    val verdict: String,
    val score: Int,
    val threatName: String?,
    val detectedAt: Long,
    val reported: Boolean = false,
)
