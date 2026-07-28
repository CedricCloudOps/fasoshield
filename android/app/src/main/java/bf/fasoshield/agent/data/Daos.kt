package bf.fasoshield.agent.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface BlocklistDao {
    @Query("SELECT * FROM blocklist WHERE sha256 = :sha256 LIMIT 1")
    suspend fun byHash(sha256: String): BlocklistEntry?

    @Query("SELECT * FROM blocklist WHERE certSha256 = :certSha256 LIMIT 1")
    suspend fun byCert(certSha256: String): BlocklistEntry?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(entries: List<BlocklistEntry>)

    @Query("SELECT COUNT(*) FROM blocklist")
    suspend fun count(): Int
}

@Dao
interface OfficialAppDao {
    @Query("SELECT * FROM official_apps")
    suspend fun all(): List<OfficialAppEntry>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(entries: List<OfficialAppEntry>)
}

@Dao
interface DetectionDao {
    @Insert
    suspend fun insert(entry: DetectionEntry): Long

    /**
     * Most recent detection per application.
     *
     * The table is an event log — one row per scan per application, which is
     * what lets telemetry report each occurrence exactly once — so reading it
     * back raw would show the same application once per scan it survived. The
     * screen wants current state, not history.
     */
    @Query(
        "SELECT * FROM detections WHERE id IN " +
            "(SELECT MAX(id) FROM detections GROUP BY packageName) " +
            "ORDER BY detectedAt DESC"
    )
    fun observeCurrent(): Flow<List<DetectionEntry>>

    @Query("SELECT * FROM detections WHERE reported = 0")
    suspend fun unreported(): List<DetectionEntry>

    /** Drop rows that have been reported and are older than the cutoff. A daily
     *  scan writes a row per standing detection, so without this the log grows
     *  for the life of the install. Unreported rows are never dropped: they
     *  still owe the platform an event. */
    @Query("DELETE FROM detections WHERE reported = 1 AND detectedAt < :cutoff")
    suspend fun pruneReportedBefore(cutoff: Long): Int

    @Query("UPDATE detections SET reported = 1 WHERE id = :id")
    suspend fun markReported(id: Long)
}
