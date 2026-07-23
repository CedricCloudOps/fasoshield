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

    @Query("SELECT * FROM detections ORDER BY detectedAt DESC")
    fun observeAll(): Flow<List<DetectionEntry>>

    @Query("SELECT * FROM detections WHERE reported = 0")
    suspend fun unreported(): List<DetectionEntry>

    @Query("UPDATE detections SET reported = 1 WHERE id = :id")
    suspend fun markReported(id: Long)
}
