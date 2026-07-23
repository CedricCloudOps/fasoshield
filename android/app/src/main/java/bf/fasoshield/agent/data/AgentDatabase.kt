package bf.fasoshield.agent.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [BlocklistEntry::class, OfficialAppEntry::class, DetectionEntry::class],
    version = 1,
    exportSchema = false,
)
abstract class AgentDatabase : RoomDatabase() {
    abstract fun blocklistDao(): BlocklistDao
    abstract fun officialAppDao(): OfficialAppDao
    abstract fun detectionDao(): DetectionDao

    companion object {
        @Volatile
        private var instance: AgentDatabase? = null

        fun get(context: Context): AgentDatabase =
            instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    AgentDatabase::class.java,
                    "fasoshield-agent.db",
                ).build().also { instance = it }
            }
    }
}
