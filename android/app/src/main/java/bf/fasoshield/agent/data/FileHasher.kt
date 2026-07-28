package bf.fasoshield.agent.data

import android.content.Context
import android.net.Uri
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * SHA-256 of a file addressed by content URI, streamed rather than loaded.
 *
 * Split out of the repository so the download path has no direct dependency on
 * a ContentResolver, and so it can be substituted in a test.
 */
fun interface FileHasher {
    suspend fun sha256(uri: Uri): String?
}

class ContentUriHasher(private val context: Context) : FileHasher {

    override suspend fun sha256(uri: Uri): String? = withContext(Dispatchers.IO) {
        runCatching {
            val digest = MessageDigest.getInstance("SHA-256")
            context.contentResolver.openInputStream(uri)?.use { input ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    digest.update(buffer, 0, read)
                }
            } ?: return@runCatching null
            digest.digest().joinToString("") { "%02x".format(it) }
        }.getOrNull()
    }
}
