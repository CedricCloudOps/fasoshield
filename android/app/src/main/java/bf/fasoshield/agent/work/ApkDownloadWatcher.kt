package bf.fasoshield.agent.work

import android.Manifest
import android.content.ContentResolver
import android.content.Context
import android.content.pm.PackageManager
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import androidx.core.content.ContextCompat
import bf.fasoshield.agent.ServiceLocator
import bf.fasoshield.agent.scan.DownloadTriage
import bf.fasoshield.agent.util.Prefs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Watches the download folder and inspects every APK that lands in it, before
 * anything is installed.
 *
 * MediaStore rather than a FileObserver on the directory: browsers and the
 * system download manager register what they fetch with MediaStore, so a
 * content observer catches exactly the path the fraud takes — a link tapped in
 * a message, a download, a file waiting to be opened. A raw directory watch
 * would also miss anything written outside the public folder and would have to
 * re-implement the filtering MediaStore already does.
 *
 * Everything is best-effort by design. Reading other applications' downloads
 * requires all-files access on modern Android, which the user may not have
 * granted; when it is missing the watcher simply stays idle rather than
 * failing, and the install-time scan remains the backstop.
 */
class ApkDownloadWatcher(
    private val context: Context,
    private val scope: CoroutineScope,
) {

    private val resolver: ContentResolver = context.contentResolver
    private val prefs = Prefs(context)

    private val observer = object : ContentObserver(Handler(Looper.getMainLooper())) {
        override fun onChange(selfChange: Boolean, uri: Uri?) {
            scope.launch(Dispatchers.IO) { inspectNewDownloads() }
        }
    }

    fun start() {
        if (!hasFileAccess(context)) return
        resolver.registerContentObserver(collection(), true, observer)
        // A download may have completed while the service was not running.
        scope.launch(Dispatchers.IO) { inspectNewDownloads() }
    }

    fun stop() {
        runCatching { resolver.unregisterContentObserver(observer) }
    }

    /**
     * Hash and assess every APK indexed since the last pass.
     *
     * The watermark is a timestamp rather than a set of identifiers: MediaStore
     * rows are renumbered and removed freely, and a file re-downloaded under
     * the same name must be looked at again. It advances only over rows that
     * were actually processed, so a crash mid-pass re-examines rather than
     * skips.
     */
    private suspend fun inspectNewDownloads() {
        val since = prefs.lastDownloadScanSeconds
        val projection = arrayOf(
            MediaStore.MediaColumns._ID,
            MediaStore.MediaColumns.DISPLAY_NAME,
            MediaStore.MediaColumns.MIME_TYPE,
            MediaStore.MediaColumns.DATE_ADDED,
        )
        var newest = since

        val cursor = runCatching {
            resolver.query(
                collection(),
                projection,
                "${MediaStore.MediaColumns.DATE_ADDED} > ?",
                arrayOf(since.toString()),
                "${MediaStore.MediaColumns.DATE_ADDED} ASC",
            )
        }.getOrNull() ?: return

        cursor.use {
            val idCol = it.getColumnIndexOrThrow(MediaStore.MediaColumns._ID)
            val nameCol = it.getColumnIndexOrThrow(MediaStore.MediaColumns.DISPLAY_NAME)
            val mimeCol = it.getColumnIndexOrThrow(MediaStore.MediaColumns.MIME_TYPE)
            val dateCol = it.getColumnIndexOrThrow(MediaStore.MediaColumns.DATE_ADDED)

            while (it.moveToNext()) {
                val addedAt = it.getLong(dateCol)
                if (addedAt > newest) newest = addedAt

                val name = it.getString(nameCol)
                val mime = it.getString(mimeCol)
                if (!DownloadTriage.isApkCandidate(name, mime)) continue

                val uri = MediaStore.Downloads.getContentUri(
                    MediaStore.VOLUME_EXTERNAL, it.getLong(idCol),
                )
                inspect(uri, name ?: "APK")
            }
        }

        if (newest > since) prefs.lastDownloadScanSeconds = newest
    }

    private suspend fun inspect(uri: Uri, displayName: String) {
        val repo = ServiceLocator.repository(context)
        val assessment = repo.assessDownloadedApk(uri, displayName) ?: return
        if (DownloadTriage.shouldWarn(assessment)) {
            Alerts.postDownloadWarning(context, displayName, assessment)
        }
    }

    private fun collection(): Uri =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL)
        } else {
            @Suppress("DEPRECATION")
            MediaStore.Files.getContentUri("external")
        }

    companion object {
        /**
         * Whether the agent can read files other applications downloaded.
         *
         * From Android 11 this means all-files access, which the user grants
         * from a dedicated settings screen. Google lists antivirus software
         * among the permitted uses, but it is never granted at install time —
         * the agent has to ask, and must work without it.
         */
        fun hasFileAccess(context: Context): Boolean =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Environment.isExternalStorageManager()
            } else {
                ContextCompat.checkSelfPermission(
                    context, Manifest.permission.READ_EXTERNAL_STORAGE,
                ) == PackageManager.PERMISSION_GRANTED
            }
    }
}
