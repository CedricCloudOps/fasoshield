package bf.fasoshield.agent.work

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import bf.fasoshield.agent.R
import bf.fasoshield.agent.scan.DownloadAssessment
import bf.fasoshield.agent.scan.ScanResult

/** Builds and posts detection notifications, and opens the uninstall screen. */
object Alerts {

    private const val CHANNEL_ID = "fasoshield_detections"

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.channel_detections),
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = context.getString(R.string.channel_detections_desc)
        }
        context.getSystemService(NotificationManager::class.java)
            .createNotificationChannel(channel)
    }

    fun postDetection(context: Context, result: ScanResult) {
        if (!canPost(context)) return
        ensureChannel(context)

        val uninstall = Intent(Intent.ACTION_DELETE).apply {
            data = Uri.parse("package:${result.facts.packageName}")
        }
        val pending = PendingIntent.getActivity(
            context,
            result.facts.packageName.hashCode(),
            uninstall,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val reason = result.findings.firstOrNull()?.title ?: result.threatName.orEmpty()
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(
                context.getString(R.string.alert_title, result.facts.label)
            )
            .setContentText(context.getString(R.string.alert_text, reason))
            .setStyle(
                NotificationCompat.BigTextStyle().bigText(
                    context.getString(
                        R.string.alert_big,
                        result.verdict.name,
                        result.score,
                        reason,
                    )
                )
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ERROR)
            .setAutoCancel(true)
            .addAction(0, context.getString(R.string.action_uninstall), pending)
            .build()

        NotificationManagerCompat.from(context)
            .notify(result.facts.packageName.hashCode(), notification)
    }

    /**
     * Warn about an APK that has just been downloaded and is known bad, before
     * the user opens it.
     *
     * No uninstall action here — there is nothing installed yet, and that is
     * the point. The notification names the file so the user can recognise
     * what they were about to open, and tells them plainly not to. Deleting it
     * on their behalf is deliberately not offered: the agent does not remove
     * the user's files, and a deletion they did not ask for would undermine
     * exactly the trust this warning depends on.
     */
    fun postDownloadWarning(context: Context, fileName: String, assessment: DownloadAssessment) {
        if (!canPost(context)) return
        ensureChannel(context)

        val reason = assessment.threatName ?: context.getString(R.string.download_reason_generic)
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(context.getString(R.string.download_alert_title))
            .setContentText(context.getString(R.string.download_alert_text, fileName))
            .setStyle(
                NotificationCompat.BigTextStyle().bigText(
                    context.getString(R.string.download_alert_big, fileName, reason)
                )
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ERROR)
            .setAutoCancel(true)
            .build()

        NotificationManagerCompat.from(context).notify(fileName.hashCode(), notification)
    }

    private fun canPost(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(
                context, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
}
