package bf.fasoshield.agent.work

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Restores protection after the device reboots: the periodic scan is
 * rescheduled, and the resident service restarted so the download watcher is
 * listening again before the user opens anything.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            ScanWorker.schedule(context)
            ProtectionService.start(context)
        }
    }
}
