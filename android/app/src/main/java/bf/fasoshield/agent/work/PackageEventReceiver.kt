package bf.fasoshield.agent.work

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.work.CoroutineWorker
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkerParameters
import androidx.work.WorkManager
import androidx.work.workDataOf
import bf.fasoshield.agent.ServiceLocator
import bf.fasoshield.agent.data.AgentRepository

/**
 * Fires on PACKAGE_ADDED / PACKAGE_REPLACED. Broadcast receivers must return
 * quickly, so the scan of the new package is delegated to a one-shot worker.
 * Replacements are scanned too — trojanised updates are a real vector.
 */
class PackageEventReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart ?: return
        if (packageName == context.packageName) return

        val request = OneTimeWorkRequestBuilder<NewPackageWorker>()
            .setInputData(workDataOf(NewPackageWorker.KEY_PACKAGE to packageName))
            .build()
        WorkManager.getInstance(context).enqueue(request)
    }
}

/** Scans a single newly installed package and alerts if malicious. */
class NewPackageWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val packageName = inputData.getString(KEY_PACKAGE) ?: return Result.failure()
        val repo = ServiceLocator.repository(applicationContext)
        val result = repo.scanNewPackage(packageName) ?: return Result.success()
        if (AgentRepository.shouldAlert(result)) {
            Alerts.postDetection(applicationContext, result)
        }
        runCatching { repo.flushTelemetry() }
        return Result.success()
    }

    companion object {
        const val KEY_PACKAGE = "package_name"
    }
}
