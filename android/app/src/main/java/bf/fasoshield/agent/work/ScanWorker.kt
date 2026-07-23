package bf.fasoshield.agent.work

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import bf.fasoshield.agent.ServiceLocator
import bf.fasoshield.agent.data.AgentRepository
import java.util.concurrent.TimeUnit

/**
 * Periodic maintenance: sync signatures, run a full scan, alert on malicious
 * results and flush telemetry. Scheduled by WorkManager, survives reboot.
 */
class ScanWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val repo = ServiceLocator.repository(applicationContext)
        return try {
            // Best-effort sync; a network failure must not abort the local scan.
            runCatching { repo.syncSignatures() }

            val results = repo.scanAndPersist()
            results.filter { AgentRepository.shouldAlert(it) }
                .forEach { Alerts.postDetection(applicationContext, it) }

            runCatching { repo.flushTelemetry() }
            Result.success()
        } catch (t: Throwable) {
            if (runAttemptCount < MAX_ATTEMPTS) Result.retry() else Result.failure()
        }
    }

    companion object {
        private const val UNIQUE_NAME = "fasoshield_periodic_scan"
        private const val MAX_ATTEMPTS = 3

        /** Schedule the daily scan; safe to call repeatedly (KEEP policy). */
        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()
            val request = PeriodicWorkRequestBuilder<ScanWorker>(24, TimeUnit.HOURS)
                .setConstraints(constraints)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request,
            )
        }
    }
}
