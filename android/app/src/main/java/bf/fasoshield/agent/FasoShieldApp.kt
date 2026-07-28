package bf.fasoshield.agent

import android.app.Application
import bf.fasoshield.agent.work.Alerts
import bf.fasoshield.agent.work.ProtectionService
import bf.fasoshield.agent.work.ScanWorker

class FasoShieldApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Alerts.ensureChannel(this)
        ProtectionService.ensureChannel(this)
        ScanWorker.schedule(this)
        // Resident protection starts with the process, not with the screen:
        // the user should not have to open the app for it to be watching.
        ProtectionService.start(this)
    }
}
