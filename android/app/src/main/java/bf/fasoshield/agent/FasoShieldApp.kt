package bf.fasoshield.agent

import android.app.Application
import bf.fasoshield.agent.work.Alerts
import bf.fasoshield.agent.work.ScanWorker

class FasoShieldApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Alerts.ensureChannel(this)
        ScanWorker.schedule(this)
    }
}
