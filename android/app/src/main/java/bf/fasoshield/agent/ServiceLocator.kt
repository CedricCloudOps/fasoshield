package bf.fasoshield.agent

import android.content.Context
import bf.fasoshield.agent.data.AgentDatabase
import bf.fasoshield.agent.data.AgentRepository
import bf.fasoshield.agent.data.SignatureStore
import bf.fasoshield.agent.network.ApiClient
import bf.fasoshield.agent.scan.AppScanner
import bf.fasoshield.agent.util.Prefs

/**
 * Minimal manual dependency container. Kept deliberately simple (no DI
 * framework) so the wiring is obvious for a reviewer.
 *
 * The agent API key ships as a build secret in a real deployment (e.g. via a
 * provisioning step); here it is read from BuildConfig / a placeholder.
 */
object ServiceLocator {

    @Volatile
    private var repo: AgentRepository? = null

    fun repository(context: Context): AgentRepository =
        repo ?: synchronized(this) {
            repo ?: build(context.applicationContext).also { repo = it }
        }

    private fun build(context: Context): AgentRepository {
        val db = AgentDatabase.get(context)
        val prefs = Prefs(context)
        val store = SignatureStore(db.blocklistDao(), db.officialAppDao(), prefs)
        val scanner = AppScanner(context, store)
        val api = ApiClient.create(apiKey = provisionedApiKey())
        return AgentRepository(api, store, scanner, db.detectionDao(), prefs)
    }

    // Placeholder: replaced by a provisioned per-agent key at enrolment.
    private fun provisionedApiKey(): String = ""
}
