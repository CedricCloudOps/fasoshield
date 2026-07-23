package bf.fasoshield.agent.util

import android.content.Context
import java.util.UUID

/**
 * Lightweight preferences wrapper. Holds the opaque agent identifier and the
 * local signature DB version.
 *
 * Privacy: the agent id is a locally generated UUID with no link to any device
 * identifier (no IMEI, no MSISDN). It is the only identifier ever sent with
 * telemetry.
 */
class Prefs(context: Context) {

    private val sp = context.getSharedPreferences("fasoshield", Context.MODE_PRIVATE)

    /** Stable opaque agent id, generated once on first launch. */
    val agentId: String
        get() = sp.getString(KEY_AGENT_ID, null) ?: UUID.randomUUID().toString().also {
            sp.edit().putString(KEY_AGENT_ID, it).apply()
        }

    var signatureVersion: String
        get() = sp.getString(KEY_SIG_VERSION, "0") ?: "0"
        set(value) {
            sp.edit().putString(KEY_SIG_VERSION, value).apply()
        }

    /** Coarse, user-declared region for national campaign mapping (optional). */
    var region: String?
        get() = sp.getString(KEY_REGION, null)
        set(value) {
            sp.edit().putString(KEY_REGION, value).apply()
        }

    companion object {
        private const val KEY_AGENT_ID = "agent_id"
        private const val KEY_SIG_VERSION = "signature_version"
        private const val KEY_REGION = "region"
    }
}
