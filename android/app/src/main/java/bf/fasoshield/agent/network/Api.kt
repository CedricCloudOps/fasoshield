package bf.fasoshield.agent.network

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit contract mirroring the FasoShield platform API. Only the
 * agent-facing endpoints are declared; APK upload (POST /v1/scan) is not used
 * on the hot path and is omitted from the mobile client.
 */
interface FasoShieldApi {

    @GET("v1/reputation/{sha256}")
    suspend fun reputation(@Path("sha256") sha256: String): ReputationResponse

    @GET("v1/signatures/version")
    suspend fun signatureVersion(): SignatureVersionResponse

    @GET("v1/signatures/updates")
    suspend fun signatureUpdates(@Query("since") since: String): SignatureUpdateResponse

    @POST("v1/telemetry")
    suspend fun telemetry(@Body event: TelemetryRequest): TelemetryAck
}

@JsonClass(generateAdapter = true)
data class ReputationResponse(
    val sha256: String,
    val known: Boolean,
    val verdict: String?,
    @Json(name = "threat_name") val threatName: String?,
    val source: String?,
    @Json(name = "signature_db_version") val signatureDbVersion: String,
)

@JsonClass(generateAdapter = true)
data class SignatureVersionResponse(
    val version: String,
    @Json(name = "blocklist_entries") val blocklistEntries: Int,
    @Json(name = "official_apps") val officialApps: Int,
)

@JsonClass(generateAdapter = true)
data class SignatureUpdateResponse(
    val since: String,
    val version: String,
    val entries: List<SignatureEntry>,
)

@JsonClass(generateAdapter = true)
data class SignatureEntry(
    val sha256: String,
    @Json(name = "threat_name") val threatName: String,
    val source: String,
    @Json(name = "added_at") val addedAt: String,
)

@JsonClass(generateAdapter = true)
data class TelemetryRequest(
    @Json(name = "agent_id") val agentId: String,
    @Json(name = "event_type") val eventType: String,
    val sha256: String? = null,
    @Json(name = "package_name") val packageName: String? = null,
    val verdict: String? = null,
    @Json(name = "threat_name") val threatName: String? = null,
    val region: String? = null,
)

@JsonClass(generateAdapter = true)
data class TelemetryAck(
    val accepted: Boolean,
    @Json(name = "received_at") val receivedAt: String,
)
