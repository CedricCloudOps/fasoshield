package bf.fasoshield.agent.network

import bf.fasoshield.agent.BuildConfig
import com.squareup.moshi.Moshi
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/** Builds a configured FasoShieldApi with the agent API key attached. */
object ApiClient {

    fun create(apiKey: String): FasoShieldApi {
        val logging = HttpLoggingInterceptor().apply {
            level = if (BuildConfig.DEBUG) {
                HttpLoggingInterceptor.Level.BASIC
            } else {
                HttpLoggingInterceptor.Level.NONE
            }
        }

        val http = OkHttpClient.Builder()
            .addInterceptor { chain ->
                val request = chain.request().newBuilder()
                    .header("X-API-Key", apiKey)
                    .header("User-Agent", "FasoShield-Agent/${BuildConfig.VERSION_NAME}")
                    .build()
                chain.proceed(request)
            }
            .addInterceptor(logging)
            .build()

        // Adapters are generated at build time by the Moshi KSP codegen
        // (each DTO is annotated @JsonClass(generateAdapter = true)).
        val moshi = Moshi.Builder().build()

        return Retrofit.Builder()
            .baseUrl(BuildConfig.API_BASE_URL)
            .client(http)
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .build()
            .create(FasoShieldApi::class.java)
    }
}
