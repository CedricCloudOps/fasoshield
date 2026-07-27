import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
}

/**
 * Release signing material, resolved from a keystore.properties file that is
 * never committed (see .gitignore), or from environment variables in CI.
 *
 * The production key belongs to the national authority: it is held in an HSM
 * or a sealed offline store, and the build only ever receives a path to it.
 * When nothing is configured the release build stays unsigned rather than
 * silently falling back to the debug key — an unsigned artefact is obvious,
 * a debug-signed one shipped to users would not be.
 */
val keystoreProperties = Properties().apply {
    val file = rootProject.file("keystore.properties")
    if (file.exists()) file.inputStream().use { load(it) }
}

fun signingValue(key: String, env: String): String? =
    keystoreProperties.getProperty(key) ?: System.getenv(env)

val releaseStoreFile = signingValue("storeFile", "FASOSHIELD_KEYSTORE")

/**
 * Platform endpoint used by the debug build. The default is the emulator's
 * alias for the host machine, which means nothing on a physical handset: there,
 * either forward the port over USB (`adb reverse tcp:8000 tcp:8000`, then use
 * 127.0.0.1) or point at the host's address on the local network.
 *
 *   ./gradlew :app:installDebug -PfasoshieldDebugApiUrl=http://127.0.0.1:8000/
 *   ./gradlew :app:installDebug -PfasoshieldDebugApiUrl=http://192.168.1.20:8000/
 *
 * The value can also live in the developer's own gradle.properties. It only
 * ever reaches the debug build type; release keeps the production URL.
 */
val debugApiBaseUrl = (findProperty("fasoshieldDebugApiUrl") as String?)
    ?.takeIf { it.isNotBlank() }
    ?: "http://10.0.2.2:8000/"

/**
 * Base64 SubjectPublicKeyInfo of the key that signs signature bundles, printed
 * by `fasoshield keys generate` on the platform. Built into the APK so the
 * agent can verify every delta it applies, whatever route the bytes took.
 *
 *   ./gradlew :app:assembleRelease -PfasoshieldSignatureKey=MFkwEwYHKoZIzj0CAQ...
 *
 * When it is absent the agent accepts unsigned bundles, which is only
 * acceptable against a local development platform — hence the warning below.
 */
val signaturePublicKey = (findProperty("fasoshieldSignatureKey") as String?)?.trim().orEmpty()
if (signaturePublicKey.isEmpty()) {
    logger.warn(
        "fasoshield: no -PfasoshieldSignatureKey — this build accepts unsigned " +
            "signature bundles and must not be distributed."
    )
}

android {
    namespace = "bf.fasoshield.agent"
    compileSdk = 35

    defaultConfig {
        applicationId = "bf.fasoshield.agent"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Base API URL. Overridden per build type; the emulator reaches the
        // host machine through 10.0.2.2.
        buildConfigField("String", "API_BASE_URL", "\"https://api.fasoshield.bf/\"")
        buildConfigField("String", "SIGNATURE_PUBLIC_KEY", "\"$signaturePublicKey\"")
    }

    signingConfigs {
        if (releaseStoreFile != null) {
            create("release") {
                storeFile = file(releaseStoreFile)
                storePassword = signingValue("storePassword", "FASOSHIELD_KEYSTORE_PASSWORD")
                keyAlias = signingValue("keyAlias", "FASOSHIELD_KEY_ALIAS")
                keyPassword = signingValue("keyPassword", "FASOSHIELD_KEY_PASSWORD")
                // v2/v3 give the whole-APK signature that Android verifies at
                // install time; v1 is kept for the minSdk 24 devices that are
                // still very common on the national handset fleet.
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        debug {
            buildConfigField("String", "API_BASE_URL", "\"$debugApiBaseUrl\"")
        }
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // Persistence
    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    ksp("androidx.room:room-compiler:2.6.1")

    // Background work
    implementation("androidx.work:work-runtime-ktx:2.9.1")

    // Networking
    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.retrofit2:converter-moshi:2.11.0")
    implementation("com.squareup.moshi:moshi:1.15.1")
    ksp("com.squareup.moshi:moshi-kotlin-codegen:1.15.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    // Unit tests (run on the JVM, no device required)
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    testImplementation("com.google.truth:truth:1.4.4")
}
