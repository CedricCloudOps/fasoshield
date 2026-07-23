package bf.fasoshield.agent.scan

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import bf.fasoshield.agent.data.SignatureStore
import java.security.MessageDigest

/**
 * Reads installed packages through PackageManager, extracts static facts and
 * runs the on-device layers: local blocklist (by certificate/APK hash) and
 * behavioural heuristics. No APK is uploaded here — this is the offline path.
 */
class AppScanner(
    private val context: Context,
    private val store: SignatureStore,
) {

    private val pm: PackageManager = context.packageManager

    private companion object {
        // Read-only partitions that hold preinstalled applications.
        val SYSTEM_PARTITIONS = listOf(
            "/system/", "/system_ext/", "/product/", "/vendor/", "/odm/", "/oem/", "/apex/",
        )
    }

    /** Scan every user-installed application (system apps are skipped). */
    suspend fun scanInstalledApps(includeSystem: Boolean = false): List<ScanResult> {
        val official = store.officialApps()
        // List.filter / List.map are inline, so the suspend lookup inside
        // scanPackage stays legal here — unlike a lazy Sequence, which cannot
        // carry a suspend call in its transform.
        return installedPackages()
            .filter { includeSystem || !it.isSystemApp() }
            .map { scanPackage(it, official) }
    }

    /** Scan a single package by name; null if it is not installed. */
    suspend fun scanPackage(packageName: String): ScanResult? {
        val info = runCatching { packageInfo(packageName) }.getOrNull() ?: return null
        return scanPackage(info, store.officialApps())
    }

    private suspend fun scanPackage(
        info: PackageInfo,
        official: Map<String, OfficialApp>,
    ): ScanResult {
        val facts = extractFacts(info)
        val findings = buildList {
            // Layer 1: local blocklist lookup by certificate SHA-256. The
            // agent avoids hashing full APKs on-device (I/O cost); certificate
            // reuse across a malware family is the practical local signal.
            facts.certSha256?.let { cert ->
                store.blocklistByCert(cert)?.let { threat ->
                    add(
                        Finding(
                            ruleId = "sig.cert_blocklist",
                            title = "Certificat de signature connu comme malveillant",
                            severity = Severity.CRITICAL,
                            description = "Le certificat correspond à $threat dans la " +
                                "base de signatures nationale.",
                            evidence = cert,
                        )
                    )
                }
            }
            // Layers 2+: behavioural heuristics.
            addAll(Heuristics.run(facts, official))
        }

        val (verdict, score) = Scoring.verdictOf(findings)
        val threatName = when {
            findings.any { it.ruleId == "sig.cert_blocklist" } ->
                findings.first { it.ruleId == "sig.cert_blocklist" }.title
            verdict == Verdict.MALICIOUS ->
                findings.maxByOrNull { it.severity.weight }?.ruleId
            else -> null
        }
        return ScanResult(facts, verdict, score, threatName, findings)
    }

    private fun extractFacts(info: PackageInfo): AppFacts {
        val app = info.applicationInfo
        val label = app?.let { pm.getApplicationLabel(it).toString() } ?: info.packageName
        return AppFacts(
            packageName = info.packageName,
            label = label,
            versionName = info.versionName,
            targetSdk = app?.targetSdkVersion ?: 0,
            debuggable = app != null &&
                (app.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
            permissions = info.requestedPermissions?.toList() ?: emptyList(),
            certSha256 = signingCertSha256(info),
            installerPackage = installerOf(info.packageName),
            apkSha256 = null, // computed lazily only when uploading to /v1/scan
            isSystemApp = systemOrigin(info),
        )
    }

    /** True for preinstalled apps: the system flags, or — belt-and-braces —
     *  code residing on a read-only system partition. Some OEM builds
     *  under-report FLAG_SYSTEM for their bundled applications. */
    private fun systemOrigin(info: PackageInfo): Boolean {
        if (info.isSystemApp()) return true
        val dir = info.applicationInfo?.sourceDir ?: return false
        return SYSTEM_PARTITIONS.any { dir.startsWith(it) }
    }

    private fun installedPackages(): List<PackageInfo> {
        val flags = PackageManager.GET_PERMISSIONS or signingFlag()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(flags)
        }
    }

    private fun packageInfo(packageName: String): PackageInfo {
        val flags = PackageManager.GET_PERMISSIONS or signingFlag()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, flags)
        }
    }

    private fun signingFlag(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }

    /** SHA-256 of the app's signing certificate, hex-encoded. */
    private fun signingCertSha256(info: PackageInfo): String? {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.signingInfo?.let { si ->
                if (si.hasMultipleSigners()) si.apkContentsSigners
                else si.signingCertificateHistory
            }
        } else {
            @Suppress("DEPRECATION")
            info.signatures
        }
        val cert = signatures?.firstOrNull()?.toByteArray() ?: return null
        return MessageDigest.getInstance("SHA-256").digest(cert)
            .joinToString("") { "%02x".format(it) }
    }

    private fun installerOf(packageName: String): String? =
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        }.getOrNull()

    private fun PackageInfo.isSystemApp(): Boolean {
        val flags = applicationInfo?.flags ?: 0
        return (flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
            (flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
    }
}
