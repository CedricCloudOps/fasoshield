package bf.fasoshield.agent.scan

/**
 * On-device behavioural heuristics. Kotlin counterpart of the server engine's
 * heuristics — same rule identifiers, same severities — with one agent-side
 * refinement the server cannot make: provenance gating. PackageManager tells
 * the agent whether an app is preinstalled or came from an official store;
 * such apps are exempt from the permission and hygiene heuristics, which only
 * indicate malice for sideloaded software. Blocklist and impersonation checks
 * always apply. This keeps the false-positive rate low on real devices, where
 * legitimate apps routinely hold powerful permissions.
 *
 * The heuristics operate purely on facts already extracted by PackageManager;
 * they run offline and are the agent's first line of defence when the device
 * has no connectivity.
 */
object Heuristics {

    private const val P = "android.permission."

    /** Distinctive financial brand tokens used in impersonation campaigns. */
    private val BRAND_TOKENS = listOf(
        "orange money", "orangemoney",
        "moov money", "moovmoney",
        "wave money", "wave senegal",
        "coris money", "corismoney",
        "sank money", "sankmoney",
        "mobicash", "telecel money",
    )

    /** Trusted install sources: official app stores and OEM system-app updaters.
     *  An app installed from one of these — or preinstalled — has trusted
     *  provenance and is exempt from the permission and hygiene heuristics below,
     *  which only indicate malice for sideloaded software. Mobile money fraud is
     *  distributed by sideloading, not through these channels. An installer name
     *  cannot be spoofed by the installed app, so it is a sound trust anchor. */
    private val OFFICIAL_STORES = setOf(
        "com.android.vending",                  // Google Play
        "com.google.android.feedback",          // legacy Play
        "com.sec.android.app.samsungapps",      // Samsung Galaxy Store
        // OEM updaters for preinstalled apps. Samsung's Update Center moves
        // updated system apps into /data/app and strips their system flags, so
        // the installer is the only remaining provenance signal for them.
        "com.samsung.android.app.updatecenter", // Samsung Update Center
        "com.amazon.venezia",                   // Amazon Appstore
        "com.huawei.appmarket",                 // Huawei AppGallery
        "com.xiaomi.mipicks",                   // Xiaomi GetApps
    )

    private const val PACKAGE_SIMILARITY_THRESHOLD = 0.88

    /**
     * @param facts        the app under scrutiny
     * @param officialApps package_name -> (label, certSha256?) from the local
     *                     signature database (allowlist of official apps)
     */
    fun run(facts: AppFacts, officialApps: Map<String, OfficialApp>): List<Finding> {
        val official = officialApps[facts.packageName]
        if (official != null && official.certSha256 != null &&
            official.certSha256 == facts.certSha256
        ) {
            // Genuine official app: certificate matches the allowlist.
            return listOf(
                Finding(
                    ruleId = "heur.official_app",
                    title = "Application officielle",
                    severity = Severity.INFO,
                    description = "Le certificat de signature correspond à " +
                        "l'entrée officielle de ${official.label}.",
                )
            )
        }

        return buildList {
            // Impersonation and the (upstream) blocklist check always apply: a
            // repackaged clone or a known-bad certificate is malicious whatever
            // its source.
            addAll(impersonation(facts, officialApps, official))
            // Permission profile, install source and manifest hygiene are only
            // meaningful for untrusted provenance. A messaging app from the Play
            // Store legitimately reads SMS (OTP autofill) and records audio;
            // flagging it would drown real detections in false positives.
            if (!trustedProvenance(facts)) {
                addAll(permissionCombos(facts))
                addAll(installSource(facts))
                addAll(manifestHygiene(facts))
            }
        }
    }

    /** Preinstalled, or installed from an official store. */
    private fun trustedProvenance(facts: AppFacts): Boolean =
        facts.isSystemApp || facts.installerPackage in OFFICIAL_STORES

    private fun impersonation(
        facts: AppFacts,
        officialApps: Map<String, OfficialApp>,
        official: OfficialApp?,
    ): List<Finding> = buildList {
        if (official != null && official.certSha256 != null && facts.certSha256 != null) {
            // Same package name as an official app, signed by another key:
            // repackaged / trojanised clone.
            add(
                Finding(
                    ruleId = "heur.cert_mismatch",
                    title = "Application officielle signée par un certificat inconnu",
                    severity = Severity.CRITICAL,
                    description = "Le paquet ${facts.packageName} se présente comme " +
                        "${official.label} mais son certificat ne correspond pas " +
                        "au certificat officiel enregistré.",
                    evidence = "cert_sha256=${facts.certSha256}",
                )
            )
            return@buildList
        }

        if (official == null) {
            officialApps.values.firstOrNull { entry ->
                similarity(facts.packageName, entry.packageName) >= PACKAGE_SIMILARITY_THRESHOLD
            }?.let { entry ->
                add(
                    Finding(
                        ruleId = "heur.package_lookalike",
                        title = "Nom de paquet imitant une application officielle",
                        severity = Severity.HIGH,
                        description = "Le paquet ${facts.packageName} ressemble à " +
                            "${entry.packageName} (${entry.label}).",
                        evidence = facts.packageName,
                    )
                )
            }

            val label = facts.label.lowercase()
            BRAND_TOKENS.firstOrNull { it in label }?.let { token ->
                add(
                    Finding(
                        ruleId = "heur.brand_in_label",
                        title = "Marque financière utilisée par un paquet non officiel",
                        severity = Severity.HIGH,
                        description = "Le libellé \"${facts.label}\" utilise la marque " +
                            "\"$token\" alors que le paquet n'est pas au registre officiel.",
                        evidence = facts.label,
                    )
                )
            }
        }
    }

    private fun permissionCombos(facts: AppFacts): List<Finding> = buildList {
        val perms = facts.permissions.toSet()
        fun has(name: String) = "$P$name" in perms

        if ((has("RECEIVE_SMS") || has("READ_SMS")) && has("INTERNET")) {
            add(
                Finding(
                    "heur.sms_exfiltration",
                    "Interception de SMS avec accès réseau",
                    Severity.HIGH,
                    "L'application peut lire les SMS entrants (codes OTP mobile money) " +
                        "et les relayer sur le réseau.",
                    "RECEIVE_SMS/READ_SMS + INTERNET",
                )
            )
        }
        if (has("SEND_SMS")) {
            add(
                Finding(
                    "heur.send_sms",
                    "Envoi de SMS autonome",
                    Severity.MEDIUM,
                    "SEND_SMS permet la fraude aux numéros surtaxés et les transferts " +
                        "mobile money par USSD sans interaction.",
                    "SEND_SMS",
                )
            )
        }
        if (has("SYSTEM_ALERT_WINDOW")) {
            add(
                Finding(
                    "heur.overlay",
                    "Superposition d'écran",
                    Severity.MEDIUM,
                    "Les fenêtres en superposition sont la technique principale des " +
                        "trojans bancaires pour afficher de faux écrans de saisie de PIN.",
                    "SYSTEM_ALERT_WINDOW",
                )
            )
        }
        if (has("RECORD_AUDIO") && has("INTERNET") &&
            (has("ACCESS_FINE_LOCATION") || has("READ_CONTACTS"))
        ) {
            add(
                Finding(
                    "heur.spyware_combo",
                    "Profil de permissions de type spyware",
                    Severity.HIGH,
                    "Capture micro combinée à la localisation ou aux contacts et à une " +
                        "capacité d'exfiltration réseau.",
                    "RECORD_AUDIO + INTERNET + LOCATION/CONTACTS",
                )
            )
        }
        if (has("REQUEST_INSTALL_PACKAGES")) {
            add(
                Finding(
                    "heur.dropper",
                    "Peut installer d'autres paquets",
                    Severity.MEDIUM,
                    "REQUEST_INSTALL_PACKAGES est caractéristique des droppers qui " +
                        "téléchargent une charge secondaire après installation.",
                    "REQUEST_INSTALL_PACKAGES",
                )
            )
        }
    }

    private fun installSource(facts: AppFacts): List<Finding> = buildList {
        // Only reached for untrusted provenance (trustedProvenance already
        // excluded system apps and official stores), so the source is either a
        // manual/ADB sideload (null) or an unofficial store.
        val installer = facts.installerPackage
        if (installer == null || installer !in OFFICIAL_STORES) {
            add(
                Finding(
                    ruleId = "heur.sideloaded",
                    title = "Installée hors store officiel",
                    severity = Severity.LOW,
                    description = "Source d'installation : " +
                        (installer ?: "inconnue (chargement manuel)") +
                        ". Les campagnes de fraude mobile money se diffusent " +
                        "majoritairement hors du Play Store.",
                    evidence = installer,
                )
            )
        }
    }

    private fun manifestHygiene(facts: AppFacts): List<Finding> = buildList {
        if (facts.debuggable) {
            add(
                Finding(
                    "heur.debuggable",
                    "Application débogable",
                    Severity.LOW,
                    "android:debuggable=true dans une application distribuée indique " +
                        "une version de développement ou un repackaging.",
                )
            )
        }
        if (facts.targetSdk in 1..22) {
            add(
                Finding(
                    "heur.legacy_target_sdk",
                    "Cible un SDK antérieur aux permissions à l'exécution",
                    Severity.MEDIUM,
                    "targetSdkVersion=${facts.targetSdk} (< 23) accorde toutes les " +
                        "permissions à l'installation, évasion fréquente des malwares.",
                )
            )
        }
    }

    /**
     * Normalised similarity between two package names, based on the length of
     * the longest common subsequence. Lightweight stand-in for the server's
     * SequenceMatcher ratio, sufficient for lookalike detection.
     */
    internal fun similarity(a: String, b: String): Double {
        if (a == b) return 1.0
        if (a.isEmpty() || b.isEmpty()) return 0.0
        val lcs = longestCommonSubsequence(a, b)
        return 2.0 * lcs / (a.length + b.length)
    }

    private fun longestCommonSubsequence(a: String, b: String): Int {
        val dp = IntArray(b.length + 1)
        for (i in 1..a.length) {
            var prev = 0
            for (j in 1..b.length) {
                val temp = dp[j]
                dp[j] = if (a[i - 1] == b[j - 1]) prev + 1 else maxOf(dp[j], dp[j - 1])
                prev = temp
            }
        }
        return dp[b.length]
    }
}

/** Allowlist entry for an official financial application. */
data class OfficialApp(
    val packageName: String,
    val label: String,
    val certSha256: String?,
)
