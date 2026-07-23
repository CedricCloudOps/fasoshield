package bf.fasoshield.agent.data

import bf.fasoshield.agent.scan.OfficialApp
import bf.fasoshield.agent.util.Prefs

/**
 * Facade over the local signature database used by the scanner. Also tracks
 * the signature DB version for delta synchronisation.
 */
class SignatureStore(
    private val blocklistDao: BlocklistDao,
    private val officialAppDao: OfficialAppDao,
    private val prefs: Prefs,
) {

    suspend fun blocklistByCert(certSha256: String): String? =
        blocklistDao.byCert(certSha256)?.threatName

    suspend fun blocklistByHash(sha256: String): String? =
        blocklistDao.byHash(sha256)?.threatName

    suspend fun officialApps(): Map<String, OfficialApp> =
        officialAppDao.all().associate { entry ->
            entry.packageName to OfficialApp(entry.packageName, entry.label, entry.certSha256)
        }

    suspend fun applyBlocklistDelta(entries: List<BlocklistEntry>) {
        if (entries.isNotEmpty()) blocklistDao.upsertAll(entries)
    }

    suspend fun replaceOfficialApps(entries: List<OfficialAppEntry>) {
        if (entries.isNotEmpty()) officialAppDao.upsertAll(entries)
    }

    suspend fun blocklistCount(): Int = blocklistDao.count()

    /** Local signature DB version ("0" until the first successful sync). */
    var localVersion: String
        get() = prefs.signatureVersion
        set(value) {
            prefs.signatureVersion = value
        }
}
