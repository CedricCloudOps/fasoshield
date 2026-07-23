// FasoShield national rule set
// Target: droppers that fetch and install a second-stage payload, the main
// distribution channel for malware outside official app stores.

rule Android_Dropper_DynamicLoad
{
    meta:
        description = "Dynamic code loading combined with APK install intent (second-stage dropper)"
        severity = "HIGH"
        author = "FasoShield ruleset"

    strings:
        $dex_magic = { 64 65 78 0A 30 33 }
        $load1 = "dalvik.system.DexClassLoader"
        $load2 = "dalvik.system.InMemoryDexClassLoader"
        $load3 = "dalvik.system.PathClassLoader"
        $mime = "application/vnd.android.package-archive"
        $install = "android.intent.action.INSTALL_PACKAGE"

    condition:
        $dex_magic at 0
        and 1 of ($load*)
        and ($mime or $install)
}
