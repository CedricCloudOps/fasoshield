// FasoShield national rule set
// Target: banking/mobile-money trojans using screen overlays and
// accessibility service abuse to capture PIN codes.

rule Android_Overlay_PIN_Capture
{
    meta:
        description = "Overlay window techniques combined with accessibility abuse (fake PIN screen pattern)"
        severity = "HIGH"
        author = "FasoShield ruleset"

    strings:
        $dex_magic = { 64 65 78 0A 30 33 }
        $overlay1 = "TYPE_APPLICATION_OVERLAY"
        $overlay2 = "TYPE_SYSTEM_ALERT"
        $a11y1 = "AccessibilityService"
        $a11y2 = "performGlobalAction"
        $a11y3 = "getRootInActiveWindow"
        $wm = "WindowManager"

    condition:
        $dex_magic at 0
        and 1 of ($overlay*)
        and $wm
        and 2 of ($a11y*)
}
