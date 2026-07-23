// FasoShield national rule set
// Target: French-language smishing kits impersonating mobile money services.

rule Android_Smishing_MobileMoney_FR
{
    meta:
        description = "French mobile-money phishing lures embedded in application code"
        severity = "HIGH"
        author = "FasoShield ruleset"

    strings:
        $lure1 = "votre compte a" nocase          // "votre compte a ete suspendu/bloque"
        $lure2 = "code de validation" nocase
        $lure3 = "confirmez votre code secret" nocase
        $lure4 = "retrait en attente" nocase
        $lure5 = "votre solde sera" nocase
        $brand1 = "Orange Money" nocase
        $brand2 = "Moov Money" nocase
        $brand3 = "Wave" fullword
        $short1 = "bit.ly/" nocase
        $short2 = "tinyurl.com/" nocase
        $short3 = "cutt.ly/" nocase

    condition:
        (2 of ($lure*) and 1 of ($brand*))
        or (1 of ($lure*) and 1 of ($brand*) and 1 of ($short*))
}
