// Standard EICAR test signature. Lets integrators verify the full detection
// pipeline (agent -> API -> verdict) without handling real malware, exactly
// like every commercial antivirus product.

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test string (harmless, for end-to-end testing)"
        severity = "CRITICAL"
        author = "FasoShield ruleset"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
