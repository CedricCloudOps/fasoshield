// FasoShield national rule set
// Target: OTP/SMS interception malware aimed at mobile money accounts.

rule Android_SMS_Stealer_Generic
{
    meta:
        description = "DEX code registers for incoming SMS, reads message bodies and exfiltrates over HTTP"
        severity = "HIGH"
        author = "FasoShield ruleset"
        reference = "OTP theft pattern against mobile money accounts"

    strings:
        $dex_magic = { 64 65 78 0A 30 33 }                     // "dex\n03x"
        $sms_recv = "android.provider.Telephony.SMS_RECEIVED"
        $get_body = "getMessageBody"
        $get_origin = "getOriginatingAddress"
        $abort = "abortBroadcast"
        $http1 = "http://" nocase
        $http2 = "https://" nocase

    condition:
        $dex_magic at 0
        and $sms_recv
        and ($get_body or $get_origin)
        and ($abort or 1 of ($http*))
}

rule Android_SMS_Silent_Sender
{
    meta:
        description = "DEX code sends SMS programmatically without user interface strings"
        severity = "MEDIUM"
        author = "FasoShield ruleset"

    strings:
        $dex_magic = { 64 65 78 0A 30 33 }
        $mgr = "SmsManager"
        $send1 = "sendTextMessage"
        $send2 = "sendMultipartTextMessage"
        $ussd = "sendUssdRequest"

    condition:
        $dex_magic at 0 and $mgr and 1 of ($send*, $ussd)
}
