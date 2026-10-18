rule Heuristic_PowerShell_Download_Decode_Execute
{
    meta:
        description = "PowerShell contains download, decode, and execution indicators; this is heuristic, not a malware verdict."
        recommendation = "อย่าเปิดไฟล์ทันที ตรวจแหล่งที่มาและบริบทโดยผู้ดูแลระบบ และยืนยันผลด้วยเครื่องมือป้องกันไวรัสที่เชื่อถือได้"

    strings:
        $download1 = "DownloadString" nocase ascii wide
        $download2 = "DownloadFile" nocase ascii wide
        $decode1 = "FromBase64String" nocase ascii wide
        $decode2 = "-EncodedCommand" nocase ascii wide
        $execute1 = "Invoke-Expression" nocase ascii wide
        $execute2 = "IEX" nocase ascii wide

    condition:
        1 of ($download*) and 1 of ($decode*) and 1 of ($execute*)
}

rule Heuristic_JavaScript_Decode_Dynamic_Execute
{
    meta:
        description = "JavaScript contains encoded-data decoding and dynamic code execution indicators; this is heuristic, not a malware verdict."
        recommendation = "ตรวจสอบแหล่งที่มาของสคริปต์และเหตุผลที่ต้องถอดรหัสแล้วประมวลผลโค้ดแบบไดนามิก หลีกเลี่ยง eval หรือ Function กับข้อมูลที่ไม่น่าเชื่อถือ"

    strings:
        $decode1 = "atob(" nocase ascii wide
        $decode2 = "Buffer.from(" nocase ascii wide
        $execute1 = "eval(" nocase ascii wide
        $execute2 = "new Function(" nocase ascii wide

    condition:
        1 of ($decode*) and 1 of ($execute*)
}
