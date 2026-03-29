/* Malyze YARA Rules — Packer and Malware Family Detection */

rule UPX_Packed {
    meta:
        description = "UPX packed executable"
        author      = "Malyze"
    strings:
        $s1 = "UPX0" ascii
        $s2 = "UPX1" ascii
        $s3 = "UPX!" ascii
    condition:
        2 of them
}

rule MPRESS_Packed {
    meta:
        description = "MPRESS packed executable"
    strings:
        $s1 = ".MPRESS1" ascii
        $s2 = ".MPRESS2" ascii
    condition:
        any of them
}

rule Themida_Protected {
    meta:
        description = "Themida/WinLicense protected"
    strings:
        $s1 = "Themida" ascii nocase
        $s2 = ".themida" ascii nocase
        $s3 = "WinLicense" ascii nocase
    condition:
        any of them
}

rule VMProtect {
    meta:
        description = "VMProtect protected binary"
    strings:
        $s1 = ".vmp0" ascii
        $s2 = ".vmp1" ascii
        $s3 = "VMProtect" ascii
    condition:
        any of them
}

rule ASPack {
    meta:
        description = "ASPack packed"
    strings:
        $s1 = ".aspack" ascii nocase
        $s2 = "ASPack" ascii
    condition:
        any of them
}

rule Suspicious_Powershell {
    meta:
        description = "Suspicious PowerShell execution"
    strings:
        $s1 = "powershell" ascii nocase
        $s2 = "-EncodedCommand" ascii nocase
        $s3 = "-enc " ascii nocase
        $s4 = "IEX(" ascii nocase
        $s5 = "Invoke-Expression" ascii nocase
        $s6 = "DownloadString" ascii nocase
        $s7 = "DownloadFile" ascii nocase
        $s8 = "FromBase64String" ascii nocase
    condition:
        $s1 and 2 of ($s2, $s3, $s4, $s5, $s6, $s7, $s8)
}

rule Process_Injection {
    meta:
        description = "Indicators of process injection"
    strings:
        $s1 = "VirtualAllocEx" ascii
        $s2 = "WriteProcessMemory" ascii
        $s3 = "CreateRemoteThread" ascii
        $s4 = "NtCreateThreadEx" ascii
        $s5 = "RtlCreateUserThread" ascii
    condition:
        2 of them
}

rule Keylogger_Indicators {
    meta:
        description = "Keylogger API usage"
    strings:
        $s1 = "SetWindowsHookEx" ascii
        $s2 = "GetAsyncKeyState" ascii
        $s3 = "GetKeyState" ascii
        $s4 = "MapVirtualKey" ascii
    condition:
        2 of them
}

rule Ransomware_Indicators {
    meta:
        description = "Potential ransomware indicators"
    strings:
        $s1 = "CryptEncrypt" ascii
        $s2 = "CryptAcquireContext" ascii
        $s3 = "FindFirstFile" ascii
        $s4 = "bitcoin" ascii nocase
        $s5 = ".onion" ascii nocase
        $s6 = "ransom" ascii nocase
        $s7 = "decrypt" ascii nocase
        $s8 = "your files" ascii nocase
    condition:
        3 of them
}

rule AntiDebug {
    meta:
        description = "Anti-debugging techniques"
    strings:
        $s1 = "IsDebuggerPresent" ascii
        $s2 = "CheckRemoteDebuggerPresent" ascii
        $s3 = "NtQueryInformationProcess" ascii
        $s4 = "OutputDebugString" ascii
        $s5 = "FindWindow" ascii
        $s6 = "GetTickCount" ascii
    condition:
        2 of them
}

rule Network_Indicators {
    meta:
        description = "Network communication capabilities"
    strings:
        $s1 = "WSAStartup" ascii
        $s2 = "InternetOpen" ascii nocase
        $s3 = "HttpSendRequest" ascii nocase
        $s4 = "URLDownloadToFile" ascii nocase
        $s5 = "WinHttpOpen" ascii nocase
    condition:
        2 of them
}

rule Persistence_Mechanisms {
    meta:
        description = "Common persistence mechanisms"
    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $reg2 = "SYSTEM\\CurrentControlSet\\Services" ascii nocase
        $svc1 = "CreateService" ascii
        $svc2 = "OpenSCManager" ascii
        $task1 = "schtasks" ascii nocase
        $task2 = "ITaskScheduler" ascii
    condition:
        2 of them
}

rule Credential_Access {
    meta:
        description = "Credential dumping indicators"
    strings:
        $s1 = "lsass" ascii nocase
        $s2 = "sekurlsa" ascii nocase
        $s3 = "mimikatz" ascii nocase
        $s4 = "SAM" ascii
        $s5 = "NtlmHash" ascii nocase
        $s6 = "LsaEnumerateLogonSessions" ascii
    condition:
        2 of them
}
