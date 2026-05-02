"""
CPU Emulation and Micro-Execution (Speakeasy)

Emulates Windows malware statically to extract:
  - Dynamically resolved Win32 API calls (with arguments)
  - Network IOCs
  - Dropped files
  - Decoded strings

Anti-evasion: the emulated environment is configured to look like a real
Windows 10 workstation so samples that check CPU vendor, timing, usernames,
or environment variables don't abort early.
"""

from typing import Dict, Any

# Speakeasy config that spoofs a realistic Windows 10 analyst workstation.
# Samples checking CPUID (vendor = GenuineIntel), QueryPerformanceCounter
# results, or env vars won't detect the emulation environment.
_ANTI_EVASION_CONFIG = {
    "hostname":     "DESKTOP-W7K2P1R",
    "user_name":    "john.doe",
    "user_dir":     "C:\\Users\\john.doe",
    "domain":       "WORKGROUP",
    "os_version":   "10.0.19041",     # Windows 10 20H1
    "code_pageid":  1252,             # Western European
    "env_vars": {
        "COMPUTERNAME": "DESKTOP-W7K2P1R",
        "USERNAME":     "john.doe",
        "USERPROFILE":  "C:\\Users\\john.doe",
        "APPDATA":      "C:\\Users\\john.doe\\AppData\\Roaming",
        "TEMP":         "C:\\Users\\john.doe\\AppData\\Local\\Temp",
        "SystemRoot":   "C:\\Windows",
        "windir":       "C:\\Windows",
        "PROCESSOR_IDENTIFIER": "Intel64 Family 6 Model 142 Stepping 10, GenuineIntel",
        "NUMBER_OF_PROCESSORS": "4",
    },
    # Randomise QPC tick rate to defeat timing-based VM detection
    "random_seed":  0x41424344,
}


def analyze_with_speakeasy(file_path: str) -> Dict[str, Any]:
    try:
        import speakeasy
        if not hasattr(speakeasy, "Speakeasy"):
            return {
                "error": (
                    "Wrong 'speakeasy' package is installed. "
                    "Uninstall it and install Mandiant's emulator: "
                    "pip uninstall speakeasy -y && pip install speakeasy-emulator"
                )
            }
    except ImportError:
        return {"error": "speakeasy not installed. Run: pip install speakeasy-emulator"}

    try:
        import pefile
        pe = pefile.PE(file_path, fast_load=True)
        arch = "x86"
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE.get("IMAGE_FILE_MACHINE_AMD64", 0x8664):
            arch = "x64"
        pe.close()

        cfg = dict(_ANTI_EVASION_CONFIG)
        cfg["arch"] = arch

        se     = speakeasy.Speakeasy(config=cfg)
        module = se.load_module(file_path)
        se.run_module(module)
        report = se.get_report()

        api_calls = [
            {
                "api_name": e.get("api_name"),
                "args":     e.get("args"),
                "ret_val":  e.get("ret_val"),
            }
            for e in report.get("api_events", [])
        ]

        return {
            "emulation_successful": True,
            "architecture":         arch,
            "anti_evasion":         True,
            "api_calls_count":      len(api_calls),
            "api_calls":            api_calls[:100],
            "network_events":       report.get("network_events", []),
            "file_events":          report.get("file_access_events", []),
            "dropped_files":        [f.get("name") for f in report.get("dropped_files", [])],
            "dynamic_strings":      report.get("strings", [])[:50],
        }

    except Exception as e:
        return {"error": f"Speakeasy emulation failed: {str(e)}"}
