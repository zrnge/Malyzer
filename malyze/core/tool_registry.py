"""
Tool Registry — catalog of every analysis tool Malyze knows about.

Each entry describes:
  - how to detect if the tool is available
  - how to install it if missing (with source URL)
  - which file types it applies to
  - the Python runner function to call
"""

import os
import sys
import shutil
import importlib
from pathlib import Path
from typing import Optional, Callable


# ─────────────────────────────────────────────────────────────────────────────
# Tool type constants
# ─────────────────────────────────────────────────────────────────────────────
T_PYTHON_LIB = "python_lib"   # importable Python package
T_CLI        = "cli"          # external binary on PATH or config path
T_BUILTIN    = "builtin"      # always available (pure Python, stdlib only)


# ─────────────────────────────────────────────────────────────────────────────
# Full tool catalog
# ─────────────────────────────────────────────────────────────────────────────
CATALOG = {

    # ── Always available ────────────────────────────────────────────────────

    "file_hashes": {
        "name":        "File Hashing (MD5 / SHA1 / SHA256)",
        "description": "Compute cryptographic hashes and file size.",
        "type":        T_BUILTIN,
        "category":    "identification",
        "file_types":  ["*"],
    },

    "file_id": {
        "name":        "File Type Identification",
        "description": "Detect file type via magic bytes, extension, and structure.",
        "type":        T_BUILTIN,
        "category":    "identification",
        "file_types":  ["*"],
    },

    "shodan": {
        "name":        "Shodan IP Intel",
        "description": "Query an IP address (found in strings or network analysis) to see its open ports, organization, and hostnames.",
        "type":        T_BUILTIN,
        "category":    "threat_intel",
        "file_types":  ["*"],
    },

    "otx": {
        "name":        "AlienVault OTX",
        "description": "Query an indicator (hash, IP, domain) for related malware campaigns and pulses.",
        "type":        T_BUILTIN,
        "category":    "threat_intel",
        "file_types":  ["*"],
    },

    "entropy": {
        "name":        "Entropy Analysis",
        "description": "Shannon entropy per file / per PE section. Detects packing and encryption.",
        "type":        T_BUILTIN,
        "category":    "static",
        "file_types":  ["*"],
    },

    "strings_python": {
        "name":        "String Extraction (Python fallback)",
        "description": "Pure-Python ASCII + Unicode string extractor. Always available.",
        "type":        T_BUILTIN,
        "category":    "static",
        "file_types":  ["*"],
    },

    "script_analysis": {
        "name":        "Script Static Analysis (built-in)",
        "description": "Deep static analysis of scripts: deobfuscation, base64 decode, "
                       "pattern detection, IOC extraction. No execution required.",
        "type":        T_BUILTIN,
        "category":    "static",
        "file_types":  ["SCRIPT_POWERSHELL", "SCRIPT_VBS", "SCRIPT_JS",
                        "SCRIPT_PYTHON", "SCRIPT_BAT", "SCRIPT"],
    },

    "pdf_analysis": {
        "name":        "PDF Static Analysis (built-in)",
        "description": "PDF structure analysis: objects, JavaScript detection, "
                       "embedded files, auto-actions, URLs. No execution.",
        "type":        T_BUILTIN,
        "category":    "static",
        "file_types":  ["PDF"],
    },

    "office_analysis": {
        "name":        "Office Document Static Analysis (built-in)",
        "description": "OLE/OOXML/RTF analysis: macros, embedded objects, "
                       "external URLs, CVE indicators. No execution.",
        "type":        T_BUILTIN,
        "category":    "static",
        "file_types":  ["OLE", "ZIP", "RTF"],
    },

    # ── Python library tools ─────────────────────────────────────────────────

    "pefile": {
        "name":        "PE Analysis (pefile)",
        "description": "Parse PE headers, sections, imports, exports, resources, overlay.",
        "type":        T_PYTHON_LIB,
        "module":      "pefile",
        "install_cmd": "pip install pefile",
        "source":      "https://github.com/erocarrera/pefile",
        "category":    "static",
        "file_types":  ["PE", "PE_DLL", "PE_DRIVER"],
    },

    "capstone": {
        "name":        "Disassembly (Capstone)",
        "description": "Disassemble x86/x64/ARM from entry point. Works on PE and ELF.",
        "type":        T_PYTHON_LIB,
        "module":      "capstone",
        "install_cmd": "pip install capstone",
        "source":      "https://www.capstone-engine.org/",
        "category":    "static",
        "file_types":  ["PE", "PE_DLL", "PE_DRIVER", "ELF", "MACHO"],
    },

    "yara_python": {
        "name":        "YARA Rule Scanning (yara-python)",
        "description": "Scan file against malware family / packer YARA rules.",
        "type":        T_PYTHON_LIB,
        "module":      "yara",
        "install_cmd": "pip install yara-python",
        "source":      "https://virustotal.github.io/yara/",
        "category":    "static",
        "file_types":  ["*"],
    },

    "oletools": {
        "name":        "OLE/Office Analysis (oletools)",
        "description": "Analyse Office documents for macros, OLE streams, suspicious content.",
        "type":        T_PYTHON_LIB,
        "module":      "oletools.olevba",
        "install_cmd": "pip install oletools",
        "source":      "https://github.com/decalage2/oletools",
        "category":    "static",
        "file_types":  ["OLE", "ZIP"],
        "note":        "Best for .doc .xls .ppt .docm .xlsm files",
    },

    "pdfminer": {
        "name":        "PDF Analysis (pdfminer.six)",
        "description": "Extract text, metadata, JavaScript, and embedded objects from PDFs.",
        "type":        T_PYTHON_LIB,
        "module":      "pdfminer.high_level",
        "install_cmd": "pip install pdfminer.six",
        "source":      "https://github.com/pdfminer/pdfminer.six",
        "category":    "static",
        "file_types":  ["PDF"],
    },

    "pyelftools": {
        "name":        "ELF Analysis (pyelftools)",
        "description": "Parse ELF headers, sections, symbols, dynamic libraries.",
        "type":        T_PYTHON_LIB,
        "module":      "elftools.elf.elffile",
        "install_cmd": "pip install pyelftools",
        "source":      "https://github.com/eliben/pyelftools",
        "category":    "static",
        "file_types":  ["ELF", "ELF_KERNEL"],
    },

    "speakeasy": {
        "name":        "CPU Emulation (Speakeasy)",
        "description": "Emulates the binary to extract dynamically resolved APIs, network events, and dropped files statically.",
        "type":        T_PYTHON_LIB,
        "module":      "speakeasy",
        "install_cmd": "pip install speakeasy-emu",
        "source":      "https://github.com/fireeye/speakeasy",
        "category":    "static",
        "file_types":  ["PE", "PE_DLL"],
    },

    # ── CLI tools ────────────────────────────────────────────────────────────

    "floss": {
        "name":        "FLOSS — FLARE Obfuscated String Solver",
        "description": "Decode obfuscated / stack / tight strings in malware.",
        "type":        T_CLI,
        "bin_windows": "floss.exe",
        "bin_linux":   "floss",
        "install_windows": "Download from GitHub releases, place on PATH",
        "install_linux":   "Download from GitHub releases, chmod +x",
        "source":      "https://github.com/mandiant/flare-floss/releases",
        "category":    "static",
        "file_types":  ["PE", "PE_DLL", "PE_DRIVER", "ELF"],
        "timeout":     300,   # FLOSS can be slow on large/complex binaries
    },

    "strings_cli": {
        "name":        "strings / strings64 (Sysinternals)",
        "description": "Fast string extraction from any binary.",
        "type":        T_CLI,
        "bin_windows": "strings64.exe",
        "bin_linux":   "strings",
        "install_windows": "Download Sysinternals Suite from Microsoft",
        "install_linux":   "sudo apt install binutils  OR  sudo yum install binutils",
        "source":      "https://learn.microsoft.com/en-us/sysinternals/downloads/strings",
        "category":    "static",
        "file_types":  ["*"],
    },

    "die": {
        "name":        "Detect-It-Easy (diec)",
        "description": "Identify compiler, linker, packer, protector used on the binary.",
        "type":        T_CLI,
        "bin_windows": "diec.exe",
        "bin_linux":   "diec",
        "install_windows": "Download from GitHub, place diec.exe on PATH or in FlareVM",
        "install_linux":   "Download from GitHub releases",
        "source":      "https://github.com/horsicq/Detect-It-Easy/releases",
        "category":    "static",
        "file_types":  ["PE", "PE_DLL", "PE_DRIVER", "ELF", "MACHO"],
    },

    "upx": {
        "name":        "UPX (packer detection + unpacking)",
        "description": "Test if file is UPX-packed. Can unpack UPX samples.",
        "type":        T_CLI,
        "bin_windows": "upx.exe",
        "bin_linux":   "upx",
        "install_windows": "Download from GitHub, place on PATH",
        "install_linux":   "sudo apt install upx-ucl",
        "source":      "https://upx.github.io/",
        "category":    "static",
        "file_types":  ["PE", "PE_DLL", "ELF"],
    },

    "capa": {
        "name":        "CAPA (FLARE Capability Detection)",
        "description": "Identify malware capabilities (persistence, injection, crypto, C2, etc.).",
        "type":        T_CLI,
        "bin_windows": "capa.exe",
        "bin_linux":   "capa",
        "install_windows": "Download from GitHub releases, place capa.exe on PATH",
        "install_linux":   "pip install flare-capa  OR download from GitHub",
        "source":      "https://github.com/mandiant/capa/releases",
        "category":    "static",
        "file_types":  ["PE", "PE_DLL", "PE_DRIVER", "ELF"],
        "note":        "Requires capa-rules. First run downloads rules automatically.",
        "timeout":     240,   # CAPA rule matching can take time on large binaries
    },

    "yara_cli": {
        "name":        "YARA (CLI binary)",
        "description": "Scan file with YARA rules.",
        "type":        T_CLI,
        "bin_windows": "yara64.exe",
        "bin_linux":   "yara",
        "install_windows": "Download from VirusTotal YARA releases",
        "install_linux":   "sudo apt install yara",
        "source":      "https://github.com/VirusTotal/yara/releases",
        "category":    "static",
        "file_types":  ["*"],
    },

    "exiftool": {
        "name":        "ExifTool",
        "description": "Extract rich metadata from PE, PDF, Office, images, and more.",
        "type":        T_CLI,
        "bin_windows": "exiftool.exe",
        "bin_linux":   "exiftool",
        "install_windows": "Download from exiftool.org, place on PATH",
        "install_linux":   "sudo apt install libimage-exiftool-perl",
        "source":      "https://exiftool.org/",
        "category":    "static",
        "file_types":  ["*"],
    },

    "binwalk": {
        "name":        "Binwalk",
        "description": "Scan for embedded files and executable code.",
        "type":        T_CLI,
        "bin_windows": "binwalk.exe",
        "bin_linux":   "binwalk",
        "install_windows": "pip install binwalk (limited on Windows)",
        "install_linux":   "sudo apt install binwalk  OR pip install binwalk",
        "source":      "https://github.com/ReFirmLabs/binwalk",
        "category":    "static",
        "file_types":  ["*"],
    },

    "readelf": {
        "name":        "readelf (GNU binutils)",
        "description": "Display ELF headers, sections, symbols, dynamic deps.",
        "type":        T_CLI,
        "bin_windows": "readelf.exe",
        "bin_linux":   "readelf",
        "install_windows": "Install MinGW or WSL",
        "install_linux":   "sudo apt install binutils",
        "source":      "https://sourceware.org/binutils/",
        "category":    "static",
        "file_types":  ["ELF", "ELF_KERNEL"],
    },

    "objdump": {
        "name":        "objdump (GNU binutils)",
        "description": "Disassemble and dump ELF/PE object files.",
        "type":        T_CLI,
        "bin_windows": "objdump.exe",
        "bin_linux":   "objdump",
        "install_windows": "Install MinGW or WSL",
        "install_linux":   "sudo apt install binutils",
        "source":      "https://sourceware.org/binutils/",
        "category":    "static",
        "file_types":  ["ELF", "PE"],
    },

    "pdf_parser": {
        "name":        "pdf-parser (Didier Stevens)",
        "description": "Inspect PDF objects, streams, JavaScript, embedded files.",
        "type":        T_CLI,
        "bin_windows": "pdf-parser.py",
        "bin_linux":   "pdf-parser.py",
        "install_windows": "Download from blog.didierstevens.com, run with python",
        "install_linux":   "Download from blog.didierstevens.com, run with python",
        "source":      "https://blog.didierstevens.com/programs/pdf-tools/",
        "category":    "static",
        "file_types":  ["PDF"],
    },

    "oledump": {
        "name":        "oledump (Didier Stevens)",
        "description": "Analyse OLE/Office compound document streams and macros.",
        "type":        T_CLI,
        "bin_windows": "oledump.py",
        "bin_linux":   "oledump.py",
        "install_windows": "Download from blog.didierstevens.com",
        "install_linux":   "Download from blog.didierstevens.com",
        "source":      "https://blog.didierstevens.com/programs/oledump-py/",
        "category":    "static",
        "file_types":  ["OLE"],
    },

    # ── Dynamic analysis tools ───────────────────────────────────────────────

    "procmon": {
        "name":        "Process Monitor (Sysinternals)",
        "description": "Capture process, file, registry, and network events in real time.",
        "type":        T_CLI,
        "bin_windows": "Procmon64.exe",
        "bin_linux":   None,
        "install_windows": "Download Sysinternals Suite from Microsoft",
        "install_linux":   "Not available on Linux (use strace/sysdig instead)",
        "source":      "https://learn.microsoft.com/en-us/sysinternals/downloads/procmon",
        "category":    "dynamic",
        "file_types":  ["PE", "PE_DLL", "SCRIPT_POWERSHELL", "SCRIPT_BAT"],
        "os":          ["windows"],
    },

    "fakenet": {
        "name":        "FakeNet-NG",
        "description": "Intercept and simulate network traffic during dynamic analysis.",
        "type":        T_CLI,
        "bin_windows": "FakeNet.exe",
        "bin_linux":   "fakenet",
        "install_windows": "Included in FlareVM. Download from GitHub.",
        "install_linux":   "pip install flare-fakenet-ng",
        "source":      "https://github.com/mandiant/flare-fakenet-ng",
        "category":    "dynamic",
        "file_types":  ["PE", "PE_DLL", "ELF", "SCRIPT_POWERSHELL"],
    },

    "regshot": {
        "name":        "Regshot",
        "description": "Compare registry snapshots before/after sample execution.",
        "type":        T_CLI,
        "bin_windows": "Regshot-x64-Unicode.exe",
        "bin_linux":   None,
        "install_windows": "Download from Regshot GitHub, included in FlareVM",
        "install_linux":   "Not available on Linux",
        "source":      "https://github.com/Seabreg/Regshot",
        "category":    "dynamic",
        "file_types":  ["PE", "PE_DLL"],
        "os":          ["windows"],
    },

    "strace": {
        "name":        "strace",
        "description": "Trace system calls and signals on Linux.",
        "type":        T_CLI,
        "bin_windows": None,
        "bin_linux":   "strace",
        "install_windows": "Not available on Windows (use Procmon)",
        "install_linux":   "sudo apt install strace",
        "source":      "https://strace.io/",
        "category":    "dynamic",
        "file_types":  ["ELF", "SCRIPT_BASH", "SCRIPT_PYTHON"],
        "os":          ["linux"],
    },

    "tshark": {
        "name":        "tshark (Wireshark CLI)",
        "description": "Capture and analyze live network traffic during execution. "
                       "More granular than FakeNet — captures raw packets and extracts DNS/HTTP/TLS IOCs.",
        "type":        T_CLI,
        "bin_windows": "tshark.exe",
        "bin_linux":   "tshark",
        "install_windows": "Install Wireshark from wireshark.org (tshark is included)",
        "install_linux":   "sudo apt install tshark",
        "source":      "https://www.wireshark.org/",
        "category":    "dynamic",
        "file_types":  ["PE", "PE_DLL", "ELF", "SCRIPT_POWERSHELL", "SCRIPT_BAT"],
    },

    "autorunsc": {
        "name":        "Autorunsc (Sysinternals)",
        "description": "Snapshot all autorun / persistence locations (registry Run keys, "
                       "scheduled tasks, services, startup folders, browser extensions, etc.). "
                       "Compare before/after sample execution to detect new persistence.",
        "type":        T_CLI,
        "bin_windows": "autorunsc.exe",
        "bin_linux":   None,
        "install_windows": "Part of Sysinternals Suite — download from Microsoft or included in FlareVM",
        "install_linux":   "Not available on Linux (use crontab / systemd inspection instead)",
        "source":      "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
        "category":    "dynamic",
        "file_types":  ["PE", "PE_DLL", "PE_DRIVER", "SCRIPT_POWERSHELL", "SCRIPT_BAT"],
        "os":          ["windows"],
    },

    "procdump": {
        "name":        "ProcDump (Sysinternals)",
        "description": "Dump process memory to disk. "
                       "Captures unpacked malware code from memory — useful when packer detection "
                       "confirmed packing and static strings were garbage.",
        "type":        T_CLI,
        "bin_windows": "procdump64.exe",
        "bin_linux":   None,
        "install_windows": "Part of Sysinternals Suite — download from Microsoft or included in FlareVM",
        "install_linux":   "Not available on Linux (use gcore or gdb instead)",
        "source":      "https://learn.microsoft.com/en-us/sysinternals/downloads/procdump",
        "category":    "dynamic",
        "file_types":  ["PE", "PE_DLL"],
        "os":          ["windows"],
    },

    "wireshark": {
        "name":        "Wireshark (GUI — manual review)",
        "description": "Network protocol analyzer GUI. Use tshark for automated capture; "
                       "open the saved .pcap in Wireshark for deep manual inspection.",
        "type":        T_CLI,
        "bin_windows": "Wireshark.exe",
        "bin_linux":   "wireshark",
        "install_windows": "Download from wireshark.org",
        "install_linux":   "sudo apt install wireshark",
        "source":      "https://www.wireshark.org/",
        "category":    "dynamic",
        "file_types":  ["PE", "PE_DLL", "ELF"],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Tool availability detection
# ─────────────────────────────────────────────────────────────────────────────

def _check_python_lib(module_name: str) -> bool:
    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        return False


def _check_cli(bin_name: Optional[str], extra_paths: list = None) -> Optional[str]:
    """Return the resolved binary path, or None if not found."""
    if not bin_name:
        return None
    # PATH check
    found = shutil.which(bin_name)
    if found:
        return found
    # Common FlareVM / tool directories
    search = extra_paths or []
    search += [
        r"C:\Tools",
        r"C:\tools\floss",
        r"C:\tools\capa",
        r"C:\tools\die",
        r"C:\tools\sysinternals",
        r"C:\Program Files\ExifTool",
        "/usr/bin", "/usr/local/bin", "/opt/tools",
    ]
    for d in search:
        candidate = Path(d) / bin_name
        if candidate.exists():
            return str(candidate)
    return None


def check_availability(tool_id: str, cfg: dict = None, is_windows: bool = True) -> dict:
    """
    Check if a tool is available and return status info.
    Returns: {available, path_or_module, recommendation}
    """
    cfg = cfg or {}
    entry = CATALOG.get(tool_id)
    if not entry:
        return {"available": False, "recommendation": f"Unknown tool: {tool_id}"}

    t = entry["type"]

    if t == T_BUILTIN:
        return {"available": True, "path_or_module": "builtin"}

    if t == T_PYTHON_LIB:
        mod = entry.get("module", "")
        ok  = _check_python_lib(mod)
        if ok:
            return {"available": True, "path_or_module": mod}
        return {
            "available": False,
            "path_or_module": None,
            "recommendation": (
                f"Install with: {entry.get('install_cmd','pip install <package>')}\n"
                f"Source: {entry.get('source','')}"
            ),
        }

    if t == T_CLI:
        bin_key = "bin_windows" if is_windows else "bin_linux"
        bin_name = entry.get(bin_key)

        # Config override
        cfg_path = cfg.get("flarevm", {}).get(tool_id, "")
        if cfg_path and Path(cfg_path).exists():
            return {"available": True, "path_or_module": cfg_path}

        resolved = _check_cli(bin_name)
        if resolved:
            return {"available": True, "path_or_module": resolved}

        install_key = "install_windows" if is_windows else "install_linux"
        return {
            "available": False,
            "path_or_module": None,
            "recommendation": (
                f"Tool not found: '{bin_name}'\n"
                f"Install: {entry.get(install_key,'See source URL')}\n"
                f"Source:  {entry.get('source','')}"
            ),
        }

    return {"available": False, "recommendation": "Unknown tool type"}


def get_tool_info(tool_id: str) -> dict:
    return CATALOG.get(tool_id, {})


def all_tool_ids() -> list:
    return list(CATALOG.keys())


def tools_for_file_type(file_type: str) -> list:
    """Return tool IDs applicable to a given file type."""
    result = []
    for tid, entry in CATALOG.items():
        types = entry.get("file_types", [])
        if "*" in types or file_type in types or any(file_type.startswith(t) for t in types):
            result.append(tid)
    return result
