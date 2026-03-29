"""File type identification — determines what analysis tools to apply."""

import hashlib
import os
import struct
from pathlib import Path
from typing import Optional


# Magic bytes for common file types
MAGIC_SIGNATURES = {
    b"\x4d\x5a": "PE",                         # MZ header
    b"\x7fELF": "ELF",                          # Linux ELF
    b"\xca\xfe\xba\xbe": "MACHO",              # macOS Mach-O FAT
    b"\xcf\xfa\xed\xfe": "MACHO",              # Mach-O 64-bit
    b"\xce\xfa\xed\xfe": "MACHO",              # Mach-O 32-bit
    b"PK\x03\x04": "ZIP",                       # ZIP / JAR / DOCX etc.
    b"\x50\x4b\x05\x06": "ZIP",
    b"PK\x07\x08": "ZIP",
    b"\x1f\x8b": "GZIP",
    b"BZh": "BZIP2",
    b"\xfd7zXZ": "XZ",
    b"Rar!\x1a\x07": "RAR",
    b"\x25\x50\x44\x46": "PDF",                 # %PDF
    b"\xd0\xcf\x11\xe0": "OLE",                 # Office OLE compound
    b"\x4f\x54\x54\x4f": "OTF",                 # OpenType Font
    b"\x00\x00\x01\x00": "ICO",
    b"MSCF": "CAB",                             # Microsoft Cabinet
    b"\x7b\x5c\x72\x74\x66": "RTF",            # {\rtf
    b"#!/": "SCRIPT",
    b"#!": "SCRIPT",
    b"\xef\xbb\xbf": "UTF8_BOM",
}

PE_SUBTYPES = {
    0x0002: "GUI",
    0x0003: "Console (CUI)",
    0x000E: "EFI",
    0x0010: "EFI ROM",
}

EXTENSION_MAP = {
    ".exe": "PE",
    ".dll": "PE_DLL",
    ".sys": "PE_DRIVER",
    ".scr": "PE",
    ".ocx": "PE_DLL",
    ".cpl": "PE_DLL",
    ".drv": "PE_DRIVER",
    ".so":  "ELF",
    ".elf": "ELF",
    ".ko":  "ELF_KERNEL",
    ".sh":  "SCRIPT_BASH",
    ".ps1": "SCRIPT_POWERSHELL",
    ".vbs": "SCRIPT_VBS",
    ".js":  "SCRIPT_JS",
    ".jar": "JAVA_JAR",
    ".class": "JAVA_CLASS",
    ".py":  "SCRIPT_PYTHON",
    ".bat": "SCRIPT_BAT",
    ".cmd": "SCRIPT_BAT",
    ".pdf": "PDF",
    ".doc": "OLE",
    ".xls": "OLE",
    ".ppt": "OLE",
    ".docx": "ZIP",
    ".xlsx": "ZIP",
    ".pptx": "ZIP",
    ".rtf": "RTF",
    ".lnk": "LNK",
    ".zip": "ZIP",
    ".rar": "RAR",
    ".7z": "7ZIP",
    ".apk": "ANDROID_APK",
    ".dex": "ANDROID_DEX",
}

# Tools relevant for each file type
TOOL_MAP = {
    "PE": [
        "file_hashes", "strings", "floss", "pe_headers", "pe_imports",
        "pe_exports", "pe_sections", "pe_resources", "entropy",
        "packer_detect", "die", "capa", "disassemble", "yara"
    ],
    "PE_DLL": [
        "file_hashes", "strings", "floss", "pe_headers", "pe_imports",
        "pe_exports", "pe_sections", "entropy", "packer_detect", "die",
        "capa", "disassemble", "yara"
    ],
    "PE_DRIVER": [
        "file_hashes", "strings", "pe_headers", "pe_imports", "pe_exports",
        "pe_sections", "entropy", "packer_detect", "die", "capa",
        "disassemble", "yara"
    ],
    "ELF": [
        "file_hashes", "strings", "elf_headers", "elf_symbols", "entropy",
        "disassemble", "yara"
    ],
    "SCRIPT_POWERSHELL": ["file_hashes", "strings", "yara", "deobfuscate"],
    "SCRIPT_VBS":        ["file_hashes", "strings", "yara", "deobfuscate"],
    "SCRIPT_JS":         ["file_hashes", "strings", "yara", "deobfuscate"],
    "SCRIPT_BASH":       ["file_hashes", "strings", "yara"],
    "SCRIPT_PYTHON":     ["file_hashes", "strings", "yara"],
    "SCRIPT_BAT":        ["file_hashes", "strings", "yara"],
    "PDF":               ["file_hashes", "strings", "yara"],
    "OLE":               ["file_hashes", "strings", "yara"],
    "ZIP":               ["file_hashes", "strings", "yara"],
    "JAVA_JAR":          ["file_hashes", "strings", "yara"],
    "JAVA_CLASS":        ["file_hashes", "strings", "disassemble", "yara"],
    "ANDROID_APK":       ["file_hashes", "strings", "yara"],
    "ANDROID_DEX":       ["file_hashes", "strings", "disassemble", "yara"],
    "LNK":               ["file_hashes", "strings", "yara"],
    "UNKNOWN":           ["file_hashes", "strings", "entropy", "yara"],
}


def compute_hashes(file_path: str) -> dict:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": os.path.getsize(file_path),
    }


def _read_magic(file_path: str, n: int = 16) -> bytes:
    try:
        with open(file_path, "rb") as f:
            return f.read(n)
    except Exception:
        return b""


def identify_file(file_path: str) -> dict:
    """
    Determine the file type and return metadata + relevant tool list.
    """
    path = Path(file_path)
    magic = _read_magic(file_path)
    hashes = compute_hashes(file_path)

    detected_type = "UNKNOWN"
    subtype = ""

    # Magic bytes detection
    for sig, ftype in MAGIC_SIGNATURES.items():
        if magic.startswith(sig):
            detected_type = ftype
            break

    # PE subtype refinement
    if detected_type == "PE":
        ext = path.suffix.lower()
        if ext in (".dll", ".ocx", ".cpl", ".drv"):
            detected_type = "PE_DLL"
        elif ext in (".sys", ".drv"):
            detected_type = "PE_DRIVER"
        subtype = _get_pe_subtype(file_path)

    # Extension fallback
    if detected_type == "UNKNOWN":
        ext = path.suffix.lower()
        detected_type = EXTENSION_MAP.get(ext, "UNKNOWN")

    # ZIP-based format refinement
    if detected_type == "ZIP":
        ext = path.suffix.lower()
        if ext == ".jar":
            detected_type = "JAVA_JAR"
        elif ext == ".apk":
            detected_type = "ANDROID_APK"

    tools = TOOL_MAP.get(detected_type, TOOL_MAP["UNKNOWN"])

    return {
        "path": str(path.resolve()),
        "name": path.name,
        "extension": path.suffix.lower(),
        "type": detected_type,
        "subtype": subtype,
        "magic_bytes": magic[:8].hex(),
        "hashes": hashes,
        "tools": tools,
    }


def _get_pe_subtype(file_path: str) -> str:
    try:
        with open(file_path, "rb") as f:
            data = f.read(512)
        # Read e_lfanew
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data):
            return ""
        subsystem_offset = e_lfanew + 24 + 68
        if subsystem_offset + 2 > len(data):
            return ""
        subsystem = struct.unpack_from("<H", data, subsystem_offset)[0]
        return PE_SUBTYPES.get(subsystem, f"Subsystem({subsystem})")
    except Exception:
        return ""
