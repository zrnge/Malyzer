"""PE file analysis using pefile — headers, imports, exports, sections, resources."""

import datetime
from typing import Optional

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

from malyze.static.entropy_analyzer import calculate_entropy, classify_entropy


KNOWN_SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread",
    "QueueUserAPC", "SetThreadContext", "SuspendThread", "ResumeThread",
    "OpenProcess", "OpenThread", "NtOpenProcess",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
    "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW",
    "ShellExecuteExA", "ShellExecuteExW",
    "RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW",
    "RegSetValueA", "RegSetValueW", "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyA", "RegCreateKeyW",
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
    "HttpOpenRequestA", "HttpSendRequestA", "URLDownloadToFileA",
    "WSAStartup", "socket", "connect", "send", "recv", "bind", "listen",
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "CryptCreateHash",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "SetUnhandledExceptionFilter", "UnhandledExceptionFilter",
    "CreateMutexA", "CreateMutexW", "OpenMutexA", "OpenMutexW",
    "FindFirstFileA", "FindFirstFileW", "CopyFileA", "CopyFileW",
    "DeleteFileA", "DeleteFileW", "MoveFileA", "MoveFileW",
    "OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW",
    "StartServiceA", "StartServiceW",
}

MACHINE_TYPES = {
    0x014c: "x86 (32-bit)",
    0x8664: "x64 (64-bit)",
    0x01c0: "ARM",
    0x01c4: "ARM Thumb-2",
    0xaa64: "ARM64",
    0x0200: "IA64",
}

SUBSYSTEMS = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console (CUI)",
    7: "POSIX",
    9: "Windows CE GUI",
    10: "EFI Application",
    14: "EFI ROM",
    16: "Xbox",
}

SECTION_FLAGS = {
    0x00000020: "CODE",
    0x00000040: "INITIALIZED_DATA",
    0x00000080: "UNINITIALIZED_DATA",
    0x02000000: "DISCARDABLE",
    0x10000000: "SHARED",
    0x20000000: "EXECUTE",
    0x40000000: "READ",
    0x80000000: "WRITE",
}


def _parse_timestamp(ts: int) -> str:
    try:
        return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def _section_flags(characteristics: int) -> list:
    return [name for mask, name in SECTION_FLAGS.items() if characteristics & mask]


def analyze_pe(file_path: str) -> dict:
    if not PEFILE_AVAILABLE:
        return {"error": "pefile not installed. Run: pip install pefile"}

    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError as e:
        return {"error": f"Not a valid PE file: {e}"}
    except Exception as e:
        return {"error": str(e)}

    result = {}

    # --- Basic headers ---
    result["machine"] = MACHINE_TYPES.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    result["timestamp"] = _parse_timestamp(pe.FILE_HEADER.TimeDateStamp)
    result["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    result["is_exe"] = bool(pe.FILE_HEADER.Characteristics & 0x0002)
    result["is_driver"] = bool(pe.FILE_HEADER.Characteristics & 0x1000)
    result["is_64bit"] = hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER.Magic == 0x20b
    result["subsystem"] = SUBSYSTEMS.get(
        getattr(pe.OPTIONAL_HEADER, "Subsystem", 0), "Unknown"
    )
    result["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    result["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
    result["size_of_image"] = pe.OPTIONAL_HEADER.SizeOfImage
    result["checksum"] = hex(pe.OPTIONAL_HEADER.CheckSum)
    result["characteristics"] = hex(pe.FILE_HEADER.Characteristics)

    # --- Sections ---
    sections = []
    with open(file_path, "rb") as f:
        raw_data = f.read()

    for section in pe.sections:
        try:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        except Exception:
            name = "?"
        raw_offset = section.PointerToRawData
        raw_size   = section.SizeOfRawData
        sec_data   = raw_data[raw_offset: raw_offset + raw_size] if raw_size else b""
        entropy    = calculate_entropy(sec_data)
        sections.append({
            "name":              name,
            "virtual_address":   hex(section.VirtualAddress),
            "virtual_size":      section.Misc_VirtualSize,
            "raw_offset":        raw_offset,
            "raw_size":          raw_size,
            "characteristics":   hex(section.Characteristics),
            "flags":             _section_flags(section.Characteristics),
            "entropy":           entropy,
            "entropy_class":     classify_entropy(entropy),
            "suspicious":        entropy >= 7.0,
        })
    result["sections"] = sections

    # --- Imports ---
    imports = {}
    suspicious_imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else "?"
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode("utf-8", errors="replace")
                else:
                    name = f"ordinal_{imp.ordinal}"
                funcs.append(name)
                if name in KNOWN_SUSPICIOUS_IMPORTS:
                    suspicious_imports.append(f"{dll}!{name}")
            imports[dll] = funcs
    result["imports"] = imports
    result["suspicious_imports"] = suspicious_imports

    # --- Exports ---
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode("utf-8", errors="replace") if exp.name else f"ordinal_{exp.ordinal}"
            exports.append({"name": name, "ordinal": exp.ordinal, "address": hex(exp.address)})
    result["exports"] = exports

    # --- Resources ---
    resources = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_name = str(res_type.name) if res_type.name else pefile.RESOURCE_TYPE.get(
                res_type.struct.Id, str(res_type.struct.Id)
            )
            if hasattr(res_type, "directory"):
                for res_id in res_type.directory.entries:
                    if hasattr(res_id, "directory"):
                        for res_lang in res_id.directory.entries:
                            data_entry = res_lang.data.struct
                            resources.append({
                                "type": type_name,
                                "size": data_entry.Size,
                                "rva":  hex(data_entry.OffsetToData),
                            })
    result["resources"] = resources

    # --- Digital signature ---
    result["has_signature"] = hasattr(pe, "DIRECTORY_ENTRY_SECURITY")

    # --- TLS callbacks (anti-analysis) ---
    result["has_tls"] = hasattr(pe, "DIRECTORY_ENTRY_TLS")

    # --- Import hash (imphash) — key for cross-sample correlation ---
    try:
        result["imphash"] = pe.get_imphash()
    except Exception:
        result["imphash"] = None

    # --- .NET / CLR detection (COM+ Runtime Header = data directory 14) ---
    try:
        clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        result["is_dotnet"] = clr_dir.VirtualAddress != 0 and clr_dir.Size != 0
    except Exception:
        result["is_dotnet"] = False

    # --- PDB debug path (developer artifact — reveals build environment) ---
    result["pdb_path"] = None
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            try:
                if hasattr(dbg.struct, "Type") and dbg.struct.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                    offset = dbg.struct.PointerToRawData
                    size   = dbg.struct.SizeOfData
                    if offset and size:
                        chunk = raw_data[offset: offset + size]
                        if chunk[:4] in (b"RSDS", b"NB10"):
                            # RSDS: 4-byte sig, 16-byte GUID, 4-byte age, then null-terminated path
                            if chunk[:4] == b"RSDS" and len(chunk) > 24:
                                path_bytes = chunk[24:]
                                null_pos = path_bytes.find(b"\x00")
                                pdb = path_bytes[:null_pos].decode("utf-8", errors="replace")
                                if pdb:
                                    result["pdb_path"] = pdb
            except Exception:
                pass

    # --- Rich header (reveals true compiler/linker — survives timestamp forgery) ---
    result["rich_header"] = None
    try:
        rich = pe.parse_rich_header()
        if rich:
            result["rich_header"] = {
                "checksum": hex(rich.get("checksum", 0)),
                "entries":  rich.get("values", []),
            }
    except Exception:
        pass

    # --- Version info strings (ProductName, FileDescription, CompanyName, etc.) ---
    result["version_info"] = {}
    if hasattr(pe, "FileInfo"):
        for fi_entry in pe.FileInfo:
            for fsi in (fi_entry if isinstance(fi_entry, list) else [fi_entry]):
                if hasattr(fsi, "StringTable"):
                    for st in fsi.StringTable:
                        for entry in st.entries.items():
                            try:
                                k = entry[0].decode("utf-8", errors="replace")
                                v = entry[1].decode("utf-8", errors="replace")
                                result["version_info"][k] = v
                            except Exception:
                                pass

    # --- Overlay ---
    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset:
        overlay_data = raw_data[overlay_offset:]
        result["overlay"] = {
            "offset": overlay_offset,
            "size": len(overlay_data),
            "entropy": calculate_entropy(overlay_data),
        }
    else:
        result["overlay"] = None

    pe.close()
    return result
