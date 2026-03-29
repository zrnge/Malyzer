"""Packer/protector detection — wraps Detect-It-Easy CLI, UPX, and heuristics."""

import subprocess
import shutil
import json
import re
from pathlib import Path
from typing import Optional

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


KNOWN_PACKER_SECTION_NAMES = {
    "UPX0", "UPX1", "UPX2",
    ".aspack", "ASPack",
    ".MPRESS1", ".MPRESS2",
    "PECompact",
    ".nsp0", ".nsp1", ".nsp2",
    "Themida", ".themida",
    ".vmp0", ".vmp1", ".vmp2",
    "VMProtect",
    "aPLib",
    ".petite",
    "PKLSTB",
    "MEW",
    "RLPack",
    "NSPack",
    ".enigma1", ".enigma2",
}

ANOMALY_CHECKS = {
    "entry_in_non_code_section": "Entry point is NOT in a code/text section",
    "high_import_count_ratio": "Very few imports relative to file size (possible import hiding)",
    "single_import": "Only one or two imported DLLs (common in packed files)",
    "no_exports_but_dll": "DLL with no exports (suspicious)",
    "section_name_anomaly": "Non-standard section names detected",
}


def _run_die(file_path: str, die_bin: str) -> Optional[dict]:
    """Run Detect-It-Easy (diec) and return parsed result."""
    if not shutil.which(die_bin) and not Path(die_bin).exists():
        return None
    try:
        result = subprocess.run(
            [die_bin, "--json", file_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            detects = data.get("detects", []) or data.get("result", [])
            findings = []
            for d in detects:
                if isinstance(d, dict):
                    t = d.get("type", "")
                    n = d.get("name", "")
                    v = d.get("version", "")
                    findings.append(f"{t}: {n} {v}".strip())
                elif isinstance(d, str):
                    findings.append(d)
            return {"source": "die", "findings": findings, "raw": data}
    except Exception:
        pass
    return None


def _run_upx(file_path: str) -> dict:
    """Test if file is UPX-packed."""
    upx = shutil.which("upx") or shutil.which("upx.exe")
    if not upx:
        return {"upx_packed": False, "upx_note": "upx not found"}
    try:
        result = subprocess.run(
            [upx, "-t", file_path],
            capture_output=True, text=True, timeout=30
        )
        packed = "ok" in result.stdout.lower() or result.returncode == 0
        return {"upx_packed": packed, "upx_output": result.stdout.strip()}
    except Exception:
        return {"upx_packed": False, "upx_note": "upx failed"}


def _heuristic_checks(file_path: str) -> dict:
    """PE-based heuristic packer detection."""
    if not PEFILE_AVAILABLE:
        return {}
    try:
        pe = pefile.PE(file_path)
    except Exception:
        return {}

    findings = []
    details = {}

    # Known packer section names
    section_names = []
    for section in pe.sections:
        try:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            section_names.append(name)
        except Exception:
            pass

    matched_packers = [n for n in section_names if n in KNOWN_PACKER_SECTION_NAMES]
    if matched_packers:
        findings.append(f"Known packer sections: {', '.join(matched_packers)}")
        details["packer_sections"] = matched_packers

    # Anomalous section names (non-standard)
    standard_names = {".text", ".data", ".rdata", ".rsrc", ".reloc", ".bss",
                      ".edata", ".idata", ".pdata", ".tls", ".debug", ".CRT"}
    non_standard = [n for n in section_names if n not in standard_names and n not in KNOWN_PACKER_SECTION_NAMES]
    if non_standard:
        details["non_standard_sections"] = non_standard

    # Entry point in wrong section
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for section in pe.sections:
        if section.VirtualAddress <= ep_rva < section.VirtualAddress + section.Misc_VirtualSize:
            try:
                sec_name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
                flags = section.Characteristics
                if not (flags & 0x20000000):  # not executable
                    findings.append(f"Entry point in non-executable section: {sec_name}")
            except Exception:
                pass
            break

    # Few imports (packed files often minimize imports)
    import_count = 0
    dll_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            import_count += len(entry.imports)

    details["import_count"] = import_count
    details["dll_count"] = dll_count
    if dll_count <= 2 and import_count <= 5:
        findings.append(f"Very few imports: {import_count} from {dll_count} DLLs")

    pe.close()

    return {
        "findings": findings,
        "details": details,
        "suspicious": len(findings) > 0,
    }


def detect_packer(file_path: str, die_bin: str = "diec.exe") -> dict:
    """Run all packer detection methods and combine results."""
    results = {
        "file": file_path,
        "detected_packers": [],
        "suspicious": False,
        "sources": {},
    }

    die_result = _run_die(file_path, die_bin)
    if die_result:
        results["sources"]["die"] = die_result
        results["detected_packers"].extend(die_result.get("findings", []))

    upx_result = _run_upx(file_path)
    results["sources"]["upx"] = upx_result
    if upx_result.get("upx_packed"):
        results["detected_packers"].append("UPX (confirmed by upx -t)")

    heuristic = _heuristic_checks(file_path)
    results["sources"]["heuristics"] = heuristic
    if heuristic.get("findings"):
        results["detected_packers"].extend(heuristic["findings"])

    results["detected_packers"] = list(dict.fromkeys(results["detected_packers"]))
    results["suspicious"] = len(results["detected_packers"]) > 0

    return results
