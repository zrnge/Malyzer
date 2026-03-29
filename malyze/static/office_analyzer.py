"""
Office document static analysis — OLE, OOXML (docx/xlsx/pptx), RTF.
Focuses on macros, embedded objects, suspicious streams.
No execution.
"""

import re
import zipfile
from pathlib import Path
from typing import Optional


URL_PATTERN = re.compile(r"https?://[^\s\"'<>]{4,}", re.I)
IP_PATTERN  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

MACRO_SUSPICIOUS = [
    "Shell", "WScript", "CreateObject", "GetObject", "environ",
    "Chr(", "ChrW(", "Asc(", "Execute", "ExecuteGlobal",
    "Open", "Write", "SaveToFile", "ADODB.Stream",
    "powershell", "cmd.exe", "mshta", "rundll32",
    "URLDownloadToFile", "WinHttpRequest", "XMLHTTP",
    "AutoOpen", "AutoExec", "Document_Open", "Workbook_Open",
    "Shell.Application", "regwrite", "Run(",
]


def _analyze_with_oletools(file_path: str) -> dict:
    try:
        from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML

        parser = VBA_Parser(file_path)
        result = {
            "available":  True,
            "has_macros": parser.detect_vba_macros(),
            "type":       str(parser.type),
            "macros":     [],
            "iocs":       [],
            "suspicious_keywords": [],
        }

        if result["has_macros"]:
            for (filename, stream_path, vba_filename, vba_code) in parser.extract_macros():
                macro_entry = {
                    "stream":   str(stream_path),
                    "filename": str(vba_filename),
                    "code":     vba_code[:5000],
                    "suspicious_hits": [],
                    "urls": list(dict.fromkeys(URL_PATTERN.findall(vba_code)))[:20],
                }
                for kw in MACRO_SUSPICIOUS:
                    if kw.lower() in vba_code.lower():
                        macro_entry["suspicious_hits"].append(kw)
                result["macros"].append(macro_entry)

            # Auto-analysis
            for kw_type, keyword, description, _count in parser.analyze_macros():
                result["iocs"].append({
                    "type":        str(kw_type),
                    "keyword":     str(keyword),
                    "description": str(description),
                })
                if kw_type in ("Suspicious", "IOC", "AutoExec"):
                    result["suspicious_keywords"].append(str(keyword))

        parser.close()
        return result

    except ImportError:
        return {
            "available": False,
            "error": "oletools not installed: pip install oletools",
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


def _analyze_ooxml(file_path: str) -> dict:
    """Inspect OOXML (docx/xlsx/pptx) ZIP structure without oletools."""
    try:
        if not zipfile.is_zipfile(file_path):
            return {"available": False, "error": "Not a ZIP/OOXML file"}

        result = {
            "available":       True,
            "parts":           [],
            "relationships":   [],
            "external_urls":   [],
            "embedded_objects": [],
            "macros_present":  False,
        }

        with zipfile.ZipFile(file_path, "r") as zf:
            names = zf.namelist()
            result["parts"] = names

            # Check for macro parts
            macro_exts = [".bin", ".bas", ".cls", ".frm", ".vba"]
            for name in names:
                if any(name.lower().endswith(e) for e in macro_exts) or \
                   "vbaProject" in name or "macro" in name.lower():
                    result["macros_present"] = True

            # Scan relationships for external references
            for name in names:
                if name.endswith(".rels"):
                    try:
                        content = zf.read(name).decode("utf-8", errors="replace")
                        urls = URL_PATTERN.findall(content)
                        result["external_urls"].extend(urls)
                        # Template injection targets
                        if 'TargetMode="External"' in content:
                            targets = re.findall(r'Target="([^"]+)"', content)
                            result["relationships"].extend(targets)
                    except Exception:
                        pass

            # Check for embedded OLE objects
            for name in names:
                if "embeddings" in name.lower() or name.endswith(".bin"):
                    result["embedded_objects"].append(name)

        result["external_urls"] = list(dict.fromkeys(result["external_urls"]))[:30]
        result["relationships"] = list(dict.fromkeys(result["relationships"]))[:20]
        return result

    except Exception as e:
        return {"available": False, "error": str(e)}


def _analyze_rtf(file_path: str) -> dict:
    """Basic RTF analysis — look for OLE embedded objects and suspicious patterns."""
    try:
        raw  = Path(file_path).read_bytes()
        text = raw.decode("latin-1", errors="replace")

        result = {
            "available":       True,
            "object_count":    len(re.findall(r"\\objdata|\\object", text)),
            "has_ole_objects": bool(re.search(r"\\objdata", text)),
            "has_equation":    bool(re.search(r"\\objclass Equation", text, re.I)),
            "urls":            list(dict.fromkeys(URL_PATTERN.findall(text)))[:20],
            "hex_data_size":   len(re.findall(r"[0-9a-fA-F]{2}", text)),
        }
        # CVE-2017-11882 indicator: Equation Editor object
        if result["has_equation"]:
            result["cve_indicator"] = "CVE-2017-11882 (Equation Editor RCE) possible"

        return result
    except Exception as e:
        return {"available": False, "error": str(e)}


def analyze_office(file_path: str, file_type: str) -> dict:
    """
    Full static office document analysis.
    file_type: OLE | ZIP (docx/xlsx/pptx) | RTF
    """
    result = {
        "file_type": file_type,
        "oletools":  _analyze_with_oletools(file_path),
    }

    ext = Path(file_path).suffix.lower()

    if file_type == "RTF" or ext == ".rtf":
        result["rtf"] = _analyze_rtf(file_path)
    elif file_type == "ZIP" or ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm"):
        result["ooxml"] = _analyze_ooxml(file_path)

    # Summary
    ole = result["oletools"]
    ooxml = result.get("ooxml", {})
    rtf   = result.get("rtf", {})

    result["summary"] = {
        "has_macros":        ole.get("has_macros", False) or ooxml.get("macros_present", False),
        "suspicious_macros": bool(ole.get("suspicious_keywords")),
        "external_urls":     (ole.get("macros", [{}])[0].get("urls", []) if ole.get("macros") else []) +
                             ooxml.get("external_urls", []),
        "embedded_objects":  ooxml.get("embedded_objects", []),
        "has_ole_objects":   rtf.get("has_ole_objects", False),
        "cve_indicators":    [rtf["cve_indicator"]] if rtf.get("cve_indicator") else [],
        "ioc_count":         len(ole.get("iocs", [])),
    }

    return result
