"""
PDF static analysis — extract objects, JavaScript, embedded files, URLs, metadata.
Uses pdfminer.six (Python) and pdf-parser CLI if available.
No execution required.
"""

import re
import subprocess
import shutil
from pathlib import Path
from typing import Optional


# Known suspicious PDF keywords (malicious PDFs often use these)
SUSPICIOUS_KEYWORDS = [
    "/JS", "/JavaScript", "/AA", "/OpenAction", "/AcroForm",
    "/RichMedia", "/Launch", "/EmbeddedFile", "/XFA", "/URI",
    "/SubmitForm", "/ImportData", "/GoToE", "/Sound", "/Movie",
]

URL_PATTERN = re.compile(r"https?://[^\s\x00-\x1f\"'<>]{4,}", re.I)
IP_PATTERN  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")


def _run_pdf_parser_cli(bin_path: str, file_path: str) -> Optional[str]:
    if not bin_path:
        return None
    try:
        result = subprocess.run(
            [bin_path, "--stats", file_path],
            capture_output=True, text=True, timeout=30, errors="replace"
        )
        return result.stdout + result.stderr
    except Exception:
        return None


def _analyze_with_pdfminer(file_path: str) -> dict:
    try:
        from pdfminer.high_level import extract_text
        from pdfminer.pdfpage import PDFPage
        from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
        from pdfminer.converter import PDFPageAggregator
        from pdfminer.layout import LAParams

        with open(file_path, "rb") as f:
            pages = list(PDFPage.get_pages(f))

        text = extract_text(file_path) or ""
        return {
            "available": True,
            "page_count": len(pages),
            "extracted_text": text[:5000],
            "text_length": len(text),
        }
    except ImportError:
        return {"available": False, "error": "pdfminer.six not installed: pip install pdfminer.six"}
    except Exception as e:
        return {"available": False, "error": str(e)}


def _analyze_raw_structure(file_path: str) -> dict:
    """
    Read raw PDF bytes and scan for suspicious keywords, URLs, embedded JS.
    Works without any external dependency.
    """
    try:
        raw = Path(file_path).read_bytes()
        text = raw.decode("latin-1", errors="replace")
    except Exception as e:
        return {"error": str(e)}

    found_keywords = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.encode("latin-1") in raw or kw in text:
            found_keywords.append(kw)

    urls  = list(dict.fromkeys(URL_PATTERN.findall(text)))[:50]
    ips   = list(dict.fromkeys(IP_PATTERN.findall(text)))[:20]

    # Count objects
    obj_count = len(re.findall(r"\d+\s+\d+\s+obj", text))

    # Check for embedded JavaScript
    js_blocks = re.findall(r"/(?:JS|JavaScript)\s*\(([^)]{0,500})", text)
    js_streams = re.findall(r"<</[^>]*(?:JS|JavaScript)[^>]*>>", text)

    # Check for embedded files
    embedded = len(re.findall(r"/EmbeddedFile", text))

    # Check for AA (automatic actions)
    auto_actions = len(re.findall(r"/(?:AA|OpenAction|AcroForm)", text))

    # Version
    version_m = re.search(r"%PDF-(\d+\.\d+)", text)
    version = version_m.group(1) if version_m else "unknown"

    return {
        "pdf_version":       version,
        "object_count":      obj_count,
        "suspicious_keywords": found_keywords,
        "javascript_blocks": len(js_blocks) + len(js_streams),
        "js_samples":        [j[:200] for j in js_blocks[:3]],
        "embedded_files":    embedded,
        "auto_actions":      auto_actions,
        "urls":              urls,
        "ips":               ips,
        "suspicious":        len(found_keywords) > 0 or len(js_blocks) > 0,
    }


def analyze_pdf(file_path: str, pdf_parser_bin: Optional[str] = None) -> dict:
    """
    Full static PDF analysis.
    """
    result = {
        "raw_structure": _analyze_raw_structure(file_path),
        "pdfminer":      _analyze_with_pdfminer(file_path),
        "pdf_parser":    {},
    }

    if pdf_parser_bin:
        cli_out = _run_pdf_parser_cli(pdf_parser_bin, file_path)
        if cli_out:
            result["pdf_parser"] = {"output": cli_out[:3000]}

    # Aggregate suspicion
    raw = result["raw_structure"]
    result["summary"] = {
        "suspicious":          raw.get("suspicious", False),
        "has_javascript":      raw.get("javascript_blocks", 0) > 0,
        "has_embedded_files":  raw.get("embedded_files", 0) > 0,
        "has_auto_actions":    raw.get("auto_actions", 0) > 0,
        "suspicious_keywords": raw.get("suspicious_keywords", []),
        "urls":                raw.get("urls", []),
        "ips":                 raw.get("ips", []),
        "page_count":          result["pdfminer"].get("page_count", "N/A"),
    }

    return result
