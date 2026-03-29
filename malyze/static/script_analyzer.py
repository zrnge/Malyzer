"""
Script static analysis — PowerShell, VBScript, JavaScript, Python, Batch, etc.
NO execution. Pure text/pattern analysis + automatic deobfuscation attempts.
"""

import re
import base64
import binascii
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# IOC / suspicious pattern library
# ─────────────────────────────────────────────────────────────────────────────

_PATTERNS = {
    "urls":        re.compile(r"https?://[^\s\"'<>]{4,}", re.I),
    "ips":         re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"),
    "domains":     re.compile(
        r"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|ru|cn|io|tk|pw|cc|biz|xyz|top|onion|ws|info)\b", re.I
    ),
    "emails":      re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"),
    "base64":      re.compile(r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),
    "hex_strings": re.compile(r"(?:0x)?(?:[0-9A-Fa-f]{2}[\s,\\x]?){8,}"),
    "file_paths":  re.compile(r"[A-Za-z]:\\(?:[^\\\n\"'<>:|*?]{1,255}\\)*[^\\\n\"'<>:|*?]{1,255}"),
    "registry":    re.compile(
        r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_CLASSES_ROOT|SOFTWARE|SYSTEM\\CurrentControlSet)"
        r"[\\\/][^\s\"']{3,}", re.I
    ),
    "env_vars":    re.compile(r"%[A-Z_]{2,}%|\$env:[A-Za-z_]\w*|\$[A-Z_]{2,}", re.I),
}

# ── PowerShell ───────────────────────────────────────────────────────────────
_PS_PATTERNS = {
    "encoded_command": re.compile(
        r"-(?:En(?:c(?:odedCommand)?)?|EC)\s+([A-Za-z0-9+/=]{20,})", re.I
    ),
    "base64_decode": re.compile(
        r"\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*[\"']([A-Za-z0-9+/=]+)[\"']", re.I
    ),
    "iex": re.compile(r"\bI(?:nvoke-)?Ex(?:pression)?\b", re.I),
    "download_string": re.compile(r"\.DownloadString\s*\([\"']([^\"']+)[\"']", re.I),
    "download_file":   re.compile(r"\.DownloadFile\s*\([\"']([^\"']+)[\"']", re.I),
    "web_client":      re.compile(r"\bNew-Object\s+(?:System\.)?Net\.WebClient\b", re.I),
    "start_process":   re.compile(r"\bStart-Process\b", re.I),
    "set_content":     re.compile(r"\bSet-Content\b|\bOut-File\b|\bAdd-Content\b", re.I),
    "char_array":      re.compile(r"\[char\]\s*\d{2,3}(?:\s*\+\s*\[char\]\s*\d{2,3}){3,}"),
    "string_join":     re.compile(r"-join\s*[\"']?\s*\(?\s*\[char\]", re.I),
    "amsi_bypass":     re.compile(r"amsi(?:Utils|ScanBuffer|Initialize|Context)|AmsiOpenSession", re.I),
    "reg_exec":        re.compile(r"(?:HKCU|HKLM).*\\Run\b", re.I),
    "invoke_web":      re.compile(r"\bInvoke-WebRequest\b|\bIWR\b|\biwr\b"),
    "reflection":      re.compile(r"\[Reflection\.Assembly\]|::Load\b|::LoadFrom\b", re.I),
    "bypass_execution":re.compile(r"-ExecutionPolicy\s+(?:Bypass|Unrestricted|RemoteSigned)", re.I),
    "hidden_window":   re.compile(r"-WindowStyle\s+Hidden|-NonInteractive|-NoProfile", re.I),
    "wmi":             re.compile(r"\bGet-WmiObject\b|\bInvoke-WmiMethod\b|\bWMI\b", re.I),
    "schtask":         re.compile(r"New-ScheduledTask|Register-ScheduledTask|schtasks", re.I),
    "compress":        re.compile(r"IO\.Compression|GzipStream|DeflateStream", re.I),
}

# ── VBScript ─────────────────────────────────────────────────────────────────
_VBS_PATTERNS = {
    "chr_concat":     re.compile(r"Chr(?:W)?\(\d+\)(?:\s*&\s*Chr(?:W)?\(\d+\)){3,}", re.I),
    "wscript_shell":  re.compile(r"WScript\.Shell|CreateObject\s*\(\s*[\"']WScript\.Shell", re.I),
    "exec":           re.compile(r"\bExecute\b|\bExecuteGlobal\b|\bEval\b", re.I),
    "run_command":    re.compile(r"\.Run\s*\(|\.Exec\s*\(|\.ShellExecute\s*\(", re.I),
    "download":       re.compile(r"MSXML2\.|WinHttp\.|XMLHTTP|GetObject\s*\([\"']winmgmts", re.I),
    "filesys":        re.compile(r"Scripting\.FileSystemObject|ADODB\.Stream", re.I),
    "regwrite":       re.compile(r"\.RegWrite\s*\(", re.I),
    "shell_app":      re.compile(r"Shell\.Application|ShellExecute", re.I),
}

# ── JavaScript ───────────────────────────────────────────────────────────────
_JS_PATTERNS = {
    "eval":           re.compile(r"\beval\s*\(", re.I),
    "unescape":       re.compile(r"\bunescape\s*\(|\bdecodeURIComponent\s*\(", re.I),
    "from_char_code": re.compile(r"String\.fromCharCode\s*\(", re.I),
    "activex":        re.compile(r"ActiveXObject\s*\(\s*[\"'][^\"']+[\"']", re.I),
    "wsh":            re.compile(r"WScript\.Shell|Scripting\.", re.I),
    "xhr":            re.compile(r"XMLHttpRequest|\.open\s*\(\s*[\"'](?:GET|POST)", re.I),
    "write_file":     re.compile(r"\.write\s*\(|\.WriteText\s*\(|ADODB\.Stream", re.I),
    "obfus_concat":   re.compile(r'(?:\'[^\']{0,3}\'\s*\+\s*){5,}|(?:"[^"]{0,3}"\s*\+\s*){5,}'),
}

# ── Python ───────────────────────────────────────────────────────────────────
_PY_PATTERNS = {
    "exec_eval":    re.compile(r"\b(?:exec|eval|compile)\s*\("),
    "b64decode":    re.compile(r"base64\.b64decode|b64decode", re.I),
    "subprocess":   re.compile(r"\bsubprocess\b|\bos\.system\b|\bos\.popen\b"),
    "socket":       re.compile(r"\bsocket\b"),
    "import_dyn":   re.compile(r"\b__import__\s*\("),
    "marshal":      re.compile(r"\bmarshal\b"),
    "ctypes":       re.compile(r"\bctypes\b"),
    "mmap":         re.compile(r"\bmmap\b"),
    "requests_url": re.compile(r"requests\.(get|post|put)\s*\([\"']https?://"),
    "write_file":   re.compile(r"open\s*\([^)]+,\s*[\"']w[\"']"),
}

# ── Batch / CMD ──────────────────────────────────────────────────────────────
_BAT_PATTERNS = {
    "set_concat":   re.compile(r"(?:SET\s+\w+=.*\r?\n){3,}", re.I),
    "ps_call":      re.compile(r"(?:powershell|pwsh)(?:\.exe)?", re.I),
    "certutil":     re.compile(r"\bcertutil\b", re.I),
    "mshta":        re.compile(r"\bmshta(?:\.exe)?\b", re.I),
    "reg_add":      re.compile(r"\breg\s+add\b", re.I),
    "schtasks":     re.compile(r"\bschtasks\b", re.I),
    "bitsadmin":    re.compile(r"\bbitsadmin\b", re.I),
    "curl_wget":    re.compile(r"\b(?:curl|wget)\b", re.I),
    "net_cmd":      re.compile(r"\bnet\s+(?:user|localgroup|share|view)\b", re.I),
    "del_shadow":   re.compile(r"vssadmin.*delete|wmic.*shadowcopy.*delete", re.I),
}

LANG_PATTERNS = {
    "SCRIPT_POWERSHELL": _PS_PATTERNS,
    "SCRIPT_VBS":        _VBS_PATTERNS,
    "SCRIPT_JS":         _JS_PATTERNS,
    "SCRIPT_PYTHON":     _PY_PATTERNS,
    "SCRIPT_BAT":        _BAT_PATTERNS,
}


# ─────────────────────────────────────────────────────────────────────────────
# Deobfuscation helpers
# ─────────────────────────────────────────────────────────────────────────────

def _try_decode_base64(s: str) -> Optional[str]:
    """Try to decode a base64 string and return readable text."""
    try:
        padded = s + "=" * (-len(s) % 4)
        data = base64.b64decode(padded)
        # Try UTF-16LE (PowerShell -EncodedCommand)
        try:
            decoded = data.decode("utf-16-le")
            if decoded.isprintable() or len(decoded) > 10:
                return decoded
        except Exception:
            pass
        # Try UTF-8
        decoded = data.decode("utf-8", errors="replace")
        if sum(1 for c in decoded if c.isprintable()) / max(len(decoded), 1) > 0.7:
            return decoded
    except Exception:
        pass
    return None


def _decode_chr_array(text: str) -> str:
    """Replace Chr(n) sequences with their character equivalents."""
    def replace_chr(m):
        try:
            return chr(int(m.group(1)))
        except Exception:
            return m.group(0)
    return re.sub(r"Chr(?:W)?\((\d+)\)", replace_chr, text, flags=re.I)


def _decode_charcode_array(text: str) -> str:
    """Replace String.fromCharCode(n,...) with actual string."""
    def replace_fc(m):
        try:
            nums = [int(x.strip()) for x in m.group(1).split(",")]
            return "".join(chr(n) for n in nums if 0 <= n < 0x10000)
        except Exception:
            return m.group(0)
    return re.sub(r"String\.fromCharCode\s*\(([^)]+)\)", replace_fc, text, flags=re.I)


def _extract_ps_encoded_commands(text: str) -> list:
    """Find and decode all PowerShell -EncodedCommand payloads."""
    decoded = []
    for m in _PS_PATTERNS["encoded_command"].finditer(text):
        b64 = m.group(1)
        result = _try_decode_base64(b64)
        if result:
            decoded.append({"encoded": b64[:40] + "...", "decoded": result})
    for m in _PS_PATTERNS["base64_decode"].finditer(text):
        b64 = m.group(1)
        result = _try_decode_base64(b64)
        if result:
            decoded.append({"encoded": b64[:40] + "...", "decoded": result})
    return decoded


def _find_all_b64(text: str) -> list:
    """Find all base64-looking strings and try to decode them."""
    results = []
    seen = set()
    for m in _PATTERNS["base64"].finditer(text):
        s = m.group()
        if len(s) < 20 or s in seen:
            continue
        seen.add(s)
        decoded = _try_decode_base64(s)
        if decoded and len(decoded) > 8:
            results.append({"raw": s[:60] + ("..." if len(s) > 60 else ""), "decoded": decoded[:500]})
    return results


def _decode_hex_string(hex_str: str) -> Optional[str]:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", hex_str)
    if len(cleaned) < 8 or len(cleaned) % 2 != 0:
        return None
    try:
        data = bytes.fromhex(cleaned)
        text = data.decode("utf-8", errors="replace")
        if sum(1 for c in text if c.isprintable()) / max(len(text), 1) > 0.6:
            return text
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Main analysis entry point
# ─────────────────────────────────────────────────────────────────────────────

def analyze_script(file_path: str, file_type: str) -> dict:
    """
    Static analysis of a script file. No execution.
    Returns structured findings: iocs, suspicious patterns,
    decoded payloads, obfuscation indicators.
    """
    try:
        raw = Path(file_path).read_bytes()
        # UTF-16 LE/BE only if BOM is present (some PS scripts saved by Windows)
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            enc = "utf-16-le" if raw[:2] == b"\xff\xfe" else "utf-16-be"
            text = raw[2:].decode(enc, errors="replace")
        elif raw[:3] == b"\xef\xbb\xbf":
            text = raw[3:].decode("utf-8", errors="replace")
        else:
            text = raw.decode("utf-8", errors="replace")
    except Exception as e:
        return {"error": str(e)}

    result = {
        "file_type":            file_type,
        "size":                 len(raw),
        "line_count":           text.count("\n"),
        "iocs":                 {},
        "suspicious_patterns":  {},
        "decoded_payloads":     [],
        "obfuscation_score":    0,
        "obfuscation_indicators": [],
        "strings_sample":       [],
        "full_text":            text[:20000],   # for AI analysis
    }

    # ── Global IOC extraction ─────────────────────────────────────────────
    for name, pat in _PATTERNS.items():
        hits = list(dict.fromkeys(pat.findall(text)))[:50]
        if hits:
            result["iocs"][name] = hits

    # ── Language-specific suspicious patterns ────────────────────────────
    lang_pats = LANG_PATTERNS.get(file_type, {})
    for name, pat in lang_pats.items():
        if pat.search(text):
            result["suspicious_patterns"][name] = True

    # ── Deobfuscation ─────────────────────────────────────────────────────
    # PowerShell encoded commands
    if file_type == "SCRIPT_POWERSHELL":
        ps_decoded = _extract_ps_encoded_commands(text)
        if ps_decoded:
            result["decoded_payloads"].extend(ps_decoded)

        # Chr() array decoding
        if "[char]" in text.lower() or "chr(" in text.lower():
            decoded_chr = _decode_chr_array(text)
            if decoded_chr != text:
                # Re-run IOC extraction on decoded content
                for name, pat in _PATTERNS.items():
                    hits = list(dict.fromkeys(pat.findall(decoded_chr)))[:20]
                    if hits:
                        existing = result["iocs"].get(name, [])
                        result["iocs"][name] = list(dict.fromkeys(existing + hits))
                result["decoded_payloads"].append({
                    "type": "chr_array_decode",
                    "decoded": decoded_chr[:2000],
                })

    # JavaScript fromCharCode
    if file_type == "SCRIPT_JS":
        js_decoded = _decode_charcode_array(text)
        if js_decoded != text:
            result["decoded_payloads"].append({
                "type": "fromCharCode_decode",
                "decoded": js_decoded[:2000],
            })

    # All files: find + decode base64 blobs
    b64_hits = _find_all_b64(text)
    if b64_hits:
        result["decoded_payloads"].extend(
            [{"type": "base64_auto", **h} for h in b64_hits[:10]]
        )

    # ── Obfuscation scoring ───────────────────────────────────────────────
    score = 0
    indicators = []

    # Long unbroken strings (obfuscation blobs)
    long_tokens = re.findall(r"[A-Za-z0-9+/=]{80,}", text)
    if long_tokens:
        score += min(len(long_tokens) * 2, 6)
        indicators.append(f"{len(long_tokens)} long opaque string(s) (≥80 chars)")

    # Excessive string concatenation
    concat_count = len(re.findall(r'["\']["\']|"\s*\+\s*"|\'\\s*\+\\s*\'', text))
    if concat_count > 20:
        score += 2
        indicators.append(f"Heavy string concatenation ({concat_count} instances)")

    # Numeric character arrays
    char_count = len(re.findall(r"(?:Chr(?:W)?|fromCharCode)\s*\(\s*\d+\s*\)", text, re.I))
    if char_count > 10:
        score += min(char_count // 5, 4)
        indicators.append(f"Numeric char encoding ({char_count} instances)")

    # Reversed strings
    if re.search(r"[-\w]{10,}\s*\[\s*::\s*-1\s*\]|StrReverse\s*\(", text, re.I):
        score += 2
        indicators.append("String reversal detected")

    # Hex encoding
    hex_blobs = re.findall(r"(?:\\x[0-9A-Fa-f]{2}){6,}|(?:0x[0-9A-Fa-f]{2}[\s,]){6,}", text)
    if hex_blobs:
        score += 2
        indicators.append(f"Hex-encoded sequences ({len(hex_blobs)})")

    # Script with encoded command
    if result["decoded_payloads"]:
        score += 3
        indicators.append(f"{len(result['decoded_payloads'])} decoded payload(s) found")

    result["obfuscation_score"] = score
    result["obfuscation_indicators"] = indicators

    # ── String sample (first 100 lines, filtered) ─────────────────────────
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    result["strings_sample"] = lines[:100]

    return result
