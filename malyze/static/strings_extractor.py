"""String extraction — wraps FLOSS/strings CLI with Python fallback."""

import re
import subprocess
import shutil
from pathlib import Path
from typing import Optional
import urllib.parse


# Patterns for IOC categorization
# NOTE: base64 requires proper padding (= or ==) to reduce false positives.
#       mutex requires the Global\ or Local\ namespace prefix — bare identifiers
#       are too ambiguous to be useful as IOCs.
PATTERNS = {
    "urls":       re.compile(r"https?://[^\s\"'<>]{4,}", re.IGNORECASE),
    "ips":        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b"),
    "domains":    re.compile(r"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|ru|cn|io|tk|pw|cc|biz|info|xyz|top|club|site)\b", re.IGNORECASE),
    "emails":     re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "registry":   re.compile(r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_CLASSES_ROOT|HKEY_USERS|SOFTWARE|SYSTEM\\CurrentControlSet)[\\\/][^\s\"']{3,}", re.IGNORECASE),
    "file_paths": re.compile(r"(?:[A-Za-z]:\\|/(?:tmp|var|etc|usr|home)/)[^\s\"'<>:*?|]{3,}"),
    "api_calls":  re.compile(r"\b(?:CreateProcess|VirtualAlloc|WriteProcessMemory|CreateThread|LoadLibrary|GetProcAddress|RegOpenKey|RegSetValue|WinExec|ShellExecute|InternetOpen|HttpSendRequest|connect|recv|send|WSAStartup|CreateService|OpenSCManager|NtCreateFile|ZwCreateFile|NtAllocateVirtualMemory|RtlDecompressBuffer|CryptDecrypt|CryptEncrypt)[A-Za-z]*\b"),
    "crypto_keys": re.compile(r"[A-Fa-f0-9]{32,}"),
    # Require proper base64 padding (= or ==) so bare hex/alphanumeric strings
    # don't flood the IOC list. Minimum 24 chars before padding.
    "base64":     re.compile(r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)"),
    # Only match named mutex objects with an explicit Win32 namespace prefix.
    "mutex":      re.compile(r"\b(?:Global|Local)\\[A-Za-z0-9_\-\.]{4,64}\b"),
}

SUSPICIOUS_KEYWORDS = [
    "cmd.exe", "powershell", "wscript", "cscript", "regsvr32", "rundll32",
    "mshta", "certutil", "bitsadmin", "schtasks", "taskschd", "at.exe",
    "net user", "net localgroup", "whoami", "ipconfig", "nslookup",
    "mimikatz", "sekurlsa", "lsass", "sam", "ntdll", "ntoskrnl",
    "inject", "shellcode", "exploit", "payload", "reverse", "backdoor",
    "keylog", "screenshot", "exfil", "ransom", "encrypt", "decrypt",
    "bitcoin", "wallet", "tor", ".onion", "c2", "command and control",
]


def _extract_python(data: bytes, min_len: int = 4) -> list:
    """Pure Python string extraction (ASCII + Unicode)."""
    ascii_pat  = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
    uni_pat    = re.compile(rb"(?:[ -~]\x00){" + str(min_len).encode() + rb",}")
    strings = []
    for m in ascii_pat.finditer(data):
        strings.append(m.group().decode("ascii", errors="replace"))
    for m in uni_pat.finditer(data):
        try:
            s = m.group().decode("utf-16-le", errors="replace").rstrip("\x00")
            if len(s) >= min_len:
                strings.append(s)
        except Exception:
            pass
    return list(dict.fromkeys(strings))  # deduplicate, preserve order


def _run_floss(file_path: str, floss_bin: str) -> Optional[list]:
    if not shutil.which(floss_bin) and not Path(floss_bin).exists():
        return None
    try:
        result = subprocess.run(
            [floss_bin, "--no-progress", file_path],
            capture_output=True, text=True, timeout=120
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return lines
    except Exception:
        return None


def _run_strings(file_path: str, strings_bin: str, min_len: int) -> Optional[list]:
    if not shutil.which(strings_bin) and not Path(strings_bin).exists():
        return None
    try:
        result = subprocess.run(
            [strings_bin, "-n", str(min_len), "-a", file_path],
            capture_output=True, text=True, timeout=60
        )
        return [l.strip() for l in result.stdout.splitlines() if l.strip()]
    except Exception:
        return None


def categorize_strings(strings: list) -> dict:
    text = "\n".join(strings)
    cats = {}
    for name, pat in PATTERNS.items():
        found = list(dict.fromkeys(pat.findall(text)))[:100]
        if found:
            cats[name] = found

    # Suspicious keyword hits
    lower_text = text.lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw.lower() in lower_text]
    if hits:
        cats["suspicious_keywords"] = hits

    return cats


def extract_strings(
    file_path: str,
    min_len: int = 4,
    max_strings: int = 5000,
    floss_bin: str = "floss.exe",
    strings_bin: str = "strings64.exe",
) -> dict:
    """
    Try FLOSS first (decodes obfuscated strings), then strings.exe, then Python fallback.
    """
    source = "python_fallback"
    raw_strings = None

    raw_strings = _run_floss(file_path, floss_bin)
    if raw_strings:
        source = "floss"
    else:
        raw_strings = _run_strings(file_path, strings_bin, min_len)
        if raw_strings:
            source = "strings_exe"

    if raw_strings is None:
        with open(file_path, "rb") as f:
            data = f.read()
        raw_strings = _extract_python(data, min_len)

    raw_strings = raw_strings[:max_strings]
    categories = categorize_strings(raw_strings)

    return {
        "source": source,
        "total": len(raw_strings),
        "strings": raw_strings,
        "iocs": categories,
    }


# ── XOR Brute Force ───────────────────────────────────────────────────────────

# Common high-value strings found in malware — used to validate XOR key candidates
_XOR_ANCHOR_STRINGS = [
    b"http", b"https", b"cmd.exe", b"powershell", b"CreateProcess",
    b"VirtualAlloc", b"LoadLibrary", b"GetProcAddress", b"WinExec",
    b"regsvr32", b"rundll32", b"schtasks", b"software\\microsoft",
    b"mimikatz", b"kernel32", b".exe", b".dll", b"connect",
]

_XOR_MIN_PLAINTEXT_LEN = 6
_XOR_SUSPICIOUS_KEYWORDS = [kw.lower() for kw in SUSPICIOUS_KEYWORDS]


def xor_brute_force(
    file_path: str,
    key_sizes: tuple = (1, 2, 4),
    max_file_bytes: int = 2 * 1024 * 1024,  # 2 MB cap
) -> dict:
    """
    Brute-force common XOR key sizes (1, 2, 4 bytes) over the binary.
    Returns decoded strings for any key that yields high-value plaintext.

    This catches the most prevalent malware obfuscation technique that FLOSS
    does not handle (single/multi-byte rolling XOR without stack-string patterns).
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read(max_file_bytes)
    except Exception as e:
        return {"error": str(e), "candidates": []}

    candidates = []
    tested_keys: set = set()

    for key_size in key_sizes:
        key_space = 256 ** key_size
        for raw_key in range(1, min(key_space, 256 if key_size == 1 else 65536)):
            # Build the key bytes
            key_bytes = raw_key.to_bytes(key_size, "little")

            # XOR decode
            decoded = bytearray(len(data))
            for i, b in enumerate(data):
                decoded[i] = b ^ key_bytes[i % key_size]
            decoded_bytes = bytes(decoded)

            # Quick anchor check — must hit at least one anchor string
            low = decoded_bytes.lower()
            anchor_hits = sum(1 for anchor in _XOR_ANCHOR_STRINGS if anchor in low)
            if anchor_hits < 2:
                continue

            key_hex = key_bytes.hex()
            if key_hex in tested_keys:
                continue
            tested_keys.add(key_hex)

            # Extract readable strings from decoded data
            strings = _extract_python(decoded_bytes, _XOR_MIN_PLAINTEXT_LEN)[:200]
            iocs = categorize_strings(strings)

            # Score the result: more suspicious keywords = more likely real
            all_text = " ".join(strings).lower()
            score = sum(1 for kw in _XOR_SUSPICIOUS_KEYWORDS if kw in all_text)
            score += anchor_hits * 2

            candidates.append({
                "key_hex":    key_hex,
                "key_size":   key_size,
                "score":      score,
                "strings":    strings[:50],
                "iocs":       iocs,
                "anchor_hits": anchor_hits,
            })

    # Sort by score descending, return top 5 candidates
    candidates.sort(key=lambda x: x["score"], reverse=True)
    return {
        "candidates":    candidates[:5],
        "keys_tested":   len(tested_keys),
        "found_payloads": len(candidates) > 0,
    }
