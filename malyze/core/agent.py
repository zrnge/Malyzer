"""
AI Analysis Agent — drives the entire analysis loop.

Flow:
  1. Detect environment + available tools
  2. Identify file type
  3. Ask AI to plan the analysis (which tools, in what order)
  4. Execute each step — if it fails, ask AI for a fallback
  5. Feed all results back to AI for final threat analysis
  6. Return complete structured results
"""

import json
import re
import subprocess
import shutil
import time
import sys
from pathlib import Path
from typing import Optional, Callable

from malyze.core.environment import (
    get_os_info, scan_all_tools, get_available_tools,
    format_env_for_ai, print_missing_tool_recommendations,
)
from malyze.core.file_identifier import identify_file
from malyze.core.tool_registry import CATALOG, get_tool_info


# ─────────────────────────────────────────────────────────────────────────────
# Planner prompt
# ─────────────────────────────────────────────────────────────────────────────

PLANNER_SYSTEM = """You are a malware analysis automation engine.
Your job is to create an ordered analysis plan for a given file.
You MUST respond with ONLY valid JSON — no markdown, no explanation outside JSON.

Return exactly this structure:
{
  "reasoning": "one sentence explaining your choices",
  "steps": [
    {
      "tool_id": "<tool_id from available list>",
      "reason": "why this tool",
      "priority": 1,
      "required": true
    }
  ]
}

Rules:
- Use ONLY tool_ids from the Available Tools list
- Order steps by analysis priority (identification first, then static, then dynamic)
- Mark as required:true only the most critical steps
- If the file type doesn't support a tool, skip it
- Prefer Python-native tools over CLI tools when both exist (more reliable)
- Always include: file_hashes, file_id, entropy
- For PE files always include: pefile, strings_python or floss or strings_cli
- For scripts include: strings_python and relevant script tools
"""

PLANNER_USER_TEMPLATE = """{env_summary}

## Instruction
Create an analysis plan for the file above.
Focus on tools that will reveal: file type, packers, imports/exports, strings,
IOCs (URLs/IPs/domains), suspicious APIs, obfuscation, capabilities.

Available tool IDs (use ONLY these): {available_ids}

File type: {file_type}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Tool runner dispatch
# ─────────────────────────────────────────────────────────────────────────────

def _run_tool(tool_id: str, file_path: str, env_scan: dict, cfg: dict) -> dict:
    """
    Execute a specific tool and return its output.
    Returns: {success, output, error}
    """
    info = env_scan.get(tool_id, {})
    path_or_mod = info.get("path_or_module")

    # ── Builtins ────────────────────────────────────────────────────────────
    if tool_id == "file_hashes":
        from malyze.core.file_identifier import compute_hashes
        return {"success": True, "output": compute_hashes(file_path)}

    if tool_id == "file_id":
        result = identify_file(file_path)
        return {"success": True, "output": {k: v for k, v in result.items() if k != "tools"}}

    if tool_id == "entropy":
        from malyze.static.entropy_analyzer import analyze_file_entropy
        return {"success": True, "output": analyze_file_entropy(file_path)}

    if tool_id == "strings_python":
        from malyze.static.strings_extractor import _extract_python, categorize_strings
        with open(file_path, "rb") as f:
            data = f.read()
        min_len = cfg.get("analysis", {}).get("string_min_length", 4)
        max_s   = cfg.get("analysis", {}).get("max_strings", 5000)
        raw = _extract_python(data, min_len)[:max_s]
        return {"success": True, "output": {
            "source": "python_builtin", "total": len(raw),
            "strings": raw, "iocs": categorize_strings(raw),
        }}

    if tool_id == "script_analysis":
        from malyze.static.script_analyzer import analyze_script
        file_info = identify_file(file_path)
        result = analyze_script(file_path, file_info["type"])
        if result.get("error"):
            return {"success": False, "error": result["error"]}
        return {"success": True, "output": result}

    if tool_id == "pdf_analysis":
        from malyze.static.pdf_analyzer import analyze_pdf
        pdf_parser = env_scan.get("pdf_parser", {}).get("path_or_module")
        result = analyze_pdf(file_path, pdf_parser)
        return {"success": True, "output": result}

    if tool_id == "office_analysis":
        from malyze.static.office_analyzer import analyze_office
        file_info = identify_file(file_path)
        result = analyze_office(file_path, file_info["type"])
        return {"success": True, "output": result}

    # ── Python library tools ──────────────────────────────────────────────
    if tool_id == "pefile":
        from malyze.static.pe_analyzer import analyze_pe
        result = analyze_pe(file_path)
        if result.get("error"):
            return {"success": False, "error": result["error"]}
        return {"success": True, "output": result}

    if tool_id == "capstone":
        from malyze.static.disassembler import disassemble_pe
        result = disassemble_pe(file_path, max_instructions=150)
        if result.get("error"):
            return {"success": False, "error": result["error"]}
        return {"success": True, "output": result}

    if tool_id == "yara_python":
        return _run_yara_python(file_path, cfg)

    if tool_id == "oletools":
        return _run_oletools(file_path)

    if tool_id == "pdfminer":
        return _run_pdfminer(file_path)

    if tool_id == "pyelftools":
        return _run_pyelftools(file_path)

    # ── CLI tools ─────────────────────────────────────────────────────────
    if tool_id == "floss":
        return _run_floss(path_or_mod, file_path)

    if tool_id == "strings_cli":
        min_len = str(cfg.get("analysis", {}).get("string_min_length", 4))
        return _run_cli_capture(path_or_mod, ["-n", min_len, "-a", file_path], timeout=60)

    if tool_id == "die":
        return _run_die(path_or_mod, file_path)

    if tool_id == "upx":
        return _run_cli_capture(path_or_mod, ["-t", file_path], timeout=30)

    if tool_id == "capa":
        return _run_capa(path_or_mod, file_path)

    if tool_id == "yara_cli":
        rules_path = str(Path(__file__).parent.parent.parent / "rules" / "packers.yar")
        return _run_cli_capture(path_or_mod, [rules_path, file_path], timeout=30)

    if tool_id == "exiftool":
        return _run_cli_capture(path_or_mod, ["-json", file_path], timeout=30)

    if tool_id == "binwalk":
        return _run_cli_capture(path_or_mod, ["-B", file_path], timeout=60)

    if tool_id == "readelf":
        return _run_cli_capture(path_or_mod, ["-a", file_path], timeout=30)

    if tool_id == "objdump":
        return _run_cli_capture(path_or_mod, ["-d", "-M", "intel", file_path], timeout=60)

    if tool_id == "pdf_parser":
        return _run_cli_capture(path_or_mod, ["--stats", file_path], timeout=30)

    if tool_id == "oledump":
        return _run_cli_capture(path_or_mod, [file_path], timeout=30)

    return {"success": False, "error": f"No runner implemented for tool '{tool_id}'"}


# ─────────────────────────────────────────────────────────────────────────────
# Tool-specific helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run_cli_capture(bin_path: Optional[str], args: list, timeout: int = 60) -> dict:
    if not bin_path:
        return {"success": False, "error": "Binary path not found"}
    cmd = [bin_path] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                errors="replace")
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0 and not output.strip():
            return {"success": False, "error": f"Exit {result.returncode}: {output[:500]}"}
        return {"success": True, "output": {"text": output, "exit_code": result.returncode}}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Timed out after {timeout}s"}
    except FileNotFoundError:
        return {"success": False, "error": f"Binary not found: {bin_path}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _run_die(bin_path: Optional[str], file_path: str) -> dict:
    if not bin_path:
        return {"success": False, "error": "diec not found"}
    try:
        result = subprocess.run([bin_path, "--json", file_path],
                                capture_output=True, text=True, timeout=60, errors="replace")
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                return {"success": True, "output": data}
            except json.JSONDecodeError:
                pass
        return {"success": True, "output": {"text": result.stdout + result.stderr}}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _run_floss(bin_path: Optional[str], file_path: str) -> dict:
    """
    Run FLOSS trying multiple argument variants so older and newer builds both work.
    Variant order (newest → oldest):
      1. --no-progress -n 6 <file>   (FLOSS 2.x+)
      2. -n 6 <file>                 (any version, no progress flag)
      3. <file>                      (bare minimum)
    If the failure is an argument error we move to the next variant; any other
    error (timeout, file not found, etc.) stops immediately.
    """
    if not bin_path:
        return {"success": False, "error": "floss not found"}

    arg_variants = [
        ["--no-progress", "-n", "6", file_path],
        ["-n", "6", file_path],
        [file_path],
    ]
    _ARG_ERROR_KEYWORDS = ("unrecognized", "invalid option", "error: argument",
                           "usage:", "unknown option")

    last_error = ""
    for args in arg_variants:
        result = _run_cli_capture(bin_path, args, timeout=180)
        if result.get("success"):
            return result
        err = result.get("error", "").lower()
        output_text = result.get("output", {})
        if isinstance(output_text, dict):
            err_full = (err + " " + output_text.get("text", "")).lower()
        else:
            err_full = err
        if any(kw in err_full for kw in _ARG_ERROR_KEYWORDS):
            last_error = result.get("error", err)
            continue  # try next variant
        return result  # real failure — don't retry with different args

    return {"success": False,
            "error": f"All FLOSS argument variants failed. Last: {last_error}"}


def _run_capa(bin_path: Optional[str], file_path: str) -> dict:
    """
    Run CAPA with --json and parse the output into structured capabilities.
    Falls back to plain text if JSON parsing fails.
    Also handles verbose flag for richer output.
    """
    if not bin_path:
        return {"success": False, "error": "capa not found"}

    # Try verbose JSON first; fall back to plain JSON
    for args in (["-v", "--json", file_path], ["--json", file_path]):
        result = _run_cli_capture(bin_path, args, timeout=360)
        if result.get("success"):
            break
    else:
        return result   # type: ignore[return-value]   both variants failed

    raw_text = result.get("output", {}).get("text", "") if isinstance(
        result.get("output"), dict) else ""

    # Locate the JSON object inside the output (CAPA may print log lines before it)
    json_start = raw_text.find("{")
    if json_start < 0:
        return {"success": True, "output": {"text": raw_text, "capabilities": [],
                                            "total_rules_matched": 0}}
    try:
        data = json.loads(raw_text[json_start:])
    except json.JSONDecodeError:
        # Try to extract up to the last closing brace
        json_end = raw_text.rfind("}")
        try:
            data = json.loads(raw_text[json_start:json_end + 1])
        except Exception:
            return {"success": True, "output": {"text": raw_text, "capabilities": [],
                                                "total_rules_matched": 0,
                                                "parse_error": "JSON decode failed"}}

    capabilities = []
    for rule_name, rule_data in data.get("rules", {}).items():
        meta = rule_data.get("meta", {})
        capabilities.append({
            "name":      rule_name,
            "namespace": meta.get("namespace", ""),
            "attack":    meta.get("attack", []),
            "mbc":       meta.get("mbc", []),
            "refs":      meta.get("references", []),
        })

    return {"success": True, "output": {
        "meta":               data.get("meta", {}),
        "capabilities":       capabilities,
        "total_rules_matched": len(capabilities),
    }}


# ─────────────────────────────────────────────────────────────────────────────
# AI syntax advisor — called when a tool fails with an argument error
# ─────────────────────────────────────────────────────────────────────────────

_ARG_ERROR_SIGS = (
    "unrecognized", "invalid option", "error: argument",
    "unknown option", "no such option", "bad option",
)


def _is_argument_error(error_text: str) -> bool:
    low = error_text.lower()
    return any(sig in low for sig in _ARG_ERROR_SIGS)


def _ask_ai_for_tool_syntax(
    tool_id: str,
    bin_path: str,
    file_path: str,
    error_msg: str,
    ollama_host: str,
    model: str,
    timeout: int = 30,
) -> Optional[list]:
    """
    Ask the AI to suggest a corrected argument list for a failing CLI tool.
    Returns a list of string arguments (NOT including the binary itself) or None.
    """
    import requests

    prompt = (
        f"Tool: {tool_id}  Binary: {bin_path}\n"
        f"Error: {error_msg}\n"
        f"File to analyze: {file_path}\n\n"
        "The tool invocation failed with the error above.\n"
        "Respond with ONLY a JSON array of command-line arguments "
        "(do NOT include the binary name itself).\n"
        f'Example: ["-n", "6", "{file_path}"]\n'
        "No explanation, no markdown, just the JSON array."
    )
    payload = {
        "model":   model,
        "messages": [{"role": "user", "content": prompt}],
        "stream":  False,
        "options": {"temperature": 0.0, "num_predict": 256},
    }
    try:
        resp = requests.post(f"{ollama_host}/api/chat", json=payload, timeout=timeout)
        resp.raise_for_status()
        content = resp.json().get("message", {}).get("content", "")
        match = re.search(r"\[[\s\S]*?\]", content)
        if match:
            args = json.loads(match.group())
            if isinstance(args, list) and all(isinstance(a, str) for a in args):
                return args
    except Exception:
        pass
    return None


def _run_yara_python(file_path: str, cfg: dict) -> dict:
    try:
        import yara
        rules_dir = Path(__file__).parent.parent.parent / "rules"
        rule_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
        if not rule_files:
            return {"success": False, "error": "No YARA rule files found in rules/"}
        matches_all = []
        for rf in rule_files:
            try:
                rules = yara.compile(str(rf))
                matches = rules.match(file_path)
                for m in matches:
                    matches_all.append({
                        "rule":       m.rule,
                        "tags":       m.tags,
                        "meta":       m.meta,
                        "rule_file":  rf.name,
                    })
            except Exception as e:
                pass
        return {"success": True, "output": {"matches": matches_all, "total": len(matches_all)}}
    except ImportError:
        return {"success": False, "error": "yara-python not installed"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _run_oletools(file_path: str) -> dict:
    try:
        from oletools.olevba import VBA_Parser
        parser = VBA_Parser(file_path)
        result = {
            "has_macros": parser.detect_vba_macros(),
            "macros": [],
            "iocs": [],
        }
        if result["has_macros"]:
            for (filename, stream_path, vba_filename, vba_code) in parser.extract_macros():
                result["macros"].append({
                    "stream": stream_path,
                    "file":   vba_filename,
                    "code":   vba_code[:3000],
                })
            for t, k, d, c in parser.analyze_macros():
                result["iocs"].append({"type": t, "keyword": k, "description": d})
        return {"success": True, "output": result}
    except ImportError:
        return {"success": False, "error": "oletools not installed: pip install oletools"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _run_pdfminer(file_path: str) -> dict:
    try:
        from pdfminer.high_level import extract_text
        from pdfminer.pdfpage import PDFPage
        import io as _io

        text = extract_text(file_path)
        with open(file_path, "rb") as f:
            pages = list(PDFPage.get_pages(f))

        return {"success": True, "output": {
            "page_count": len(pages),
            "text_sample": text[:3000],
        }}
    except ImportError:
        return {"success": False, "error": "pdfminer.six not installed: pip install pdfminer.six"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _run_pyelftools(file_path: str) -> dict:
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.dynamic import DynamicSection

        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            result = {
                "arch":         elf.get_machine_arch(),
                "entry_point":  hex(elf.header.e_entry),
                "type":         elf.header.e_type,
                "sections":     [],
                "symbols":      [],
                "dynamic_libs": [],
            }
            for sec in elf.iter_sections():
                result["sections"].append({
                    "name": sec.name, "type": sec["sh_type"],
                    "size": sec["sh_size"], "addr": hex(sec["sh_addr"]),
                })
                if isinstance(sec, DynamicSection):
                    for tag in sec.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            result["dynamic_libs"].append(tag.needed)
        return {"success": True, "output": result}
    except ImportError:
        return {"success": False, "error": "pyelftools not installed: pip install pyelftools"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# AI Planner
# ─────────────────────────────────────────────────────────────────────────────

def _ask_ai_for_plan(
    env_summary: str,
    file_type: str,
    available_ids: list,
    ollama_host: str,
    model: str,
    timeout: int = 60,
) -> Optional[dict]:
    """
    Ask Ollama to return a JSON analysis plan.
    Returns parsed plan dict or None on failure.
    """
    import requests

    user_msg = PLANNER_USER_TEMPLATE.format(
        env_summary=env_summary,
        available_ids=json.dumps(available_ids),
        file_type=file_type,
    )
    payload = {
        "model":  model,
        "messages": [
            {"role": "system", "content": PLANNER_SYSTEM},
            {"role": "user",   "content": user_msg},
        ],
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 1024},
    }

    try:
        resp = requests.post(f"{ollama_host}/api/chat", json=payload, timeout=timeout)
        resp.raise_for_status()
        content = resp.json().get("message", {}).get("content", "")

        # Try to parse JSON directly
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # Extract JSON block from markdown code fences or bare text
        match = re.search(r"\{[\s\S]*\}", content)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        return None
    except Exception:
        return None


def _build_fallback_plan(file_type: str, available_ids: list) -> dict:
    """
    Build a precise, file-type-specific analysis plan.
    Each file type gets only the tools that make sense for it.
    """

    # ── PE executables / DLLs / drivers ─────────────────────────────────────
    if file_type in ("PE", "PE_DLL", "PE_DRIVER"):
        ordered = [
            ("file_hashes",   "Compute MD5/SHA1/SHA256 and file size",             True),
            ("file_id",       "Confirm PE type, subtype, magic bytes",             True),
            ("entropy",       "Detect packing/encryption via Shannon entropy",     True),
            ("die",           "Identify compiler, linker, packer (Detect-It-Easy)", True),
            ("upx",           "Confirm/test UPX packing",                          False),
            ("floss",         "Extract obfuscated strings (FLARE FLOSS)",           True),
            ("strings_cli",   "Fast string extraction (Sysinternals strings)",      False),
            ("strings_python","String extraction fallback",                         False),
            ("pefile",        "Parse PE headers, imports, exports, sections",       True),
            ("capstone",      "Disassemble from entry point",                       True),
            ("yara_python",   "Scan against packer/malware YARA rules",             True),
            ("yara_cli",      "YARA CLI scan",                                      False),
            ("capa",          "Detect capabilities: injection, crypto, C2, persist",True),
            ("exiftool",      "Extract rich metadata",                              False),
        ]

    # ── ELF Linux binaries ───────────────────────────────────────────────────
    elif file_type in ("ELF", "ELF_KERNEL"):
        ordered = [
            ("file_hashes",   "Compute hashes",                              True),
            ("file_id",       "Confirm ELF type and architecture",           True),
            ("entropy",       "Detect packing/encryption",                   True),
            ("pyelftools",    "Parse ELF headers, sections, dynamic libs",   True),
            ("readelf",       "readelf -a for full ELF inspection",          False),
            ("strings_python","Extract strings (built-in fallback)",         True),
            ("strings_cli",   "Fast string extraction",                      False),
            ("floss",         "Decode obfuscated strings",                   False),
            ("objdump",       "Disassemble with objdump -d",                 False),
            ("capstone",      "Capstone disassembly",                        True),
            ("yara_python",   "YARA rule scan",                              True),
            ("yara_cli",      "YARA CLI scan",                               False),
            ("binwalk",       "Scan for embedded files or firmware",         False),
        ]

    # ── PowerShell ──────────────────────────────────────────────────────────
    elif file_type == "SCRIPT_POWERSHELL":
        ordered = [
            ("file_hashes",    "Hash the script",                                        True),
            ("file_id",        "Confirm file type",                                      True),
            ("script_analysis","Deobfuscate, decode base64/-EncodedCommand, extract IOCs",True),
            ("yara_python",    "YARA scan for known malicious patterns",                  True),
            ("strings_python", "Additional string extraction",                            False),
            ("yara_cli",       "YARA CLI",                                                False),
            # NOTE: entropy/pefile/capstone are NOT applicable to text scripts
        ]

    # ── VBScript ─────────────────────────────────────────────────────────────
    elif file_type == "SCRIPT_VBS":
        ordered = [
            ("file_hashes",    "Hash the script",                                    True),
            ("file_id",        "Confirm file type",                                  True),
            ("script_analysis","Decode Chr() arrays, detect WScript.Shell, run IOC extraction", True),
            ("strings_python", "Raw string extraction",                               False),
            ("yara_python",    "YARA scan",                                           True),
        ]

    # ── JavaScript ───────────────────────────────────────────────────────────
    elif file_type == "SCRIPT_JS":
        ordered = [
            ("file_hashes",    "Hash the script",                                    True),
            ("file_id",        "Confirm file type",                                  True),
            ("script_analysis","Decode fromCharCode, detect eval/unescape/ActiveX",  True),
            ("strings_python", "Raw string extraction",                               False),
            ("yara_python",    "YARA scan",                                           True),
        ]

    # ── Python scripts ───────────────────────────────────────────────────────
    elif file_type == "SCRIPT_PYTHON":
        ordered = [
            ("file_hashes",    "Hash the script",                                    True),
            ("file_id",        "Confirm file type",                                  True),
            ("script_analysis","Detect exec/eval/base64/subprocess/ctypes patterns", True),
            ("strings_python", "Extract strings",                                    True),
            ("yara_python",    "YARA scan",                                          True),
        ]

    # ── Batch / CMD ─────────────────────────────────────────────────────────
    elif file_type in ("SCRIPT_BAT", "SCRIPT"):
        ordered = [
            ("file_hashes",    "Hash the script",                                    True),
            ("file_id",        "Confirm file type",                                  True),
            ("script_analysis","Detect SET concat, certutil, PowerShell calls",      True),
            ("strings_python", "Extract strings",                                    True),
            ("yara_python",    "YARA scan",                                          True),
        ]

    # ── PDF ──────────────────────────────────────────────────────────────────
    elif file_type == "PDF":
        ordered = [
            ("file_hashes",   "Hash the PDF",                                             True),
            ("file_id",       "Confirm PDF version",                                      True),
            ("pdf_analysis",  "Scan PDF objects: JavaScript, embedded files, auto-actions",True),
            ("pdfminer",      "Extract text content and page count",                      False),
            ("pdf_parser",    "Deep PDF object analysis via pdf-parser CLI",              False),
            ("strings_python","Raw string extraction for IOCs",                           True),
            ("yara_python",   "YARA scan",                                                True),
            ("exiftool",      "Extract PDF metadata (author, creator, timestamps)",       False),
            # entropy is less meaningful for PDF; structure analysis covers it
        ]

    # ── Office OLE (doc/xls/ppt) ─────────────────────────────────────────────
    elif file_type in ("OLE",):
        ordered = [
            ("file_hashes",    "Hash the document",                                  True),
            ("file_id",        "Confirm OLE type",                                   True),
            ("office_analysis","Extract VBA macros, detect suspicious patterns",     True),
            ("oletools",       "Deep OLE analysis via oletools",                     False),
            ("oledump",        "oledump.py stream analysis",                         False),
            ("strings_python", "String extraction",                                  True),
            ("yara_python",    "YARA scan",                                          True),
            ("exiftool",       "Extract document metadata",                          False),
        ]

    # ── OOXML Office (docx/xlsx/pptx) ────────────────────────────────────────
    elif file_type == "ZIP":
        ordered = [
            ("file_hashes",    "Hash the document",                                  True),
            ("file_id",        "Confirm OOXML/ZIP type",                             True),
            ("office_analysis","Inspect OOXML parts, macros, external relationships",True),
            ("oletools",       "VBA macro extraction",                               False),
            ("strings_python", "String extraction from ZIP",                         True),
            ("yara_python",    "YARA scan",                                          True),
            ("exiftool",       "Extract metadata",                                   False),
        ]

    # ── Android APK / JAR ───────────────────────────────────────────────────
    elif file_type in ("ANDROID_APK", "JAVA_JAR"):
        ordered = [
            ("file_hashes",   "Hash the file",                                   True),
            ("file_id",       "Confirm APK/JAR",                                 True),
            ("strings_python","Extract strings from ZIP container",               True),
            ("yara_python",   "YARA scan",                                        True),
            ("binwalk",       "Scan embedded content",                            False),
        ]

    # ── LNK / Shortcut ──────────────────────────────────────────────────────
    elif file_type == "LNK":
        ordered = [
            ("file_hashes",   "Hash the LNK",                           True),
            ("file_id",       "Confirm LNK",                            True),
            ("strings_python","Extract target paths and arguments",      True),
            ("exiftool",      "Parse LNK metadata and target",          False),
            ("yara_python",   "YARA scan",                              True),
        ]

    # ── Unknown / generic binary ─────────────────────────────────────────────
    else:
        ordered = [
            ("file_hashes",   "Hash the file",                          True),
            ("file_id",       "Identify file type",                     True),
            ("entropy",       "Check entropy level",                    True),
            ("strings_python","Extract strings",                        True),
            ("die",           "Detect-It-Easy identification",          False),
            ("yara_python",   "YARA scan",                              True),
            ("binwalk",       "Scan for embedded files",                False),
            ("exiftool",      "Extract metadata",                       False),
        ]

    steps = []
    seen  = set()
    for i, (tid, reason, required) in enumerate(ordered):
        if tid in available_ids and tid not in seen:
            seen.add(tid)
            steps.append({
                "tool_id":  tid,
                "reason":   reason,
                "priority": i + 1,
                "required": required,
            })

    return {
        "reasoning": f"Type-specific plan for {file_type}: {len(steps)} applicable tools",
        "steps": steps,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main Agent
# ─────────────────────────────────────────────────────────────────────────────

class MalyzeAgent:

    def __init__(self, cfg: dict, log_fn: Optional[Callable] = None):
        self.cfg    = cfg
        self.log    = log_fn or (lambda msg, level="info": print(f"[{level.upper()}] {msg}"))
        self.ollama = cfg.get("ollama", {})

    def run(
        self,
        file_path: str,
        analyst_name: str = "Analyst",
        run_dynamic: bool = False,
    ) -> dict:
        import datetime
        from malyze.core.orchestrator import (
            AgenticOrchestrator, DynamicOrchestrator, AnalysisContext
        )

        start = time.time()
        results = {
            "meta": {
                "analyst":   analyst_name,
                "org":       self.cfg.get("analyst", {}).get("org", ""),
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "tool":      "Malyzer v2.0.0",
            },
            "environment": {},
            "file_info":   {},
            "static":      {},
            "dynamic":     None,
            "ai_analysis": {},
            "tool_log":    [],
            "iteration_log": [],
        }

        # ── Step 1/7: OS & Tool Environment ────────────────────────────────
        self.log("=" * 62)
        self.log("Malyzer — AI-Driven Malware Analysis")
        self.log(f"Analyst: {analyst_name}   Sample: {Path(file_path).name}")
        self.log("=" * 62)
        self.log("\n[1/7] Scanning OS and available tools...")

        os_info  = get_os_info()
        env_scan = scan_all_tools(self.cfg)

        static_tools  = [t for t, i in env_scan.items()
                         if i.get("available") and not i.get("dynamic_only")]
        dynamic_tools = [t for t, i in env_scan.items()
                         if i.get("available") and i.get("dynamic_only")]
        miss          = [t for t, i in env_scan.items()
                         if not i.get("available") and not i.get("skip")]

        self.log(f"      OS              : {os_info['system']} {os_info['release']} "
                 f"({os_info['machine']})")
        self.log(f"      Static tools    : {len(static_tools)}")
        self.log(f"      Dynamic tools   : {len(dynamic_tools)}")
        self.log(f"      Missing tools   : {len(miss)}")
        results["environment"] = {
            "os": os_info,
            "static_tools":  static_tools,
            "dynamic_tools": dynamic_tools,
            "missing":       miss,
        }

        # ── Step 2/7: File ID + Threat Intel ───────────────────────────────
        self.log("\n[2/7] Identifying file and querying threat intelligence...")
        file_info = identify_file(file_path)
        results["file_info"] = file_info
        file_type = file_info["type"]

        self.log(f"      Type   : {file_type}  {file_info.get('subtype','')}")
        self.log(f"      SHA256 : {file_info['hashes']['sha256']}")
        self.log(f"      Size   : {file_info['hashes']['size']:,} bytes")

        db_path = str(Path(self.cfg.get("output", {}).get("dir", "./output")) / "samples.db")
        intel_summary = ""
        try:
            from malyze.intel.sample_db import lookup_hash, find_by_imphash
            known = lookup_hash(file_info["hashes"]["sha256"], db_path)
            if known:
                self.log(f"      [DB ] Previously analysed — family: {known.get('malware_family')}, "
                         f"level: {known.get('threat_level')}")
                results["previously_analysed"] = known
                intel_summary += (f"Previously analysed: family={known.get('malware_family')}, "
                                  f"level={known.get('threat_level')}. ")
        except Exception:
            pass

        try:
            from malyze.intel.lookup import enrich_sample
            intel = enrich_sample(file_info["hashes"], self.cfg)
            results["intel"] = intel
            summary = intel.get("_summary", {})
            if summary.get("known_malware"):
                fam = summary.get("consensus_family", "unknown")
                self.log(f"      [INTEL] KNOWN MALWARE — family: {fam}")
                intel_summary += f"Known malware in threat intel: family={fam}. "
            else:
                self.log("      [INTEL] Not found in threat intelligence databases")
        except Exception as exc:
            self.log(f"      [INTEL] Lookup failed: {exc}", "warning")
            results["intel"] = {}

        print_missing_tool_recommendations(env_scan, file_type, self.log)

        # ── Step 3/7: Agentic Static Analysis Loop ─────────────────────────
        self.log("\n[3/7] Starting agentic static analysis loop...")
        self.log(f"      AI will select tools one at a time from {len(static_tools)} "
                 f"available static tools")

        available_ids = [t for t, i in env_scan.items() if i.get("available")]

        ctx = AnalysisContext(
            file_path       = file_path,
            file_type       = file_type,
            file_info       = file_info,
            os_info         = os_info,
            intel_summary   = intel_summary,
            available_tools = available_ids,
        )

        agentic = AgenticOrchestrator(self.cfg, self.log)
        collected, iter_log = agentic.run(ctx)

        results["static"]        = _normalise_static(collected)
        results["iteration_log"] = iter_log
        results["tool_log"]      = [
            {"tool": entry.get("tool"), "status": "ok", "reason": entry.get("reason", "")}
            for entry in iter_log if entry.get("tool")
        ]

        self.log(f"      Static loop complete — {len(iter_log)} iterations, "
                 f"{len(collected)} tools ran")

        # XOR brute force for binary file types
        if file_type in ("PE", "PE_DLL", "PE_DRIVER", "ELF", "ELF_KERNEL", "UNKNOWN"):
            self.log("      Running XOR brute force deobfuscation (1 & 2-byte keys)...")
            try:
                from malyze.static.strings_extractor import xor_brute_force
                xor_result = xor_brute_force(file_path, key_sizes=(1, 2))
                results["static"]["xor_deobfuscation"] = xor_result
                if xor_result.get("found_payloads"):
                    n = len(xor_result.get("candidates", []))
                    self.log(f"      [XOR ] Found {n} promising XOR key candidate(s)")
                else:
                    self.log("      [XOR ] No XOR-obfuscated payload detected")
            except Exception as exc:
                self.log(f"      [XOR ] Brute force failed: {exc}", "warning")

        # Similar sample lookup by imphash
        imphash = results["static"].get("pe", {}).get("imphash")
        if imphash:
            try:
                similar = find_by_imphash(imphash, db_path)
                if similar:
                    results["similar_samples"] = similar
                    self.log(f"      [DB ] Found {len(similar)} similar sample(s) by imphash")
            except Exception:
                pass

        # ── Step 4/7: Tool Inventory Report ────────────────────────────────
        self.log("\n[4/7] Tool inventory and AI reasoning log:")
        for i, entry in enumerate(iter_log, 1):
            tool    = entry.get("tool", "?")
            reason  = entry.get("reason", "")
            outcome = "OK" if entry.get("success") else "FAIL"
            self.log(f"      [{i:02d}] {outcome} {tool} — {reason[:70]}")
        hypotheses = [e.get("hypothesis", "") for e in iter_log if e.get("hypothesis")]
        if hypotheses:
            self.log(f"      Final AI hypothesis: {hypotheses[-1][:120]}")

        # ── Step 5/7: Agentic Dynamic Analysis ─────────────────────────────
        if run_dynamic:
            self.log("\n[5/7] Starting agentic dynamic analysis (SANDBOX ONLY!)...")
            self.log(f"      {len(dynamic_tools)} dynamic tools available: "
                     f"{', '.join(dynamic_tools[:8])}")
            try:
                dyn_orch = DynamicOrchestrator(self.cfg, self.log)
                dyn_result, dyn_log = dyn_orch.run(ctx, file_path)
                results["dynamic"]      = dyn_result
                results["dynamic_log"]  = dyn_log
                self.log(f"      Dynamic loop complete — {len(dyn_log)} iterations")
                results["tool_log"] += [
                    {"tool": e.get("tool"), "status": "dynamic_ok", "reason": e.get("reason", "")}
                    for e in dyn_log if e.get("tool")
                ]
            except Exception as exc:
                self.log(f"      Dynamic analysis failed (pipeline continues): {exc}", "warning")
                results["dynamic"] = {
                    "error": str(exc),
                    "execution": {},
                    "network_activity":        {"available": False},
                    "process_file_registry":   {"available": False},
                }

        # ── Step 6/7: Final AI Synthesis ────────────────────────────────────
        self.log("\n[6/7] AI synthesising all collected data into final report...")
        from malyze.ai.ollama_analyzer import analyze_with_ollama
        host = self.ollama.get("host", "http://localhost:11434")
        if not host or not host.startswith("http"):
            self.log("      AI analysis skipped (no valid Ollama host configured)", "warning")
            results["ai_analysis"] = {"model": "", "analysis": "", "error": "skipped"}
            results["meta"]["duration_seconds"] = round(time.time() - start, 2)
            _post_analysis(results, db_path, self.cfg, self.log)
            return results

        ai_result = analyze_with_ollama(
            analysis_data = results,
            host          = self.ollama.get("host",    "http://localhost:11434"),
            model         = self.ollama.get("model",   "llama3.2"),
            timeout       = self.ollama.get("timeout", 300),
        )
        results["ai_analysis"] = ai_result
        if ai_result.get("error"):
            self.log(f"      AI error: {ai_result['error']}", "warning")
        else:
            self.log(f"      AI synthesis complete ({ai_result.get('completion_tokens',0)} tokens)")
            structured = ai_result.get("structured") or {}
            if structured.get("threat_level"):
                self.log(f"      Threat level : {structured['threat_level']}")
            if structured.get("malware_family"):
                self.log(f"      Family       : {structured['malware_family']}")
            if structured.get("malware_type"):
                self.log(f"      Type         : {structured['malware_type']}")
            if structured.get("confidence"):
                self.log(f"      Confidence   : {structured['confidence']}")

        # ── Step 7/7: Post-Analysis (DB save + auto-YARA) ──────────────────
        self.log("\n[7/7] Saving to database and generating YARA rule...")
        _post_analysis(results, db_path, self.cfg, self.log)

        results["meta"]["duration_seconds"] = round(time.time() - start, 2)
        self.log(f"\n      Total time: {results['meta']['duration_seconds']}s")
        return results


def _get_fallbacks(tool_id: str, available_ids: list) -> list:
    """Return ordered list of fallback tool IDs for a failed tool."""
    fallback_map = {
        "floss":      ["strings_cli", "strings_python"],
        "strings_cli":["strings_python"],
        "die":        ["yara_python", "yara_cli"],
        "yara_cli":   ["yara_python"],
        "capa":       [],
        "capstone":   ["objdump"],
        "objdump":    [],
        "pefile":     [],
        "readelf":    ["pyelftools"],
        "pyelftools": ["readelf"],
    }
    return [f for f in fallback_map.get(tool_id, []) if f in available_ids]


def _normalise_static(collected: dict) -> dict:
    """
    Map arbitrary tool_id keys to the named keys expected by the report generator:
    entropy, strings, pe, packer, disassembly, yara, capa, etc.
    """
    static = {}

    if "entropy" in collected:
        static["entropy"] = collected["entropy"]

    # Strings: prefer floss > strings_cli > strings_python
    for key in ("floss", "strings_cli", "strings_python"):
        if key in collected:
            raw = collected[key]
            if isinstance(raw, dict) and "text" in raw:
                # CLI text output — parse into list
                from malyze.static.strings_extractor import categorize_strings
                lines = [l.strip() for l in raw["text"].splitlines() if l.strip()]
                static["strings"] = {
                    "source": key, "total": len(lines),
                    "strings": lines, "iocs": categorize_strings(lines),
                }
            else:
                static["strings"] = raw
            break

    if "pefile" in collected:
        static["pe"] = collected["pefile"]

    # Packer: die or upx
    packer_data = {"detected_packers": [], "suspicious": False, "sources": {}}
    for key in ("die", "upx"):
        if key in collected:
            raw = collected[key]
            packer_data["sources"][key] = raw
            if key == "die":
                detects = raw.get("detects", []) or []
                for d in detects:
                    name = d.get("name") or str(d)
                    if name:
                        packer_data["detected_packers"].append(name)
            elif key == "upx":
                txt = (raw.get("text") or "")
                if "ok" in txt.lower():
                    packer_data["detected_packers"].append("UPX")
    if packer_data["detected_packers"]:
        packer_data["suspicious"] = True
    if packer_data["sources"]:
        static["packer"] = packer_data

    if "capstone" in collected:
        static["disassembly"] = collected["capstone"]

    if "yara_python" in collected or "yara_cli" in collected:
        static["yara"] = collected.get("yara_python") or collected.get("yara_cli")

    if "capa" in collected:
        raw = collected["capa"]
        # If _run_capa already returned structured output, pass through.
        # If it's raw text (old format or parse failure), normalise it.
        if isinstance(raw, dict) and "capabilities" in raw:
            static["capa"] = raw
        elif isinstance(raw, dict) and "text" in raw:
            # Best-effort: count lines as a proxy for capabilities
            lines = [l.strip() for l in raw["text"].splitlines() if l.strip()]
            static["capa"] = {"text": raw["text"], "capabilities": [],
                               "total_rules_matched": 0,
                               "raw_lines": len(lines)}
        else:
            static["capa"] = raw

    if "exiftool" in collected:
        static["metadata"] = collected["exiftool"]

    if "oletools" in collected:
        static["ole"] = collected["oletools"]

    if "office_analysis" in collected:
        static["office"] = collected["office_analysis"]

    if "pdfminer" in collected:
        static["pdf"] = collected.get("pdf_analysis") or collected["pdfminer"]
    elif "pdf_analysis" in collected:
        static["pdf"] = collected["pdf_analysis"]

    if "script_analysis" in collected:
        static["script"] = collected["script_analysis"]
        # Merge script IOCs into strings.iocs for report
        script_iocs = collected["script_analysis"].get("iocs", {})
        if "strings" not in static:
            static["strings"] = {
                "source": "script_analysis",
                "total":  len(collected["script_analysis"].get("strings_sample", [])),
                "strings": collected["script_analysis"].get("strings_sample", []),
                "iocs":    script_iocs,
            }
        else:
            # Merge IOCs
            existing_iocs = static["strings"].get("iocs", {})
            for cat, items in script_iocs.items():
                existing_iocs[cat] = list(dict.fromkeys(existing_iocs.get(cat, []) + items))
            static["strings"]["iocs"] = existing_iocs

    if "pyelftools" in collected:
        static["elf"] = collected["pyelftools"]

    # Keep raw tool outputs too
    static["_raw"] = collected

    return static


def _post_analysis(results: dict, db_path: str, cfg: dict, log) -> None:
    """
    Run after AI analysis completes:
      1. Save sample to local database.
      2. Generate YARA rule if sample is HIGH or CRITICAL.
    """
    # Save to sample DB
    try:
        from malyze.intel.sample_db import save_sample
        saved = save_sample(results, db_path)
        if saved:
            log("      [DB ] Sample saved to local database")
    except Exception as exc:
        log(f"      [DB ] Could not save to database: {exc}", "warning")

    # Auto-generate YARA rule for HIGH / CRITICAL samples
    try:
        from malyze.report.generator import _threat_level
        from malyze.static.yara_generator import save_yara_rule

        level, _, _ = _threat_level(results)
        if level in ("HIGH", "CRITICAL"):
            sha256 = results.get("file_info", {}).get("hashes", {}).get("sha256", "unknown")
            out_dir = Path(cfg.get("output", {}).get("dir", "./output")) / "yara_rules"
            yara_path = str(out_dir / f"{sha256[:16]}.yar")
            saved_path = save_yara_rule(results, yara_path)
            if saved_path:
                log(f"      [YARA] Auto-generated hunting rule: {saved_path}")
    except Exception as exc:
        log(f"      [YARA] Rule generation failed: {exc}", "warning")
