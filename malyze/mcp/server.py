"""MCP Server — exposes all Malyze analysis tools via Model Context Protocol."""

import json
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    raise SystemExit("mcp package not installed. Run: pip install mcp[cli]")

import yaml
from malyze.core.file_identifier import identify_file
from malyze.static.entropy_analyzer import analyze_file_entropy
from malyze.static.strings_extractor import extract_strings
from malyze.static.pe_analyzer import analyze_pe
from malyze.static.packer_detector import detect_packer
from malyze.static.disassembler import disassemble_pe
from malyze.ai.ollama_analyzer import analyze_with_ollama
from malyze.core.workflow import AnalysisWorkflow, load_config
from malyze.report.generator import generate_report


# Load config
_config_path = Path(__file__).parent.parent.parent / "config.yaml"
_cfg = load_config(str(_config_path))

mcp = FastMCP(
    "Malyze",
    description="AI-powered malware analysis framework for FlareVM. "
                "Provides static analysis, dynamic analysis, AI-powered threat intelligence, and report generation.",
)


# ─────────────────────────────────────────────────────────────────────────────
# Tool: identify_file
# ─────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def identify_sample(file_path: str) -> str:
    """
    Identify the type of a file (PE, ELF, script, PDF, OLE, etc.) and compute
    cryptographic hashes (MD5, SHA1, SHA256). Returns the file type and the
    list of analysis tools recommended for this file type.

    Args:
        file_path: Absolute path to the file to identify.
    """
    if not Path(file_path).exists():
        return json.dumps({"error": f"File not found: {file_path}"})
    result = identify_file(file_path)
    return json.dumps(result, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Tool: analyze_entropy
# ─────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def analyze_entropy(file_path: str) -> str:
    """
    Calculate the Shannon entropy of a file to detect packing, encryption,
    or obfuscation. Returns overall entropy, per-block entropy, and a
    classification (Low / Medium / High / Very High).

    Args:
        file_path: Absolute path to the file to analyze.
    """
    if not Path(file_path).exists():
        return json.dumps({"error": f"File not found: {file_path}"})
    return json.dumps(analyze_file_entropy(file_path), indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Tool: extract_strings
# ─────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def extract_file_strings(
    file_path: str,
    min_length: int = 4,
    max_strings: int = 5000,
) -> str:
    """
    Extract printable ASCII and Unicode strings from a binary file.
    Uses FLOSS (if available) to also decode obfuscated strings, then falls back
    to strings.exe or a pure-Python extractor. Automatically categorizes IOCs:
    URLs, IPs, domains, registry keys, API calls, suspicious keywords, Base64, etc.

    Args:
        file_path:   Absolute path to the file.
        min_length:  Minimum string length to include (default 4).
        max_strings: Maximum number of strings to return (default 5000).
    """
    if not Path(file_path).exists():
        return json.dumps({"error": f"File not found: {file_path}"})
    result = extract_strings(
        file_path,
        min_len=min_length,
        max_strings=max_strings,
        floss_bin=_cfg["flarevm"].get("floss", "floss.exe"),
        strings_bin=_cfg["flarevm"].get("strings", "strings64.exe"),
    )
    return json.dumps(result, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Tool: analyze_pe_file
# ─────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def analyze_pe_file(file_path: str) -> str:
    """
    Deep static analysis of a PE (Portable Executable) file. Extracts:
    - DOS/NT headers (machine type, timestamp, subsystem, entry point, image base)
    - Sections with entropy and flags
    - Import table with suspicious API flagging
    - Export table
    - Resources
    - Overlay data
    - TLS callbacks, digital signature presence

    Args:
        file_path: Absolute path to the PE file (.exe, .dll, .sys, etc.).
    """
    if not Path(file_path).exists():
        return json.dumps({"error": f"File not found: {file_path}"})
    result = analyze_pe(file_path)
    return json.dumps(result, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Tool: detect_packer
# ─────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def detect_file_packer(file_path: str) -> str:
    """
    Detect packers, protectors, and obfuscators applied to a PE file.
    Runs Detect-It-Easy (diec), UPX test, and heuristic checks
    (known packer section names, entry point anomalies, import count anomalies).

    Args:
        file_path: Absolute path to the PE file.
    """
    if not Path(file_path).exists():
        return json.dumps({"error": f"File not found: {file_path}"})
    result = detect_packer(
        file_path,
        die_bin=_cfg["flarevm"].get("die", "diec.exe"),
    )
    return json.dumps(result, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Tool: disassemble_file
# ─────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def disassemble_file(file_path: str, max_instructions: int = 200) -> str:
    """
    Disassemble a PE file from its entry point using Capstone.
    Supports x86 (32-bit) and x64 (64-bit) architectures.
    Returns structured output with address, mnemonic, operands, and raw bytes.

    Args:
        file_path:        Absolute path to the PE file.
        max_instructions: Maximum number of instructions to disassemble (default 200).
    """
    if not Path(file_path).exists():
        return json.dumps({"error": f"File not found: {file_path}"})
    result = disassemble_pe(file_path, max_instructions=max_instructions)
    return json.dumps(result, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Tool: full_static_analysis
# ─────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def full_static_analysis(file_path: str) -> str:
    """
    Run ALL static analysis on a file: identification, hashes, entropy,
    strings/IOC extraction, PE headers, packer detection, and disassembly.
    Returns a comprehensive JSON object with all findings.

    Args:
        file_path: Absolute path to the sample file.
    """
    if not Path(file_path).exists():
        return json.dumps({"error": f"File not found: {file_path}"})

    file_info = identify_file(file_path)
    tools = set(file_info["tools"])
    result = {"file_info": file_info, "static": {}}

    if "entropy" in tools:
        result["static"]["entropy"] = analyze_file_entropy(file_path)

    if "strings" in tools or "floss" in tools:
        result["static"]["strings"] = extract_strings(
            file_path,
            min_len=_cfg["analysis"]["string_min_length"],
            max_strings=_cfg["analysis"]["max_strings"],
            floss_bin=_cfg["flarevm"].get("floss", "floss.exe"),
            strings_bin=_cfg["flarevm"].get("strings", "strings64.exe"),
        )

    if any(t in tools for t in ["pe_headers", "pe_imports", "pe_exports", "pe_sections"]):
        result["static"]["pe"] = analyze_pe(file_path)

    if "packer_detect" in tools or "die" in tools:
        result["static"]["packer"] = detect_packer(
            file_path, die_bin=_cfg["flarevm"].get("die", "diec.exe")
        )

    if "disassemble" in tools:
        result["static"]["disassembly"] = disassemble_pe(file_path, max_instructions=150)

    return json.dumps(result, indent=2, default=str)


# ─────────────────────────────────────────────────────────────────────────────
# Tool: ai_analyze
# ─────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def ai_analyze(analysis_json: str, model: str = "") -> str:
    """
    Send collected analysis data to the local Ollama AI model for threat
    intelligence analysis. Produces: malware classification, MITRE ATT&CK TTPs,
    threat level, IOCs, evasion techniques, and detection recommendations.

    Args:
        analysis_json: JSON string of analysis data (output from full_static_analysis).
        model:         Ollama model name to use (default from config, e.g. 'llama3.2').
    """
    try:
        analysis_data = json.loads(analysis_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON: {e}"})

    ollama_cfg = _cfg.get("ollama", {})
    result = analyze_with_ollama(
        analysis_data=analysis_data,
        host=ollama_cfg.get("host", "http://localhost:11434"),
        model=model or ollama_cfg.get("model", "llama3.2"),
        timeout=ollama_cfg.get("timeout", 300),
    )
    return json.dumps(result, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Tool: generate_analysis_report
# ─────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def generate_analysis_report(
    analysis_json: str,
    output_path: str = "",
) -> str:
    """
    Generate a professional HTML malware analysis report from analysis data.
    The report includes threat level, file info, AI analysis, entropy, PE headers,
    suspicious imports, IOCs, disassembly, and dynamic analysis (if available).

    Args:
        analysis_json: JSON string of the full analysis data.
        output_path:   Output file path for the HTML report. If empty, saves to ./output/.
    """
    try:
        analysis_data = json.loads(analysis_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON: {e}"})

    if not output_path:
        out_dir = Path(_cfg.get("output", {}).get("dir", "./output"))
        out_dir.mkdir(parents=True, exist_ok=True)
        name = analysis_data.get("file_info", {}).get("name", "sample")
        output_path = str(out_dir / f"{name}_report.html")

    path = generate_report(analysis_data, output_path)
    return json.dumps({"report_path": path, "success": True})


# ─────────────────────────────────────────────────────────────────────────────
# Tool: full_analysis_pipeline
# ─────────────────────────────────────────────────────────────────────────────
@mcp.tool()
def full_analysis_pipeline(
    file_path: str,
    analyst_name: str = "",
    run_dynamic: bool = False,
    output_dir: str = "",
    report_format: str = "all",
) -> str:
    """
    Run the COMPLETE AI-driven Malyze analysis pipeline on a sample:
    1. Detect environment and available tools
    2. Identify file type
    3. AI plans the analysis (selects best tools for the file type)
    4. Execute each tool — auto-fallback on failure, recommendations for missing tools
    5. AI threat analysis via Ollama
    6. Generate reports (HTML + PDF + DOCX + JSON by default)

    Returns paths to generated reports and a summary of findings.

    Args:
        file_path:     Absolute path to the malware sample.
        analyst_name:  Name of the analyst for the report.
        run_dynamic:   If True, execute the sample in a sandbox and capture behavior.
        output_dir:    Directory for output files (default: ./output/).
        report_format: all | html | pdf | docx | json (default: all)
    """
    if not Path(file_path).exists():
        return json.dumps({"error": f"File not found: {file_path}"})

    logs = []

    def log_fn(msg, level="info"):
        logs.append(f"[{level.upper()}] {msg}")

    workflow = AnalysisWorkflow(_cfg, log_fn=log_fn)
    analysis = workflow.run(
        file_path=file_path,
        analyst_name=analyst_name or _cfg.get("analyst", {}).get("name", "Analyst"),
        run_dynamic=run_dynamic,
        output_dir=output_dir or _cfg.get("output", {}).get("dir", "./output"),
    )

    # Generate reports
    out_dir = Path(output_dir or _cfg.get("output", {}).get("dir", "./output"))
    out_dir.mkdir(parents=True, exist_ok=True)
    base = str(out_dir / f"{Path(file_path).stem}_report")

    from malyze.report.generator import generate_report, generate_all
    if report_format == "all":
        report_paths = generate_all(analysis, base)
    else:
        rp = generate_report(analysis, f"{base}.{report_format}", fmt=report_format)
        report_paths = {report_format: rp}

    return json.dumps({
        "report_paths":            report_paths,
        "file_type":               analysis["file_info"].get("type"),
        "sha256":                  analysis["file_info"]["hashes"]["sha256"],
        "tools_ran":               [t["tool"] for t in analysis.get("tool_log",[]) if t.get("status")=="ok"],
        "tools_failed":            [t["tool"] for t in analysis.get("tool_log",[]) if "fail" in t.get("status","")],
        "tools_skipped":           [t["tool"] for t in analysis.get("tool_log",[]) if t.get("status")=="skipped"],
        "ai_analysis_available":   bool(analysis["ai_analysis"].get("analysis")),
        "ai_error":                analysis["ai_analysis"].get("error"),
        "duration_seconds":        analysis["meta"].get("duration_seconds"),
        "log": logs,
    }, indent=2)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
