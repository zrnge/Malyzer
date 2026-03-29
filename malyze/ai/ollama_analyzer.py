"""Ollama AI integration — sends structured analysis data, receives threat intelligence."""

import json
import re
import requests
from typing import Optional


SYSTEM_PROMPT = """You are an elite malware analyst and reverse engineer with deep expertise in:
- Windows internals, PE file format, and x86/x64 assembly
- Malware families: ransomware, RATs, stealers, loaders, droppers, rootkits, backdoors
- MITRE ATT&CK framework TTPs
- Threat intelligence and attribution
- Anti-analysis techniques: packing, obfuscation, anti-debug, anti-VM

When given malware analysis data, you will:
1. Identify the malware type/family if possible
2. Map behaviors to MITRE ATT&CK TTPs
3. Highlight the most critical/dangerous findings
4. Explain suspicious indicators clearly
5. Assess the threat level (Critical/High/Medium/Low)
6. Provide actionable IOCs and detection recommendations

Be precise, technical, and thorough. Structure your response clearly."""

STRUCTURED_SYSTEM = """You are a malware analysis data extractor.
You will be given a free-text malware analysis report.
Extract the key findings and return ONLY valid JSON — no markdown, no explanation.

Return exactly this schema:
{
  "malware_family": "<family name or null>",
  "malware_type": "<ransomware|rat|stealer|loader|dropper|rootkit|backdoor|worm|adware|unknown>",
  "confidence": <0-100 integer>,
  "threat_level": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "ttps": [
    {"id": "<ATT&CK ID e.g. T1055>", "name": "<technique name>", "evidence": "<one sentence>"}
  ],
  "iocs": {
    "ips": ["<ip>"],
    "urls": ["<url>"],
    "domains": ["<domain>"],
    "file_hashes": ["<hash>"],
    "mutex_names": ["<mutex>"],
    "registry_keys": ["<key>"]
  },
  "evasion_techniques": ["<technique name>"],
  "capabilities": ["<capability description>"],
  "attribution_hints": "<any threat actor hints or null>",
  "summary": "<2-3 sentence executive summary>"
}"""


def build_analysis_prompt(analysis_data: dict) -> str:
    file_info = analysis_data.get("file_info", {})
    static    = analysis_data.get("static", {})
    dynamic   = analysis_data.get("dynamic") or {}
    plan      = analysis_data.get("plan", {})

    parts = [
        "## MALWARE SAMPLE ANALYSIS DATA\n",
        f"**File:** {file_info.get('name', 'unknown')}",
        f"**Type:** {file_info.get('type', 'unknown')}",
        f"**MD5:** {file_info.get('hashes', {}).get('md5', 'N/A')}",
        f"**SHA256:** {file_info.get('hashes', {}).get('sha256', 'N/A')}",
        f"**Size:** {file_info.get('hashes', {}).get('size', 0):,} bytes",
        "",
    ]

    # Tool execution log
    tool_log = analysis_data.get("tool_log", [])
    if tool_log:
        ran  = [t["tool"] for t in tool_log if t.get("status") in ("ok","ok_fallback")]
        fail = [t["tool"] for t in tool_log if t.get("status") in ("failed","fallback_failed")]
        skip = [t["tool"] for t in tool_log if t.get("status") == "skipped"]
        parts += [
            "### Tools Executed",
            f"- Succeeded: {', '.join(ran) or 'none'}",
            f"- Failed:    {', '.join(fail) or 'none'}",
            f"- Skipped:   {', '.join(skip) or 'none'}",
            "",
        ]

    # YARA hits
    yara_data = static.get("yara", {})
    if yara_data and yara_data.get("matches"):
        parts += ["### YARA Matches"]
        for m in yara_data["matches"]:
            parts.append(f"  - Rule: {m.get('rule')}  ({m.get('rule_file','')})")
        parts.append("")

    # CAPA capabilities
    capa_data = static.get("capa", {})
    if capa_data:
        caps = capa_data.get("capabilities", [])
        if caps:
            parts.append(f"### CAPA Capabilities ({len(caps)} rules matched)")
            for c in caps[:40]:
                atk = ", ".join(
                    a.get("technique", str(a)) if isinstance(a, dict) else str(a)
                    for a in c.get("attack", [])
                )
                ns = c.get("namespace", "")
                label = f"  - {c.get('name','?')}"
                if ns:
                    label += f"  [{ns}]"
                if atk:
                    label += f"  ATT&CK: {atk}"
                parts.append(label)
            parts.append("")
        elif capa_data.get("text"):
            parts += ["### CAPA Capabilities", capa_data["text"][:2000], ""]

    # OLE/macro analysis
    ole_data = static.get("ole", {})
    if ole_data:
        parts += [
            "### OLE/Macro Analysis",
            f"- Has Macros: {ole_data.get('has_macros', False)}",
            f"- IOCs: {ole_data.get('iocs', [])}",
            "",
        ]

    # PDF analysis
    pdf_data = static.get("pdf", {})
    if pdf_data:
        parts += [
            "### PDF Analysis",
            f"- Pages: {pdf_data.get('page_count', 'N/A')}",
            f"- Text sample: {str(pdf_data.get('text_sample',''))[:500]}",
            "",
        ]

    # ELF analysis
    elf_data = static.get("elf", {})
    if elf_data:
        parts += [
            "### ELF Analysis",
            f"- Arch: {elf_data.get('arch', 'N/A')}",
            f"- Entry: {elf_data.get('entry_point', 'N/A')}",
            f"- Dynamic libs: {', '.join(elf_data.get('dynamic_libs', [])[:20])}",
            "",
        ]

    # Script analysis
    script = static.get("script", {})
    if script and not script.get("error"):
        parts += [
            "### Script Static Analysis",
            f"- File type:          {script.get('file_type', 'N/A')}",
            f"- Line count:         {script.get('line_count', 0)}",
            f"- Obfuscation score:  {script.get('obfuscation_score', 0)}/15",
            f"- Obfuscation indicators: {', '.join(script.get('obfuscation_indicators', [])) or 'none'}",
            "",
        ]
        sp = script.get("suspicious_patterns", {})
        if sp:
            parts += ["### Suspicious Script Patterns Detected"]
            for pat_name in sp:
                parts.append(f"  - {pat_name}")
            parts.append("")
        dp = script.get("decoded_payloads", [])
        if dp:
            parts += [f"### Decoded Payloads ({len(dp)} found)"]
            for p in dp[:5]:
                parts.append(f"  [{p.get('type','')}] {str(p.get('decoded',''))[:300]}")
            parts.append("")
        script_iocs = script.get("iocs", {})
        if script_iocs:
            parts += ["### Script IOCs"]
            for cat, items in script_iocs.items():
                parts.append(f"  {cat}: {', '.join(str(i) for i in items[:15])}")
            parts.append("")
        if script.get("strings_sample"):
            parts += ["### Script Content (first 50 lines)"]
            parts += [f"  {l}" for l in script["strings_sample"][:50]]
            parts.append("")

    # PDF analysis
    pdf = static.get("pdf", {})
    if pdf:
        summary = pdf.get("summary", {}) or pdf.get("raw_structure", {})
        if summary:
            parts += [
                "### PDF Analysis",
                f"- Pages:              {summary.get('page_count', 'N/A')}",
                f"- Has JavaScript:     {summary.get('has_javascript', False)}",
                f"- Has Embedded Files: {summary.get('has_embedded_files', False)}",
                f"- Has Auto Actions:   {summary.get('has_auto_actions', False)}",
                f"- Suspicious:         {summary.get('suspicious', False)}",
                f"- Suspicious Keywords: {', '.join(summary.get('suspicious_keywords', []))}",
                f"- URLs found:         {summary.get('urls', [])}",
                "",
            ]

    # Office document analysis
    office = static.get("office", {})
    if not office:
        office = static.get("ole", {})
    if office:
        ole_s = office.get("summary", {})
        if ole_s:
            parts += [
                "### Office Document Analysis",
                f"- Has Macros:       {ole_s.get('has_macros', False)}",
                f"- Suspicious Macros:{ole_s.get('suspicious_macros', False)}",
                f"- External URLs:    {ole_s.get('external_urls', [])}",
                f"- CVE Indicators:   {ole_s.get('cve_indicators', [])}",
                f"- IOC Count:        {ole_s.get('ioc_count', 0)}",
                "",
            ]
        macros = office.get("oletools", {}).get("macros", []) or office.get("macros", [])
        for m in macros[:3]:
            if m.get("suspicious_hits"):
                parts.append(f"  Macro '{m.get('filename','')}' suspicious hits: "
                             f"{', '.join(m['suspicious_hits'][:10])}")
        if macros:
            parts.append("")

    # Entropy
    entropy = static.get("entropy", {})
    if entropy:
        parts += [
            "### Entropy Analysis",
            f"- Overall: {entropy.get('overall_entropy', 'N/A')} — {entropy.get('classification', '')}",
            f"- Suspicious: {entropy.get('suspicious', False)}",
            "",
        ]

    # Packer detection
    packer = static.get("packer", {})
    if packer and packer.get("detected_packers"):
        parts += [
            "### Packer/Protector Detection",
            f"- Findings: {', '.join(packer.get('detected_packers', []))}",
            "",
        ]

    # PE analysis
    pe = static.get("pe", {})
    if pe and not pe.get("error"):
        parts += [
            "### PE Headers",
            f"- Machine: {pe.get('machine', 'N/A')}",
            f"- Timestamp: {pe.get('timestamp', 'N/A')}",
            f"- Subsystem: {pe.get('subsystem', 'N/A')}",
            f"- Entry Point: {pe.get('entry_point', 'N/A')}",
            f"- Is DLL: {pe.get('is_dll', False)}",
            f"- Has TLS: {pe.get('has_tls', False)}",
            f"- Has Signature: {pe.get('has_signature', False)}",
            "",
            "### Sections",
        ]
        for sec in pe.get("sections", []):
            flag = " [SUSPICIOUS - HIGH ENTROPY]" if sec.get("suspicious") else ""
            parts.append(
                f"  - {sec['name']:12s} | VA: {sec['virtual_address']} | "
                f"Entropy: {sec['entropy']:.2f}{flag}"
            )
        parts.append("")

        susp_imp = pe.get("suspicious_imports", [])
        if susp_imp:
            parts += [
                "### Suspicious Imports",
                *[f"  - {i}" for i in susp_imp[:50]],
                "",
            ]

        # All imports summary
        all_imports = pe.get("imports", {})
        if all_imports:
            parts.append("### Import Summary")
            for dll, funcs in list(all_imports.items())[:15]:
                parts.append(f"  - {dll}: {len(funcs)} functions")
            parts.append("")

        exports = pe.get("exports", [])
        if exports:
            parts += [
                "### Exports",
                *[f"  - {e['name']}" for e in exports[:30]],
                "",
            ]

        overlay = pe.get("overlay")
        if overlay:
            parts += [
                "### Overlay Data",
                f"  - Offset: {overlay['offset']}, Size: {overlay['size']}, "
                f"Entropy: {overlay['entropy']:.2f}",
                "",
            ]

    # Strings / IOCs
    strings_data = static.get("strings", {})
    iocs = strings_data.get("iocs", {})
    if iocs:
        parts.append("### Extracted IOCs from Strings")
        for cat, items in iocs.items():
            parts.append(f"  **{cat}:**")
            for item in items[:20]:
                parts.append(f"    - {item}")
        parts.append("")

    # Notable strings sample
    all_strings = strings_data.get("strings", [])
    if all_strings:
        parts += [
            "### Notable Strings Sample (first 100)",
            *[f"  {s}" for s in all_strings[:100]],
            "",
        ]

    # Disassembly
    disasm = static.get("disassembly", {})
    if disasm and not disasm.get("error"):
        parts += [
            f"### Disassembly (Arch: {disasm.get('arch', 'N/A')})",
            f"Entry Point RVA: {disasm.get('entry_point_rva', 'N/A')}",
            "",
        ]
        for block_name, block in (disasm.get("blocks") or {}).items():
            if block.get("error"):
                continue
            parts.append(f"**{block_name}** @ {block.get('va', '?')}:")
            for instr in block.get("instructions", [])[:50]:
                parts.append(
                    f"  {instr['address']}  {instr['mnemonic']:8s} {instr['op_str']}"
                )
            parts.append("")

    # Dynamic analysis
    if dynamic:
        parts.append("### Dynamic Analysis")
        exec_r = dynamic.get("execution", {})
        if exec_r:
            parts += [
                f"  - PID: {exec_r.get('pid', 'N/A')}",
                f"  - Exit code: {exec_r.get('exit_code', 'N/A')}",
                f"  - Timed out: {exec_r.get('timed_out', False)}",
            ]

        net = dynamic.get("network_activity", {})
        if net.get("available"):
            parts.append(f"  - Network connections observed: {len(net.get('connections', []))}")
            for c in net.get("connections", [])[:10]:
                parts.append(f"    {c}")

        proc = dynamic.get("process_file_registry", {})
        if proc.get("available"):
            parts.append(f"  - Total events: {proc.get('total_events', 0)}")
            for e in proc.get("file_events", [])[:10]:
                parts.append(f"    FILE: {e[:120]}")
            for e in proc.get("registry_events", [])[:10]:
                parts.append(f"    REG:  {e[:120]}")
        parts.append("")

    # Threat intel enrichment
    intel = analysis_data.get("intel", {})
    summary = intel.get("_summary", {})
    if summary.get("known_malware"):
        parts += [
            "### Threat Intelligence",
            f"- KNOWN MALWARE: Yes",
            f"- Consensus Family: {summary.get('consensus_family', 'unknown')}",
            f"- All Families: {', '.join(summary.get('all_families', []))}",
        ]
        mb = intel.get("malwarebazaar", {})
        if mb.get("found"):
            parts += [
                f"  MalwareBazaar: first_seen={mb.get('first_seen')}, "
                f"tags={mb.get('tags', [])}",
            ]
        vt = intel.get("virustotal", {})
        if vt.get("found"):
            parts += [
                f"  VirusTotal: {vt.get('detection_ratio')} engines detected, "
                f"label={vt.get('suggested_threat_label')}",
            ]
        parts.append("")
    elif intel:
        parts += ["### Threat Intelligence", "- Not found in threat intelligence databases", ""]

    # XOR deobfuscation results
    xor = analysis_data.get("static", {}).get("xor_deobfuscation", {})
    if xor.get("found_payloads"):
        parts += [f"### XOR Deobfuscation ({len(xor.get('candidates', []))} key candidates found)"]
        for cand in xor.get("candidates", [])[:3]:
            parts.append(
                f"  Key: 0x{cand['key_hex']} ({cand['key_size']}-byte) | "
                f"Score: {cand['score']} | Anchors: {cand['anchor_hits']}"
            )
            parts += [f"    {s}" for s in cand.get("strings", [])[:10]]
        parts.append("")

    # Imphash and .NET info
    pe_data = analysis_data.get("static", {}).get("pe", {})
    if pe_data:
        if pe_data.get("imphash"):
            parts.append(f"### Import Hash (imphash): {pe_data['imphash']}")
        if pe_data.get("is_dotnet"):
            parts.append("### .NET Binary: YES (managed code — CLR header present)")
        if pe_data.get("pdb_path"):
            parts.append(f"### PDB Debug Path: {pe_data['pdb_path']}")
        if pe_data.get("version_info"):
            parts += ["### Version Info"]
            for k, v in list(pe_data["version_info"].items())[:8]:
                parts.append(f"  {k}: {v}")
        parts.append("")

    # Similar samples from local DB
    similar = analysis_data.get("similar_samples", [])
    if similar:
        parts += [f"### Similar Samples (same imphash — {len(similar)} matches)"]
        for s in similar[:5]:
            parts.append(
                f"  {s.get('sha256', '')[:16]}... | {s.get('file_name')} | "
                f"{s.get('malware_family')} | {s.get('threat_level')}"
            )
        parts.append("")

    parts.append(
        "\n---\nBased on all the above data, provide your complete malware analysis. "
        "Include: malware classification, threat level, MITRE ATT&CK TTPs, key IOCs, "
        "behavioral summary, evasion techniques detected, and detection/remediation recommendations."
    )

    return "\n".join(parts)


def analyze_with_ollama(
    analysis_data: dict,
    host: str = "http://localhost:11434",
    model: str = "llama3.2",
    timeout: int = 300,
) -> dict:
    """
    Send analysis data to Ollama and return AI findings.
    Makes two calls:
      1. Free-text expert analysis (the main report narrative).
      2. Structured JSON extraction from the narrative — used for scoring,
         YARA generation, and sample-DB storage.
    """
    prompt = build_analysis_prompt(analysis_data)

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 8192,   # raised from 4096 so complex reports aren't truncated
        },
    }

    result = {
        "model":             model,
        "analysis":          "",
        "structured":        None,
        "prompt_tokens":     0,
        "completion_tokens": 0,
        "error":             None,
    }

    try:
        resp = requests.post(
            f"{host}/api/chat",
            json=payload,
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        content = data.get("message", {}).get("content", "")
        result["analysis"]          = content
        result["prompt_tokens"]     = data.get("prompt_eval_count", 0)
        result["completion_tokens"] = data.get("eval_count", 0)
    except requests.ConnectionError:
        result["error"] = f"Cannot connect to Ollama at {host}. Is Ollama running?"
        return result
    except requests.Timeout:
        result["error"] = f"Ollama request timed out after {timeout}s."
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

    # ── Second pass: extract structured JSON from the narrative ──────────────
    if result["analysis"]:
        result["structured"] = _extract_structured(
            narrative=result["analysis"],
            host=host,
            model=model,
            timeout=min(timeout // 3, 120),
        )

    return result


def _extract_structured(
    narrative: str,
    host: str,
    model: str,
    timeout: int = 90,
) -> Optional[dict]:
    """
    Ask the model to extract key findings from the free-text narrative as JSON.
    Returns a parsed dict or None on failure.
    """
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": STRUCTURED_SYSTEM},
            {"role": "user",   "content": f"Extract structured data from this analysis:\n\n{narrative[:6000]}"},
        ],
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 2048},
    }
    try:
        resp = requests.post(f"{host}/api/chat", json=payload, timeout=timeout)
        resp.raise_for_status()
        content = resp.json().get("message", {}).get("content", "")

        # Try direct parse
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # Extract JSON block from markdown fences or bare text
        match = re.search(r"\{[\s\S]*\}", content)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
    except Exception:
        pass
    return None
