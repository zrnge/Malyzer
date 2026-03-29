"""
Malyzer Agentic Orchestrator — AI drives every tool decision.

Instead of planning all tools upfront, the AI picks ONE tool at a time,
sees the result, and decides what to investigate next. This mirrors how
an actual analyst works: hypothesis → test → update hypothesis → repeat.

Two orchestrators:
  AgenticOrchestrator  — drives the static analysis loop
  DynamicOrchestrator  — drives the behavioral analysis loop
"""

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable


# ─────────────────────────────────────────────────────────────────────────────
# Iteration caps
# ─────────────────────────────────────────────────────────────────────────────
MAX_STATIC_ITERATIONS  = 20
MAX_DYNAMIC_ITERATIONS = 10


# ─────────────────────────────────────────────────────────────────────────────
# AI system prompts
# ─────────────────────────────────────────────────────────────────────────────

STATIC_NEXT_TOOL_SYSTEM = """You are Malyzer — an AI malware analyst driving a tool-by-tool investigation.
After each tool result you decide the SINGLE best next action.
Respond with ONLY valid JSON. No markdown, no explanation outside JSON.

Schema when running a tool:
{
  "action": "run_tool",
  "tool_id": "<id from available list>",
  "reasoning": "<1-2 sentences referencing what you found so far>",
  "confidence": <0-100>,
  "priority": "critical|high|medium|low",
  "hypotheses": ["<what you expect to find with this tool>"]
}

Schema when done:
{
  "action": "done",
  "reasoning": "<why you have enough data>",
  "confidence": <0-100>
}

Adaptive decision rules — follow these strictly:
1. ALWAYS start with: file_hashes → file_id → entropy (in that order if not already done)
2. HIGH ENTROPY (>= 7.0): pivot immediately to packer detection (die, upx).
   Skip strings tools — output is garbage on packed binaries.
3. .NET BINARY (is_dotnet=true): prioritize capa and capstone above strings.
4. KNOWN MALWARE from threat intel: focus on capability confirmation (capa, yara_python),
   not open-ended discovery. You already know the family.
5. CAPA found C2/injection/persistence: run strings_python or floss NEXT to get actual IOC values.
6. SCRIPT file type: script_analysis MUST run before any strings tools.
7. DECLARE DONE when you have: hashes + type + entropy + at least one strings source +
   PE analysis (if PE) + at least one threat-detection tool result.
   Do not run more tools just to be thorough — stop when you have actionable findings.
8. NEVER repeat a tool that already appears in the findings list.
9. Choose tool_id EXACTLY from the available list — no invented IDs."""


DYNAMIC_NEXT_TOOL_SYSTEM = """You are Malyzer — an AI driving live behavioral analysis in an isolated sandbox.
Pick ONE dynamic tool at a time. Respond with ONLY valid JSON.

Schema when running a tool:
{
  "action": "run_tool",
  "tool_id": "<id from available list>",
  "reasoning": "<why this tool, referencing static findings or prior dynamic results>",
  "confidence": <0-100>,
  "priority": "critical|high|medium|low",
  "hypotheses": ["<what you expect to observe>"]
}

Schema when done:
{
  "action": "done",
  "reasoning": "<why behavioral analysis is complete>",
  "confidence": <0-100>
}

Dynamic ordering rules:
1. NETWORK CAPTURE (fakenet or tshark): run BEFORE sample execution. Mandatory first step.
2. REGSHOT BEFORE: take registry baseline BEFORE execution.
3. PROCMON: runs CONCURRENTLY with sample execution.
4. SAMPLE EXECUTION: happens automatically after pre-execution tools are set up.
5. POST-EXECUTION: autorunsc comparison, regshot second snapshot, procdump if process persists.
6. If procmon shows process spawning, prioritize procdump on child PIDs.
7. If network connections detected, consider a second tshark capture window.
8. DECLARE DONE after: network capture + procmon + autorunsc comparison + regshot diff.
9. NEVER repeat a tool_id already in the findings list."""


# ─────────────────────────────────────────────────────────────────────────────
# Analysis context — shared state through the full pipeline
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AnalysisContext:
    file_path:       str
    file_type:       str
    file_info:       dict                    # name, sha256, size
    os_info:         dict                    # system, machine
    intel_summary:   dict                    # known_malware, consensus_family, etc.
    available_tools: dict                    # {tool_id: {name, description, category}}
    already_run:     list = field(default_factory=list)   # tool_ids executed (success OR fail)
    findings:        list = field(default_factory=list)   # {tool_id, summary, key_findings, phase}
    iteration:       int  = 0
    hypotheses:      list = field(default_factory=list)   # running AI hypothesis list


# ─────────────────────────────────────────────────────────────────────────────
# Result summarizer — compresses raw tool output to ~300 chars for AI context
# ─────────────────────────────────────────────────────────────────────────────

def _summarize_result(tool_id: str, output) -> str:
    """Convert raw tool output to a compact human-readable summary for the AI."""
    if not isinstance(output, dict):
        return str(output)[:300]

    try:
        if tool_id == "entropy":
            return (f"Entropy: {output.get('overall_entropy','?')} "
                    f"({output.get('classification','')}) | "
                    f"Suspicious: {output.get('suspicious')} | "
                    f"High-entropy blocks: {output.get('high_entropy_blocks',0)}/{output.get('total_blocks',0)}")

        if tool_id in ("pefile", "file_id"):
            r = output
            imp_count = sum(len(v) for v in r.get("imports", {}).values())
            s_imp = len(r.get("suspicious_imports", []))
            return (f"Machine: {r.get('machine','?')} | "
                    f"Imports: {imp_count} fns / {len(r.get('imports',{}))} DLLs | "
                    f"Suspicious imports: {s_imp} | "
                    f".NET: {r.get('is_dotnet',False)} | "
                    f"TLS: {r.get('has_tls',False)} | "
                    f"Imphash: {r.get('imphash','')[:12]}...")

        if tool_id == "file_hashes":
            return (f"MD5: {output.get('md5','')[:8]}... | "
                    f"SHA256: {output.get('sha256','')[:12]}... | "
                    f"Size: {output.get('size',0):,} bytes")

        if tool_id in ("die", "upx"):
            text = output.get("text", "") or str(output)
            return f"Detection: {text[:200].strip()}"

        if tool_id == "capa":
            caps = output.get("capabilities", [])
            ns   = list({c.get("namespace","") for c in caps if c.get("namespace")})[:5]
            atk  = list({
                a.get("technique","") or str(a)
                for c in caps for a in c.get("attack", [])
            })[:6]
            return (f"{len(caps)} capabilities | "
                    f"Namespaces: {', '.join(ns)} | "
                    f"ATT&CK: {', '.join(atk)}")

        if tool_id in ("yara_python", "yara_cli"):
            matches = output.get("matches", [])
            names   = [m.get("rule","?") for m in matches[:5]]
            return f"{len(matches)} YARA matches: {', '.join(names)}"

        if tool_id in ("strings_python", "strings_cli", "floss"):
            iocs = output.get("iocs", {})
            total = output.get("total", 0)
            parts = [f"{total} strings extracted"]
            for cat in ("urls", "ips", "api_calls", "suspicious_keywords"):
                items = iocs.get(cat, [])
                if items:
                    parts.append(f"{cat}: {len(items)} ({', '.join(str(i) for i in items[:3])}...)")
            return " | ".join(parts)

        if tool_id == "script_analysis":
            return (f"Type: {output.get('file_type','?')} | "
                    f"Obfuscation score: {output.get('obfuscation_score',0)}/15 | "
                    f"Patterns: {list(output.get('suspicious_patterns',{}).keys())[:5]} | "
                    f"Decoded payloads: {len(output.get('decoded_payloads',[]))}")

        if tool_id == "capstone":
            blocks = output.get("blocks", {})
            instr_count = sum(len(b.get("instructions",[])) for b in blocks.values())
            return f"Arch: {output.get('arch','?')} | {instr_count} instructions in {len(blocks)} blocks"

        if tool_id == "pdf_analysis":
            s = output.get("summary", {}) or output.get("raw_structure", {})
            return (f"Pages: {s.get('page_count','?')} | "
                    f"JS: {s.get('has_javascript',False)} | "
                    f"Embedded: {s.get('has_embedded_files',False)} | "
                    f"Suspicious: {s.get('suspicious',False)}")

        if tool_id == "office_analysis":
            s = output.get("summary", {})
            return (f"Macros: {s.get('has_macros',False)} | "
                    f"Suspicious macros: {s.get('suspicious_macros',False)} | "
                    f"CVE indicators: {s.get('cve_indicators',[])}")

        # Generic fallback
        return str(output)[:250]
    except Exception:
        return str(output)[:250]


def _summarize_dynamic_result(tool_id: str, output: dict) -> str:
    if not isinstance(output, dict):
        return str(output)[:200]
    try:
        if tool_id == "fakenet":
            conns = output.get("connections", [])
            return (f"Network: available={output.get('available',False)} | "
                    f"{len(conns)} connections observed | "
                    f"Lines: {output.get('total_lines',0)}")

        if tool_id == "procmon":
            return (f"Events: {output.get('total_events',0)} | "
                    f"File: {len(output.get('file_events',[]))} | "
                    f"Registry: {len(output.get('registry_events',[]))} | "
                    f"Process: {len(output.get('process_events',[]))} | "
                    f"Network: {len(output.get('network_events',[]))}")

        if tool_id == "tshark":
            return (f"Packets: {output.get('packet_count',0)} | "
                    f"DNS queries: {output.get('dns_queries',[])} | "
                    f"HTTP: {len(output.get('http_requests',[]))} | "
                    f"Unique IPs: {output.get('unique_ips',[])[:5]}")

        if tool_id in ("autorunsc_before", "autorunsc_after", "autorunsc_diff"):
            added = output.get("added_entries", [])
            return (f"Persistence entries: {output.get('entry_count',0)} | "
                    f"New entries: {len(added)} | "
                    f"Samples: {added[:2]}")

        if tool_id == "regshot":
            return (f"Reg keys added: {output.get('keys_added',0)} | "
                    f"Reg values added: {output.get('values_added',0)} | "
                    f"Modified: {output.get('values_modified',0)}")

        if tool_id == "procdump":
            return f"Dump: {output.get('dump_path','?')} | Success: {output.get('success',False)}"

        if tool_id == "sample_execution":
            return (f"PID: {output.get('pid','?')} | "
                    f"Exit: {output.get('exit_code','?')} | "
                    f"Timed out: {output.get('timed_out',False)}")

        return str(output)[:200]
    except Exception:
        return str(output)[:200]


def _extract_key_findings(tool_id: str, output: dict) -> dict:
    """Extract a small dict of the most decision-relevant fields per tool."""
    try:
        if tool_id == "entropy":
            return {
                "overall_entropy": output.get("overall_entropy"),
                "suspicious":      output.get("suspicious"),
                "classification":  output.get("classification"),
            }
        if tool_id in ("pefile", "file_id"):
            return {
                "is_dotnet":         output.get("is_dotnet", False),
                "susp_import_count": len(output.get("suspicious_imports", [])),
                "has_tls":           output.get("has_tls", False),
                "machine":           output.get("machine", ""),
                "section_count":     len(output.get("sections", [])),
                "imphash":           output.get("imphash", ""),
            }
        if tool_id == "capa":
            caps = output.get("capabilities", [])
            return {
                "total_capabilities": len(caps),
                "namespaces":    list({c.get("namespace","") for c in caps})[:8],
                "attack_ids":    list({
                    a.get("technique","") or str(a)
                    for c in caps for a in c.get("attack",[])
                    if isinstance(a, dict)
                })[:8],
            }
        if tool_id in ("yara_python", "yara_cli"):
            return {"match_count": len(output.get("matches", [])),
                    "rules":       [m.get("rule","") for m in output.get("matches",[])[:5]]}
        if tool_id in ("strings_python", "strings_cli", "floss"):
            iocs = output.get("iocs", {})
            return {
                "total_strings":  output.get("total", 0),
                "url_count":      len(iocs.get("urls", [])),
                "ip_count":       len(iocs.get("ips", [])),
                "api_count":      len(iocs.get("api_calls", [])),
                "susp_kw_count":  len(iocs.get("suspicious_keywords", [])),
            }
    except Exception:
        pass
    return {}


# ─────────────────────────────────────────────────────────────────────────────
# Context prompt builder — reconstructs full investigative history for AI
# ─────────────────────────────────────────────────────────────────────────────

def _build_context_prompt(ctx: AnalysisContext, remaining_tools: list) -> str:
    parts = [
        f"## Target Sample",
        f"- Name:    {ctx.file_info.get('name', '?')}",
        f"- Type:    {ctx.file_type}",
        f"- SHA256:  {ctx.file_info.get('sha256', '?')}",
        f"- Size:    {ctx.file_info.get('size', 0):,} bytes",
        "",
        f"## Environment",
        f"- OS:      {ctx.os_info.get('system','?')} {ctx.os_info.get('machine','')}",
        "",
    ]

    # Threat intel
    intel = ctx.intel_summary
    if intel.get("known_malware"):
        parts += [
            "## Threat Intelligence — KNOWN MALWARE",
            f"- Family:       {intel.get('consensus_family', 'unknown')}",
            f"- All families: {', '.join(intel.get('all_families', []))}",
        ]
        if intel.get("vt_detections"):
            parts.append(f"- VirusTotal:   {intel['vt_detections']}")
        parts.append("")
    else:
        parts += ["## Threat Intelligence", "- Not found in threat databases", ""]

    # Findings so far
    static_findings = [f for f in ctx.findings if f.get("phase") != "dynamic"]
    if static_findings:
        parts.append(f"## Analysis So Far — Iteration {ctx.iteration} of {MAX_STATIC_ITERATIONS}")
        for i, finding in enumerate(static_findings, 1):
            status = "OK" if finding.get("success", True) else "FAILED"
            parts.append(f"### {i}. {finding['tool_id']} [{status}]")
            parts.append(f"   {finding.get('summary', 'no summary')}")
        parts.append("")
    else:
        parts += ["## Analysis So Far", "- No tools have been run yet.", ""]

    # Running hypotheses
    if ctx.hypotheses:
        parts += ["## Running Hypotheses"]
        for h in ctx.hypotheses[-6:]:  # show last 6
            parts.append(f"  - {h}")
        parts.append("")

    # Available tools (not yet run)
    if remaining_tools:
        parts += [f"## Available Tools NOT Yet Run ({len(remaining_tools)} remaining)"]
        for t in remaining_tools:
            parts.append(f"  - {t['tool_id']:20s} | {t.get('description','')[:70]}")
        parts.append("")
    else:
        parts += ["## Available Tools", "- All applicable tools have been run.", ""]

    parts.append("## Decision")
    parts.append("What is the single best next tool to run, and why?")
    parts.append("Or declare 'done' if you have sufficient data for a complete analysis.")

    return "\n".join(parts)


def _build_dynamic_context_prompt(
    ctx: AnalysisContext,
    dynamic_collected: dict,
    remaining_tools: list,
) -> str:
    parts = [
        f"## Sample (Static Analysis Complete)",
        f"- Type:   {ctx.file_type}",
        f"- SHA256: {ctx.file_info.get('sha256','?')}",
        "",
        "## Key Static Findings (summary)",
    ]
    for f in ctx.findings:
        if f.get("phase") != "dynamic" and f.get("success", True):
            parts.append(f"  [{f['tool_id']}] {f.get('summary','')[:100]}")
    parts.append("")

    # Dynamic results collected so far
    if dynamic_collected:
        parts += [f"## Dynamic Results So Far — Iteration {ctx.iteration} of {MAX_DYNAMIC_ITERATIONS}"]
        for tool_id, result in dynamic_collected.items():
            summary = _summarize_dynamic_result(tool_id, result)
            parts.append(f"  [{tool_id}] {summary}")
        parts.append("")
    else:
        parts += ["## Dynamic Results So Far", "- No dynamic tools run yet.", ""]

    # Available dynamic tools
    if remaining_tools:
        parts += [f"## Available Dynamic Tools ({len(remaining_tools)} remaining)"]
        for t in remaining_tools:
            parts.append(f"  - {t['tool_id']:20s} | {t.get('description','')[:70]}")
        parts.append("")

    parts.append("## Decision")
    parts.append("What dynamic tool should run next? Or declare 'done'.")
    return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# Static Analysis Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class AgenticOrchestrator:
    """
    Drives the static analysis loop.
    The AI picks ONE tool per iteration and explains its reasoning.
    """

    def __init__(self, cfg: dict, env_scan: dict, log_fn: Callable):
        self.cfg      = cfg
        self.env_scan = env_scan
        self.log      = log_fn
        self.ollama   = cfg.get("ollama", {})
        self._max_iter = cfg.get("analysis", {}).get("max_static_iterations", MAX_STATIC_ITERATIONS)

    def run(self, ctx: AnalysisContext) -> tuple:
        """
        Run the agentic static loop.
        Returns (collected_raw_outputs, iteration_log)
        """
        from malyze.core.agent import _run_tool, _run_cli_capture, _is_argument_error, \
            _ask_ai_for_tool_syntax, _get_fallbacks

        collected  = {}
        iter_log   = []
        ai_online  = bool(self.ollama.get("host", "").startswith("http"))

        for i in range(self._max_iter):
            ctx.iteration = i + 1
            remaining     = self._get_remaining_tools(ctx)

            if not remaining:
                self.log(f"      [ORCH] All applicable tools exhausted (iteration {i+1})")
                break

            # Ask AI for next tool decision
            if ai_online:
                decision = self._ask_ai(ctx, remaining)
            else:
                decision = self._fallback_decision(ctx, remaining)

            if not decision:
                # AI unavailable — fall back to deterministic ordering
                self.log("      [ORCH] AI unreachable — switching to fallback ordering", "warning")
                decision = self._fallback_decision(ctx, remaining)

            if decision.get("action") == "done":
                self.log(f"      [ORCH] Analysis complete: {decision.get('reasoning','')[:80]}")
                break

            if decision.get("action") != "run_tool":
                self.log(f"      [ORCH] Unexpected action '{decision.get('action')}', stopping", "warning")
                break

            tool_id   = decision.get("tool_id", "").strip()
            reasoning = decision.get("reasoning", "")
            confidence = decision.get("confidence", 0)
            hyps       = decision.get("hypotheses", [])

            # Guard: AI may hallucinate a tool_id not in remaining
            valid_ids = {t["tool_id"] for t in remaining}
            if tool_id not in valid_ids:
                self.log(f"      [ORCH] AI chose unknown/unavailable tool '{tool_id}' — using next logical tool", "warning")
                tool_id   = remaining[0]["tool_id"]
                reasoning = "AI suggested invalid tool; using next available"

            self.log(f"\n      ┌─[Step {i+1}/{self._max_iter}] Tool: {tool_id}")
            self.log(f"      │  Reason: {reasoning[:90]}")
            if confidence:
                self.log(f"      │  Confidence: {confidence}%")

            # Run the tool
            run_result = _run_tool(tool_id, ctx.file_path, self.env_scan, self.cfg)
            ctx.already_run.append(tool_id)

            if run_result.get("success"):
                raw_output = run_result["output"]
                collected[tool_id] = raw_output
                summary = _summarize_result(tool_id, raw_output)
                key_f   = _extract_key_findings(tool_id, raw_output)
                ctx.findings.append({
                    "tool_id":      tool_id,
                    "summary":      summary,
                    "key_findings": key_f,
                    "phase":        "static",
                    "iteration":    i + 1,
                    "success":      True,
                })
                if hyps:
                    ctx.hypotheses.extend(hyps)
                iter_log.append({
                    "iteration":   i + 1,
                    "tool_id":     tool_id,
                    "reasoning":   reasoning,
                    "confidence":  confidence,
                    "summary":     summary,
                    "status":      "ok",
                })
                self.log(f"      └─ Result: {summary[:100]}")
            else:
                err = run_result.get("error", "unknown error")
                self.log(f"      └─ FAILED: {err[:80]}", "warning")

                # AI syntax retry for argument errors
                tool_bin    = self.env_scan.get(tool_id, {}).get("path_or_module")
                ollama_host = self.ollama.get("host", "")
                if (tool_bin and isinstance(tool_bin, str)
                        and ollama_host.startswith("http")
                        and _is_argument_error(err)):
                    ai_args = _ask_ai_for_tool_syntax(
                        tool_id, tool_bin, ctx.file_path, err,
                        ollama_host, self.ollama.get("model", "llama3.2"), 30
                    )
                    if ai_args:
                        retry = _run_cli_capture(tool_bin, ai_args, timeout=180)
                        if retry.get("success"):
                            collected[tool_id] = retry["output"]
                            summary = _summarize_result(tool_id, retry["output"])
                            ctx.findings.append({
                                "tool_id": tool_id, "summary": summary,
                                "phase": "static", "iteration": i + 1, "success": True,
                            })
                            iter_log.append({
                                "iteration": i + 1, "tool_id": tool_id,
                                "reasoning": reasoning, "confidence": confidence,
                                "summary": summary, "status": "ok_ai_retry",
                            })
                            self.log(f"      └─ Retry OK: {summary[:80]}")
                            continue

                # Static fallback chain
                fallbacks = _get_fallbacks(tool_id, [t["tool_id"] for t in remaining])
                for fb in fallbacks:
                    if fb in ctx.already_run or fb in collected:
                        continue
                    fb_result = _run_tool(fb, ctx.file_path, self.env_scan, self.cfg)
                    ctx.already_run.append(fb)
                    if fb_result.get("success"):
                        collected[fb] = fb_result["output"]
                        summary = _summarize_result(fb, fb_result["output"])
                        ctx.findings.append({
                            "tool_id": fb, "summary": summary,
                            "phase": "static", "iteration": i + 1, "success": True,
                        })
                        iter_log.append({
                            "iteration": i + 1, "tool_id": fb,
                            "reasoning": f"fallback for {tool_id}",
                            "confidence": 60, "summary": summary, "status": "ok_fallback",
                        })
                        self.log(f"      └─ Fallback OK ({fb}): {summary[:70]}")
                        break
                else:
                    ctx.findings.append({
                        "tool_id": tool_id, "summary": f"FAILED: {err}",
                        "phase": "static", "iteration": i + 1, "success": False,
                    })
                    iter_log.append({
                        "iteration": i + 1, "tool_id": tool_id,
                        "reasoning": reasoning, "status": "failed", "error": err,
                    })

        return collected, iter_log

    # ── Private helpers ───────────────────────────────────────────────────────

    def _get_remaining_tools(self, ctx: AnalysisContext) -> list:
        """Return available static tools not yet run, filtered by file type."""
        result = []
        for tid, info in self.env_scan.items():
            if not info.get("available"):
                continue
            if info.get("category") == "dynamic":
                continue
            if tid in ctx.already_run:
                continue
            # File type filter
            file_types = info.get("file_types", [])
            if "*" not in file_types and ctx.file_type not in file_types:
                if not any(ctx.file_type.startswith(ft) for ft in file_types
                           if ft != "*"):
                    continue
            result.append({
                "tool_id":     tid,
                "name":        info.get("name", tid),
                "description": info.get("description", ""),
                "category":    info.get("category", ""),
            })
        return result

    def _ask_ai(self, ctx: AnalysisContext, remaining: list) -> Optional[dict]:
        """Single Ollama call to get next tool decision."""
        import requests

        prompt  = _build_context_prompt(ctx, remaining)
        payload = {
            "model":    self.ollama.get("model", "llama3.2"),
            "messages": [
                {"role": "system", "content": STATIC_NEXT_TOOL_SYSTEM},
                {"role": "user",   "content": prompt},
            ],
            "stream":  False,
            "options": {"temperature": 0.0, "num_predict": 512},
        }
        try:
            resp = requests.post(
                f"{self.ollama['host']}/api/chat",
                json=payload,
                timeout=self.ollama.get("planner_timeout", 60),
            )
            resp.raise_for_status()
            content = resp.json().get("message", {}).get("content", "")
            return _parse_json_decision(content)
        except Exception as exc:
            self.log(f"      [ORCH] AI call failed: {exc}", "warning")
            return None

    def _fallback_decision(self, ctx: AnalysisContext, remaining: list) -> dict:
        """Deterministic fallback when AI is unavailable."""
        from malyze.core.agent import _build_fallback_plan
        available_ids = [t["tool_id"] for t in remaining]
        plan  = _build_fallback_plan(ctx.file_type, available_ids)
        steps = plan.get("steps", [])
        for step in steps:
            if step["tool_id"] not in ctx.already_run:
                return {
                    "action":     "run_tool",
                    "tool_id":    step["tool_id"],
                    "reasoning":  step.get("reason", "Fallback plan"),
                    "confidence": 75,
                    "priority":   "high" if step.get("required") else "medium",
                    "hypotheses": [],
                }
        return {"action": "done", "reasoning": "All fallback steps complete", "confidence": 90}


# ─────────────────────────────────────────────────────────────────────────────
# Dynamic Analysis Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class DynamicOrchestrator:
    """
    Drives behavioral analysis — each tool decision made by the AI after
    seeing previous results. Smart ordering is enforced for mandatory steps.
    """

    # Tools that MUST run before sample execution
    PRE_EXECUTION_TOOLS  = {"fakenet", "tshark", "autorunsc_before"}
    # Tools that MUST run after sample execution
    POST_EXECUTION_TOOLS = {"autorunsc_after", "regshot", "procdump"}

    def __init__(self, cfg: dict, env_scan: dict, output_dir: str, log_fn: Callable):
        self.cfg        = cfg
        self.env_scan   = env_scan
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log        = log_fn
        self.ollama     = cfg.get("ollama", {})
        self._max_iter  = cfg.get("analysis", {}).get("max_dynamic_iterations", MAX_DYNAMIC_ITERATIONS)
        self._timeout   = cfg.get("analysis", {}).get("dynamic_timeout", 60)

    def run(self, ctx: AnalysisContext, sample_path: str) -> tuple:
        """
        Run the agentic dynamic analysis loop.
        Returns (dynamic_results_dict, iteration_log)
        """
        from malyze.dynamic.behavior_monitor import BehaviorMonitor

        monitor    = BehaviorMonitor(self.cfg, str(self.output_dir))
        collected  = {}
        iter_log   = []
        ai_online  = bool(self.ollama.get("host", "").startswith("http"))
        started_tools = []   # Popen handles for cleanup

        # ── Phase A: Mandatory pre-execution tools ────────────────────────────
        self.log("      [DYN] Starting pre-execution monitors...")
        self._run_pre_execution(monitor, collected, started_tools)

        # ── Phase B: Sample execution ─────────────────────────────────────────
        self.log(f"      [DYN] Executing sample (timeout: {self._timeout}s)...")
        exec_result = monitor._execute_sample(sample_path, self._timeout)
        collected["sample_execution"] = exec_result
        spawn_pid   = exec_result.get("pid")
        summary_exec = _summarize_dynamic_result("sample_execution", exec_result)
        ctx.findings.append({
            "tool_id": "sample_execution", "summary": summary_exec,
            "phase": "dynamic", "iteration": 0, "success": not exec_result.get("error"),
        })
        self.log(f"      [DYN] Execution: {summary_exec}")

        # ── Phase C: AI-driven post-execution tools ───────────────────────────
        for i in range(self._max_iter):
            ctx.iteration = i + 1
            remaining     = self._get_remaining_dynamic_tools(collected)

            if not remaining:
                break

            if ai_online:
                decision = self._ask_ai_dynamic(ctx, collected, remaining)
            else:
                decision = self._fallback_dynamic(remaining)

            if not decision or decision.get("action") == "done":
                reason = decision.get("reasoning", "Dynamic analysis complete") if decision else "AI unavailable"
                self.log(f"      [DYN] {reason}")
                break

            tool_id   = decision.get("tool_id", "").strip()
            reasoning = decision.get("reasoning", "")

            valid_ids = {t["tool_id"] for t in remaining}
            if tool_id not in valid_ids:
                tool_id = remaining[0]["tool_id"]

            self.log(f"      [DYN {i+1}] Running: {tool_id} — {reasoning[:70]}")

            result  = self._run_dynamic_tool(tool_id, sample_path, collected, monitor, spawn_pid)
            collected[tool_id] = result

            summary = _summarize_dynamic_result(tool_id, result)
            ctx.findings.append({
                "tool_id": tool_id, "summary": summary,
                "phase": "dynamic", "iteration": i + 1, "success": not result.get("error"),
            })
            iter_log.append({
                "iteration": i + 1, "tool_id": tool_id,
                "reasoning": reasoning,
                "summary":   summary,
            })
            self.log(f"      [DYN]   → {summary[:90]}")

        # ── Cleanup ───────────────────────────────────────────────────────────
        self.log("      [DYN] Cleaning up monitors...")
        for label, proc in monitor._tracked:
            monitor._safe_kill(proc)
        monitor._stop_procmon()

        return self._normalise_dynamic(collected), iter_log

    def _run_pre_execution(
        self, monitor, collected: dict, started_tools: list
    ) -> None:
        """Start mandatory pre-execution monitors."""
        # FakeNet-NG network intercept
        fakenet_proc = monitor._start_fakenet()
        if fakenet_proc:
            collected["fakenet_started"] = True
            self.log("      [DYN] FakeNet-NG started")

        # Procmon process monitor
        pml_path = str(self.output_dir / "procmon.pml")
        procmon_proc = monitor._start_procmon(pml_path)
        if procmon_proc:
            collected["procmon_started"] = True
            self.log("      [DYN] Procmon started")

        # tshark packet capture
        pcap_path = str(self.output_dir / "capture.pcap")
        tshark_result = self._start_tshark(pcap_path)
        if tshark_result.get("available"):
            collected["tshark_started"] = pcap_path
            self.log("      [DYN] tshark packet capture started")

        # Autoruns baseline snapshot
        autoruns_before = self._run_autoruns_snapshot("before")
        if autoruns_before.get("available"):
            collected["autorunsc_before"] = autoruns_before
            self.log("      [DYN] Autoruns baseline snapshot taken")

        # Allow monitors to initialise
        if collected:
            time.sleep(2)

    def _run_dynamic_tool(
        self,
        tool_id: str,
        sample_path: str,
        collected: dict,
        monitor,
        spawn_pid: Optional[int],
    ) -> dict:
        """Dispatch a single dynamic tool call."""
        if tool_id == "procmon_results":
            pml_path = str(self.output_dir / "procmon.pml")
            monitor._stop_procmon()
            csv_path = monitor._export_csv(pml_path)
            return monitor._parse_procmon_csv(csv_path)

        if tool_id == "fakenet_results":
            return monitor._read_fakenet_log()

        if tool_id == "tshark_results":
            pcap_path = collected.get("tshark_started", "")
            return self._read_tshark_results(pcap_path)

        if tool_id == "autorunsc_after":
            return self._run_autoruns_snapshot("after")

        if tool_id == "autorunsc_diff":
            before = collected.get("autorunsc_before", {})
            after  = collected.get("autorunsc_after", {})
            return self._diff_autoruns(before, after)

        if tool_id == "regshot":
            return self._run_regshot_compare()

        if tool_id == "procdump":
            pid_to_dump = spawn_pid
            if not pid_to_dump:
                return {"error": "No PID to dump — sample may not have spawned a process"}
            dump_path = str(self.output_dir / f"dump_{pid_to_dump}.dmp")
            return self._run_procdump(pid_to_dump, dump_path)

        return {"error": f"No runner for dynamic tool: {tool_id}"}

    def _get_remaining_dynamic_tools(self, collected: dict) -> list:
        """Return dynamic tools available and not yet collected."""
        # All possible post-execution dynamic analysis IDs
        all_dynamic = [
            ("procmon_results",  "Collect Procmon process/file/registry events",   "procmon"    in self.env_scan and self.env_scan["procmon"].get("available")),
            ("fakenet_results",  "Collect FakeNet-NG network intercept logs",       "fakenet"    in self.env_scan and self.env_scan["fakenet"].get("available")),
            ("tshark_results",   "Read tshark packet capture and extract IOCs",     "tshark"     in self.env_scan and self.env_scan["tshark"].get("available") and bool(collected.get("tshark_started"))),
            ("autorunsc_after",  "Take Autoruns post-execution snapshot",           "autorunsc"  in self.env_scan and self.env_scan["autorunsc"].get("available")),
            ("autorunsc_diff",   "Compare before/after Autoruns snapshots for new persistence entries",
             "autorunsc_before" in collected and "autorunsc_after" in collected),
            ("regshot",          "Registry diff: keys added/modified by the sample","regshot"    in self.env_scan and self.env_scan["regshot"].get("available")),
            ("procdump",         "Dump spawned process memory for forensic analysis","procdump"   in self.env_scan and self.env_scan["procdump"].get("available")),
        ]
        return [
            {"tool_id": tid, "description": desc}
            for tid, desc, available in all_dynamic
            if available and tid not in collected
        ]

    def _ask_ai_dynamic(
        self, ctx: AnalysisContext, collected: dict, remaining: list
    ) -> Optional[dict]:
        """Ask AI for next dynamic tool decision."""
        import requests

        prompt  = _build_dynamic_context_prompt(ctx, collected, remaining)
        payload = {
            "model":    self.ollama.get("model", "llama3.2"),
            "messages": [
                {"role": "system", "content": DYNAMIC_NEXT_TOOL_SYSTEM},
                {"role": "user",   "content": prompt},
            ],
            "stream":  False,
            "options": {"temperature": 0.0, "num_predict": 512},
        }
        try:
            resp = requests.post(
                f"{self.ollama['host']}/api/chat",
                json=payload,
                timeout=self.ollama.get("planner_timeout", 60),
            )
            resp.raise_for_status()
            content = resp.json().get("message", {}).get("content", "")
            return _parse_json_decision(content)
        except Exception as exc:
            self.log(f"      [DYN] AI call failed: {exc}", "warning")
            return None

    def _fallback_dynamic(self, remaining: list) -> dict:
        """Run remaining dynamic tools in order when AI is offline."""
        if remaining:
            return {
                "action":    "run_tool",
                "tool_id":   remaining[0]["tool_id"],
                "reasoning": "Fallback sequential execution",
                "confidence": 70,
            }
        return {"action": "done", "reasoning": "All dynamic tools complete", "confidence": 90}

    # ── Dynamic tool implementations ──────────────────────────────────────────

    def _find_tool(self, name: str) -> Optional[str]:
        import shutil
        path = self.cfg.get("flarevm", {}).get(name, "")
        if path and Path(path).exists():
            return path
        return shutil.which(name) or shutil.which(name + ".exe")

    def _start_tshark(self, pcap_path: str) -> dict:
        from malyze.dynamic.behavior_monitor import _popen_detached
        tool = self._find_tool("tshark")
        if not tool:
            return {"available": False, "error": "tshark not found"}
        capture_sec = self.cfg.get("analysis", {}).get("tshark_capture_seconds", 60)
        iface       = self.cfg.get("analysis", {}).get("tshark_interface", "")
        cmd = [tool]
        if iface:
            cmd += ["-i", iface]
        cmd += ["-w", pcap_path, "-a", f"duration:{capture_sec}"]
        try:
            proc = _popen_detached(cmd)
            return {"available": True, "pcap_path": pcap_path, "pid": proc.pid}
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _read_tshark_results(self, pcap_path: str) -> dict:
        import subprocess as _sp
        tool = self._find_tool("tshark")
        if not tool or not pcap_path or not Path(pcap_path).exists():
            return {"available": False, "error": "pcap not found"}
        try:
            result = _sp.run(
                [tool, "-r", pcap_path, "-T", "fields",
                 "-e", "ip.dst", "-e", "ip.src", "-e", "dns.qry.name",
                 "-e", "http.request.full_uri", "-e", "_ws.col.Protocol",
                 "-E", "separator=|"],
                capture_output=True, text=True, timeout=30, errors="replace",
            )
            dns_queries, http_requests, unique_ips = set(), [], set()
            packet_count = 0
            for line in result.stdout.splitlines():
                parts_line = line.split("|")
                if len(parts_line) < 5:
                    continue
                packet_count += 1
                ip_dst, ip_src, dns_q, http_uri, proto = (parts_line + ["","","","",""])[:5]
                if dns_q:
                    dns_queries.add(dns_q.strip())
                if http_uri:
                    http_requests.append(http_uri.strip())
                for ip in (ip_dst.strip(), ip_src.strip()):
                    if ip and not ip.startswith(("127.", "0.", "255.")):
                        unique_ips.add(ip)
            return {
                "available":     True,
                "packet_count":  packet_count,
                "dns_queries":   sorted(dns_queries)[:30],
                "http_requests": http_requests[:30],
                "unique_ips":    sorted(unique_ips)[:30],
                "pcap_path":     pcap_path,
            }
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _run_autoruns_snapshot(self, label: str) -> dict:
        import subprocess as _sp
        tool = self._find_tool("autorunsc") or self._find_tool("autorunsc.exe")
        if not tool:
            return {"available": False, "error": "autorunsc not found"}
        snapshot_path = str(self.output_dir / f"autoruns_{label}.csv")
        try:
            result = _sp.run(
                [tool, "-accepteula", "-a", "*", "-c", "-h", "-nobanner"],
                capture_output=True, text=True, timeout=60, errors="replace",
            )
            Path(snapshot_path).write_text(result.stdout, encoding="utf-8", errors="replace")
            lines = [l for l in result.stdout.splitlines() if l.strip()]
            return {
                "available":     True,
                "label":         label,
                "snapshot_path": snapshot_path,
                "entry_count":   len(lines),
            }
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _diff_autoruns(self, before: dict, after: dict) -> dict:
        """Compare before/after Autoruns snapshots, return new persistence entries."""
        import csv as _csv
        b_path = before.get("snapshot_path", "")
        a_path = after.get("snapshot_path", "")
        if not (b_path and a_path and Path(b_path).exists() and Path(a_path).exists()):
            return {"available": False, "error": "Missing snapshot files"}
        try:
            def _read_entries(path):
                entries = {}
                with open(path, encoding="utf-8", errors="replace") as f:
                    reader = _csv.DictReader(f)
                    for row in reader:
                        key = row.get("Image Path", "") + "|" + row.get("Launch String", "")
                        entries[key] = dict(row)
                return entries
            before_entries = _read_entries(b_path)
            after_entries  = _read_entries(a_path)
            added   = {k: v for k, v in after_entries.items() if k not in before_entries}
            removed = {k: v for k, v in before_entries.items() if k not in after_entries}
            return {
                "available":     True,
                "added_count":   len(added),
                "removed_count": len(removed),
                "added_entries": [
                    f"{v.get('Entry','?')} → {v.get('Launch String','?')}"
                    for v in list(added.values())[:20]
                ],
                "removed_entries": [v.get("Entry","?") for v in list(removed.values())[:5]],
            }
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _run_procdump(self, pid: int, output_path: str) -> dict:
        import subprocess as _sp
        tool = self._find_tool("procdump64") or self._find_tool("procdump")
        if not tool:
            return {"available": False, "error": "procdump not found"}
        try:
            result = _sp.run(
                [tool, "-accepteula", "-ma", str(pid), output_path],
                capture_output=True, text=True, timeout=60, errors="replace",
            )
            size = Path(output_path).stat().st_size if Path(output_path).exists() else 0
            return {
                "available": True,
                "pid":        pid,
                "dump_path":  output_path,
                "dump_size":  size,
                "success":    result.returncode == 0,
                "output":     result.stdout[:300],
            }
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _run_regshot_compare(self) -> dict:
        """Take 2nd Regshot snapshot and generate diff."""
        tool = self._find_tool("Regshot-x64-Unicode") or self._find_tool("Regshot-x64-Unicode.exe")
        if not tool:
            return {"available": False, "error": "Regshot not found"}
        diff_path = str(self.output_dir / "regshot_diff.txt")
        try:
            import subprocess as _sp
            _sp.run([tool, "/2shot", "/silent", f"/output:{diff_path}"],
                    capture_output=True, timeout=30)
            return self._parse_regshot_diff(diff_path)
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _parse_regshot_diff(self, diff_path: str) -> dict:
        if not Path(diff_path).exists():
            return {"available": False, "error": "No Regshot diff file"}
        try:
            text = Path(diff_path).read_text(encoding="utf-16", errors="replace")
            keys_added    = text.count("Key added:")
            vals_added    = text.count("Values added:")
            vals_modified = text.count("Values modified:")
            # Extract first few added items
            import re as _re
            added = _re.findall(r"Key added:\s*(.+)", text)[:10]
            return {
                "available":       True,
                "keys_added":      keys_added,
                "values_added":    vals_added,
                "values_modified": vals_modified,
                "sample_added_keys": added[:10],
                "diff_path":       diff_path,
            }
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _normalise_dynamic(self, collected: dict) -> dict:
        """Convert dynamic collected dict to the standard dynamic result format."""
        result = {
            "execution":             collected.get("sample_execution", {}),
            "network_activity":      {},
            "process_file_registry": {},
            "tools_available":       {},
            "persistence":           {},
            "registry_diff":         {},
            "memory_dump":           {},
        }

        # Network — prefer tshark over fakenet
        if "tshark_results" in collected and collected["tshark_results"].get("available"):
            result["network_activity"] = collected["tshark_results"]
        elif "fakenet" in collected.get("fakenet_started", {}):
            pass  # fakenet results are collected via fakenet_results key

        if "fakenet_results" in collected:
            result["network_activity"] = collected["fakenet_results"]

        if "procmon_results" in collected:
            result["process_file_registry"] = collected["procmon_results"]

        if "autorunsc_diff" in collected:
            result["persistence"] = collected["autorunsc_diff"]
        elif "autorunsc_after" in collected:
            result["persistence"] = collected["autorunsc_after"]

        if "regshot" in collected:
            result["registry_diff"] = collected["regshot"]

        if "procdump" in collected:
            result["memory_dump"] = collected["procdump"]

        result["tools_available"] = {
            k: True for k in collected
            if k.endswith("_started") or k.endswith("_results")
        }
        return result


# ─────────────────────────────────────────────────────────────────────────────
# JSON parser for AI decisions
# ─────────────────────────────────────────────────────────────────────────────

def _parse_json_decision(content: str) -> Optional[dict]:
    """Parse a JSON decision from AI response text."""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", content)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return None
