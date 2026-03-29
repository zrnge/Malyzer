# Malyzer — AI-Powered Malware Analysis Framework

> Agentic, tool-by-tool malware analysis driven by a local LLM (Ollama).
> Designed for **FlareVM** environments. No cloud dependencies.

---

## What is Malyzer?

Malyzer is a Python framework that automates the full malware analysis workflow:

1. **Detects the OS and inventories every available tool** (static + dynamic)
2. **Identifies the file type** (PE, ELF, Office, PDF, script, etc.) and computes hashes
3. **Queries threat intelligence** — MalwareBazaar (free, no key) + optional VirusTotal
4. **Runs an agentic static analysis loop** — the AI picks one tool at a time, sees the result, then decides which tool to run next (up to 20 iterations)
5. **Runs an agentic dynamic analysis loop** — Procmon, tshark/Wireshark, Autoruns, Regshot, ProcDump, FakeNet-NG — ordered intelligently (network capture before execution, registry baseline before execution, memory dump after)
6. **Synthesises all collected data** into a final AI threat report
7. **Saves to a local SQLite database** and auto-generates a YARA hunting rule for HIGH/CRITICAL samples

Reports are generated as **HTML**, **PDF**, **DOCX**, and **JSON**.

---

## Architecture

```
main.py  (CLI — click)
  └── AnalysisWorkflow  (workflow.py)
        └── MalyzeAgent  (agent.py)
              ├── Step 1/7 — OS & tool inventory        (environment.py, tool_registry.py)
              ├── Step 2/7 — File ID + threat intel      (file_identifier.py, intel/)
              ├── Step 3/7 — Agentic static loop         (orchestrator.AgenticOrchestrator)
              │     └── AI picks tool → run → AI sees result → repeat
              ├── Step 4/7 — Tool inventory report
              ├── Step 5/7 — Agentic dynamic loop        (orchestrator.DynamicOrchestrator)
              │     └── Pre-exec: FakeNet, Procmon, tshark, Autoruns baseline
              │     └── Execute sample
              │     └── Post-exec: Autoruns diff, Regshot diff, ProcDump
              ├── Step 6/7 — Final AI synthesis          (ai/ollama_analyzer.py)
              └── Step 7/7 — DB save + auto-YARA         (intel/sample_db.py, static/yara_generator.py)
```

### Static analysis tools
| Tool | Purpose |
|---|---|
| FLOSS | String extraction + deobfuscation |
| strings (Sysinternals) | Raw string extraction |
| Detect-It-Easy (DIE) | Packer / compiler detection |
| CAPA | Capability detection (MITRE ATT&CK) |
| pefile (Python) | PE header, imports, sections, rich header |
| Capstone / objdump | Disassembly |
| YARA | Pattern matching |
| Built-in entropy | Section entropy + high-entropy block detection |
| Built-in XOR brute force | 1 & 2-byte key XOR deobfuscation |
| pyelftools / readelf | ELF binary analysis |
| oletools | Office macro / OLE analysis |
| pdfminer | PDF text + stream extraction |

### Dynamic analysis tools
| Tool | Purpose |
|---|---|
| FakeNet-NG | Fake network services (DNS, HTTP, etc.) |
| Procmon | Process / file / registry monitoring |
| tshark | Live packet capture (pcap) |
| Autoruns / autorunsc | Persistence baseline → diff |
| Regshot | Registry snapshot → diff |
| ProcDump | Memory dump of spawned process |

---

## Requirements

### System
- **Windows 10/11** (FlareVM recommended)
- **Python 3.10+**
- **[Ollama](https://ollama.com)** running locally with a model pulled (e.g. `ollama pull llama3.2`)

### FlareVM tools (optional but recommended)
Install from their official sources and ensure they are on `PATH` or configure paths in `config.yaml`:

| Tool | Source |
|---|---|
| FLOSS | github.com/mandiant/flare-floss |
| Detect-It-Easy | github.com/horsicq/Detect-It-Easy |
| CAPA | github.com/mandiant/capa |
| strings64.exe | learn.microsoft.com/sysinternals |
| Procmon64.exe | learn.microsoft.com/sysinternals |
| autorunsc.exe | learn.microsoft.com/sysinternals |
| procdump64.exe | learn.microsoft.com/sysinternals |
| tshark.exe | wireshark.org |
| FakeNet.exe | github.com/mandiant/flare-fakenet-ng |
| Regshot | sourceforge.net/projects/regshot |
| YARA | virustotal.github.io/yara |

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/malyzer.git
cd malyzer
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Or use the included batch installer on FlareVM:
```
install.bat
```

---

## Configuration

Edit `config.yaml` before first use:

```yaml
ollama:
  host: http://localhost:11434
  model: llama3.2          # or mistral, codellama, kimi-k2.5, etc.
  timeout: 900

flarevm:
  floss: "floss.exe"
  capa: "capa.exe"
  die: "diec.exe"
  strings: "strings64.exe"
  procmon: "Procmon64.exe"
  tshark: "tshark.exe"
  autorunsc: "autorunsc.exe"
  procdump: "procdump64.exe"
  fakenet: "FakeNet.exe"
  regshot: "Regshot-x64-Unicode.exe"

analysis:
  max_static_iterations: 20   # how many AI tool-selection loops (static)
  max_dynamic_iterations: 10  # how many AI tool-selection loops (dynamic)
  tshark_capture_seconds: 60

intel:
  malwarebazaar: true          # always free, no key needed
  virustotal_api_key: ""       # optional — get free key at virustotal.com

analyst:
  name: "Security Analyst"
  org:  "Malware Analysis Lab"
```

---

## Usage

### Full analysis
```bash
python main.py analyze malware_sample.exe
```

### With dynamic analysis (run inside a sandbox!)
```bash
python main.py analyze malware_sample.exe --dynamic
```

### Specify analyst name and report format
```bash
python main.py analyze sample.exe --analyst "John" --format html
```

### All report formats (HTML + PDF + DOCX + JSON)
```bash
python main.py analyze sample.exe --format all
```

### Quick file identification
```bash
python main.py identify suspicious_file
```

### Extract strings only
```bash
python main.py strings sample.exe
```

### Re-generate report from saved JSON
```bash
python main.py analyze output/sample_analysis.json --report-only
```

### Start MCP server (for Claude / AI agent integration)
```bash
python main.py mcp-server
```

---

## Report formats

| Format | Description |
|---|---|
| HTML | Full interactive report with syntax-highlighted sections |
| PDF | Printable report via ReportLab |
| DOCX | Word document via python-docx |
| JSON | Raw machine-readable analysis data |

Reports are saved to `./output/` by default.

---

## Threat Intelligence

- **MalwareBazaar** (abuse.ch) — free, no API key. Hash lookup against known malware database.
- **VirusTotal** — optional. Add your free API key to `config.yaml`.
- **Local SQLite database** (`output/samples.db`) — cross-session sample correlation by SHA256 and import hash (imphash). Automatically populated after every analysis.

---

## Auto-YARA Generation

For samples assessed as **HIGH** or **CRITICAL**, Malyzer automatically generates a YARA hunting rule based on:
- Unique suspicious strings found in the sample
- Suspicious imported functions
- File metadata patterns

Rules are saved to `output/yara/<sha256>.yar`.

---

## MCP Server

Malyzer exposes all analysis tools via the **Model Context Protocol (MCP)**, allowing Claude and other AI agents to call analysis functions directly.

Add to your MCP client config (`mcp_config.json` is pre-configured):
```json
{
  "mcpServers": {
    "malyzer": {
      "command": "python",
      "args": ["main.py", "mcp-server"]
    }
  }
}
```

---

## Project structure

```
malyzer/
├── main.py                  # CLI entry point
├── config.yaml              # Configuration
├── requirements.txt
├── install.bat              # FlareVM quick installer
├── rules/
│   └── packers.yar          # YARA rules for packer detection
└── malyze/
    ├── core/
    │   ├── agent.py         # Main 7-step analysis pipeline
    │   ├── orchestrator.py  # Agentic loops (static + dynamic)
    │   ├── tool_registry.py # Tool definitions + availability checks
    │   ├── environment.py   # OS detection + tool scanning
    │   ├── file_identifier.py
    │   └── workflow.py      # Thin wrapper (MCP + CLI compatibility)
    ├── static/
    │   ├── pe_analyzer.py
    │   ├── strings_extractor.py  # + XOR brute force
    │   ├── entropy_analyzer.py
    │   ├── packer_detector.py
    │   ├── disassembler.py
    │   ├── yara_generator.py     # Auto-YARA generation
    │   ├── office_analyzer.py
    │   ├── pdf_analyzer.py
    │   └── script_analyzer.py
    ├── dynamic/
    │   └── behavior_monitor.py  # Procmon, FakeNet, Regshot
    ├── intel/
    │   ├── lookup.py            # MalwareBazaar + VirusTotal
    │   └── sample_db.py         # SQLite cross-sample database
    ├── ai/
    │   └── ollama_analyzer.py   # Ollama LLM integration
    ├── report/
    │   ├── generator.py
    │   └── templates/report.html
    └── mcp/
        └── server.py            # MCP server
```

---

## Warning

**Dynamic analysis executes the malware sample.**
Always run with `--dynamic` inside an isolated sandbox (FlareVM snapshot, VM with no network, etc.).
Never run dynamic analysis on a production or personal machine.

---

## License

MIT
