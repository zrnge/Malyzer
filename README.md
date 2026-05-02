# Malyze — AI-Powered Malware Analysis Framework

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Ollama](https://img.shields.io/badge/LLM-Ollama-black?style=flat&logo=ollama&logoColor=white)
![FlareVM](https://img.shields.io/badge/FlareVM-Compatible-red?style=flat)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-E2231A?style=flat)
![MCP](https://img.shields.io/badge/MCP-Server-6B46C1?style=flat&logo=anthropic&logoColor=white)
![Version](https://img.shields.io/badge/Version-2.1-blue?style=flat)

> An agentic, tool-by-tool malware analysis framework driven by a local LLM (Ollama).
> Built for **FlareVM** sandbox environments. Fully offline — no cloud dependencies required.

---

## Overview

Malyze automates the complete malware analysis workflow. Instead of running every tool and dumping the output, the AI acts as an analyst: it picks **one tool at a time**, reads the result, forms a hypothesis, and decides what to investigate next — exactly how a human analyst works.

**Key capabilities at a glance:**

- Agentic static loop (up to 20 AI-driven iterations)
- Agentic dynamic loop with live Procmon/FakeNet/tshark/Regshot/ProcDump
- Sample-filtered behavioral events (noise from Explorer/MsMpEng/Edge excluded)
- CPU emulation via Speakeasy (Mandiant) for unpacked code analysis
- Automatic UPX unpacking before analysis
- DGA domain detection on observed DNS queries
- IOC enrichment (GeoIP, URLhaus, passive DNS)
- Threat intelligence — MalwareBazaar, CIRCL hash lookup, VirusTotal, Shodan, AlienVault OTX
- Auto-generated YARA hunting rule for HIGH/CRITICAL samples
- STIX 2.1 bundle export
- Web UI with live log streaming and API
- MCP server for Claude / AI agent integration
- Local SQLite sample database with cross-session correlation by SHA256 and imphash

---

## Architecture

```
main.py  ──  web / CLI / MCP
              └── AnalysisWorkflow  (workflow.py)
                    └── MalyzeAgent  (agent.py)
                          │
                          ├── Step 1  OS & tool inventory      (environment.py, tool_registry.py)
                          ├── Step 2  File ID + threat intel   (file_identifier.py, intel/)
                          ├── Step 3  Agentic static loop      (orchestrator.AgenticOrchestrator)
                          │             AI picks tool → run → AI sees result → repeat
                          ├── Step 4  Tool inventory report
                          ├── Step 5  Agentic dynamic loop     (orchestrator.DynamicOrchestrator)
                          │             Pre-exec:  FakeNet · Procmon · tshark · Autoruns baseline
                          │             Execute:   sample runs in a detached process (psutil-supervised)
                          │             Post-exec: Autoruns diff · Regshot diff · ProcDump
                          │             RAG DB:    Procmon CSV → SQLite for active threat hunting
                          ├── Step 6  Final AI synthesis       (ai/ollama_analyzer.py)
                          └── Step 7  DB save + auto-YARA      (intel/sample_db.py, static/yara_generator.py)
```

---

## Static Analysis Tools

| Tool | Purpose |
|---|---|
| FLOSS | String extraction + deobfuscation |
| strings64 (Sysinternals) | Raw printable string extraction |
| Detect-It-Easy (DIE) | Packer / compiler / protector detection |
| CAPA | Capability detection mapped to MITRE ATT&CK |
| UPX | Automatic unpacking of UPX-packed binaries |
| pefile (Python) | PE headers, imports, sections, rich header, overlay |
| Capstone / objdump | Disassembly (x86/x64) |
| YARA | Custom rule matching |
| Speakeasy (Mandiant) | CPU emulation — API tracing, dynamic strings, network stubs |
| Entropy analysis | Per-section entropy + high-entropy block detection |
| XOR brute-force | 1-byte and 2-byte key deobfuscation |
| pyelftools / readelf | ELF binary analysis |
| oletools | Office macro analysis, VBA extraction |
| pdfminer | PDF text, stream extraction, JavaScript detection |
| Script analyzer | PowerShell / JS / VBS / batch obfuscation scoring |

## Dynamic Analysis Tools

| Tool | Purpose |
|---|---|
| Procmon64 | Process / file / registry event capture |
| FakeNet-NG | Fake DNS/HTTP/SMTP services for network interception |
| tshark | Live packet capture → pcap |
| autorunsc | Persistence baseline snapshot → diff |
| Regshot | Full registry snapshot → diff |
| ProcDump | Memory dump of the spawned malware process |

---

## Threat Intelligence Sources

| Source | Key Required | Notes |
|---|---|---|
| MalwareBazaar (abuse.ch) | No | Hash lookup — free, always on |
| CIRCL hash lookup | No | Community hash DB (NSRL + malware) |
| VirusTotal | Optional | 60-70 AV engines; free tier 4 req/min |
| Shodan | Optional | IP intelligence — open ports, banners |
| AlienVault OTX | Optional | Threat pulse feed |
| URLhaus | No | Malicious URL/IP lookup built into IOC enrichment |
| Passive DNS | No | Historical DNS resolution for extracted domains |
| DGA Detector | — | Statistical scoring of observed DNS queries |

---

## Requirements

### System
- **Windows 10 / 11** (FlareVM recommended for dynamic analysis)
- **Python 3.10+**
- **[Ollama](https://ollama.com)** running locally (or on a host machine reachable from the sandbox)

### Recommended models
```
ollama pull mistral
ollama pull llama3.1
ollama pull gemma2
ollama pull deepseek-r1
```

### Python dependencies
```
pip install -r requirements.txt
```

### FlareVM tools (optional — each enables additional analysis modules)

| Tool | Source |
|---|---|
| FLOSS | github.com/mandiant/flare-floss |
| Detect-It-Easy (diec.exe) | github.com/horsicq/Detect-It-Easy |
| CAPA | github.com/mandiant/capa |
| strings64.exe | learn.microsoft.com/sysinternals |
| Procmon64.exe | learn.microsoft.com/sysinternals |
| autorunsc.exe | learn.microsoft.com/sysinternals |
| procdump64.exe | learn.microsoft.com/sysinternals |
| tshark.exe | wireshark.org |
| FakeNet.exe | github.com/mandiant/flare-fakenet-ng |
| Regshot-x64-Unicode.exe | sourceforge.net/projects/regshot |
| yara64.exe | virustotal.github.io/yara |
| upx.exe | github.com/upx/upx |

---

## Installation

```bash
git clone https://github.com/zrnge/malyzer.git
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
  host: "http://localhost:11434"   # or your host machine's LAN IP if running in a sandbox
  model: "mistral"                 # any model you have pulled
  timeout: 900

flarevm:
  floss:     "floss.exe"
  capa:      "capa.exe"
  die:       "diec.exe"
  strings:   "strings64.exe"
  procmon:   "Procmon64.exe"
  tshark:    "tshark.exe"
  autorunsc: "autorunsc.exe"
  procdump:  "procdump64.exe"
  fakenet:   "FakeNet.exe"
  regshot:   "Regshot-x64-Unicode.exe"
  upx:       "upx.exe"

analysis:
  max_static_iterations:  20   # AI tool-selection loops (static phase)
  max_dynamic_iterations: 10   # AI tool-selection loops (dynamic phase)
  tshark_capture_seconds: 60
  dynamic_timeout:        60   # seconds the sample runs before being killed

intel:
  malwarebazaar:    true        # free, no key needed
  circl_hashlookup: true        # free, no key needed
  virustotal_api_key: ""        # optional
  shodan_api_key:     ""        # optional
  otx_api_key:        ""        # optional

output:
  dir:           "./output"
  report_format: html           # html | pdf | json | all

analyst:
  name: "Security Analyst"
  org:  "Malware Analysis Lab"
```

### Remote Ollama (sandbox → host machine)

If Malyze runs inside a VM/sandbox and Ollama is on your host:

1. On the host, allow Ollama to listen on all interfaces:
   ```powershell
   # Windows
   $env:OLLAMA_HOST="0.0.0.0:11434"; ollama serve
   ```
2. Set `host` in `config.yaml` to the host's LAN IP, or override at runtime:
   ```powershell
   $env:OLLAMA_HOST="http://192.168.1.10:11434"
   python main.py analyze sample.exe
   ```

---

## Usage

### Web UI
```bash
python main.py web
```
Opens at `http://localhost:5000` — drag-and-drop file upload, toggle static/dynamic analysis, live log streaming, report download.

### Full analysis (CLI)
```bash
python main.py analyze malware_sample.exe
```

### With dynamic analysis (run inside a sandbox!)
```bash
python main.py analyze malware_sample.exe --dynamic
```

### Specify report format
```bash
python main.py analyze sample.exe --format html   # html | pdf | json | all
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

### MCP server (Claude / AI agent integration)
```bash
python main.py mcp-server
```

---

## Report Formats

| Format | Contents |
|---|---|
| **HTML** | Full interactive report — TTPs, IOCs, per-tool findings, YARA rule, STIX export link |
| **PDF** | Printable version via ReportLab |
| **JSON** | Raw machine-readable analysis data |
| **STIX 2.1** | Threat intelligence bundle (Malware SDO + Indicators + Attack Patterns) |

Reports are saved to `./output/` by default (one subdirectory per sample).

---

## YARA Auto-Generation

For samples assessed as **HIGH** or **CRITICAL**, Malyze automatically generates a YARA hunting rule based on:
- Unique suspicious strings extracted from the sample
- Suspicious imported functions (e.g. `VirtualAlloc`, `WriteProcessMemory`)
- File metadata and section characteristics

Rules are saved to `output/<sample_name>/sample.yar`.

---

## MCP Server

Malyze exposes all analysis functions via the **Model Context Protocol (MCP)**, allowing Claude Desktop and other MCP-compatible agents to call tools directly.

Add to your MCP client config:
```json
{
  "mcpServers": {
    "malyze": {
      "command": "python",
      "args": ["main.py", "mcp-server"]
    }
  }
}
```

---

## Project Structure

```
malyze/
├── main.py                       # CLI entry point (click)
├── config.yaml                   # All configuration
├── requirements.txt
├── install.bat                   # FlareVM quick installer
├── mcp_config.json               # MCP client config template
├── rules/
│   └── packers.yar               # YARA rules for packer detection
└── malyze/
    ├── core/
    │   ├── agent.py              # 7-step analysis pipeline
    │   ├── orchestrator.py       # Agentic loops (AgenticOrchestrator + DynamicOrchestrator)
    │   ├── tool_registry.py      # Tool definitions + availability scanning
    │   ├── environment.py        # OS detection + tool inventory
    │   ├── file_identifier.py    # File type detection + hash computation
    │   └── workflow.py           # CLI / Web / MCP entry wrapper
    ├── static/
    │   ├── pe_analyzer.py        # PE headers, imports, sections
    │   ├── strings_extractor.py  # String extraction + XOR brute-force
    │   ├── entropy_analyzer.py   # Section entropy analysis
    │   ├── packer_detector.py    # Packer / protector identification
    │   ├── disassembler.py       # Capstone disassembly
    │   ├── emulation_analyzer.py # Speakeasy CPU emulation
    │   ├── unpacker.py           # Automatic UPX unpacking
    │   ├── yara_generator.py     # Auto-YARA rule generation
    │   ├── office_analyzer.py    # Office macro / OLE analysis
    │   ├── pdf_analyzer.py       # PDF analysis
    │   └── script_analyzer.py    # Script obfuscation scoring
    ├── dynamic/
    │   ├── behavior_monitor.py   # Procmon, FakeNet, Regshot orchestration
    │   └── rag_db.py             # Procmon CSV → SQLite for AI threat hunting
    ├── intel/
    │   ├── lookup.py             # MalwareBazaar + VirusTotal + Shodan + OTX
    │   ├── deep_intel.py         # Extended intelligence analysis
    │   ├── enrichment.py         # GeoIP + URLhaus IOC enrichment
    │   ├── dga_detector.py       # DGA domain scoring
    │   ├── pdns.py               # Passive DNS resolution
    │   └── sample_db.py          # SQLite cross-sample correlation database
    ├── ai/
    │   └── ollama_analyzer.py    # Ollama LLM integration + prompt construction
    ├── report/
    │   ├── generator.py          # HTML / PDF / JSON report generation
    │   ├── stix_export.py        # STIX 2.1 bundle export
    │   └── templates/
    ├── mcp/
    │   └── server.py             # MCP server (tool exposure)
    └── web/
        ├── server.py             # Flask web server + REST API
        └── templates/
            └── index.html        # Web UI
```

---

## Security Warning

**Dynamic analysis executes the malware sample on the host machine.**

- Always run `--dynamic` inside an isolated sandbox (FlareVM with a clean snapshot, air-gapped VM, or similar)
- Never run dynamic analysis on a production or personal machine
- The web UI binds to `localhost` only by default — do not expose it on a network interface without setting a strong `web.api_key` in `config.yaml`

---

## License

MIT
