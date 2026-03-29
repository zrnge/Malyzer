#!/usr/bin/env python3
"""
Malyzer — AI-Powered Malware Analysis Framework
CLI entry point
"""

import sys
import os
import json
from pathlib import Path

import io

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

# Force UTF-8 output on Windows to avoid cp1252 encode errors
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

console = Console(highlight=False)

BANNER = """
[bold cyan]
  __  __       _
 |  \\/  | __ _| |_   _ _______ _ __
 | |\\/| |/ _` | | | | |_  / _ \\ '__|
 | |  | | (_| | | |_| |/ /  __/ |
 |_|  |_|\\__,_|_|\\__, /___\\___|_|
                  |___/
[/bold cyan][dim]  AI-Powered Malware Analysis Framework v2.0 | FlareVM Edition[/dim]
"""


def get_config(config_path: str):
    sys.path.insert(0, str(Path(__file__).parent))
    from malyze.core.workflow import load_config
    return load_config(config_path)


@click.group()
@click.version_option("2.0.0", prog_name="malyzer")
def cli():
    """Malyzer — AI-Powered Malware Analysis Framework"""
    pass


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--analyst", "-a", default="", help="Analyst name for the report")
@click.option("--dynamic", "-d", is_flag=True, default=False, help="Enable dynamic analysis (sandbox only!)")
@click.option("--output", "-o", default="./output", help="Output directory", show_default=True)
@click.option("--config", "-c", default="./config.yaml", help="Config file path", show_default=True)
@click.option("--model", "-m", default="", help="Ollama model override (e.g. llama3.2, mistral)")
@click.option("--no-ai", is_flag=True, default=False, help="Skip AI analysis")
@click.option("--format", "-f", "fmt",
              default="all",
              type=click.Choice(["all", "html", "pdf", "docx", "json"], case_sensitive=False),
              show_default=True,
              help="Report format: all | html | pdf | docx | json")
@click.option("--report-only", is_flag=True, default=False,
              help="Generate report from existing JSON (skip analysis)")
def analyze(file_path, analyst, dynamic, output, config, model, no_ai, fmt, report_only):
    """Analyze a malware sample — full pipeline.

    \b
    Report formats:
      --format all    Generate HTML + PDF + DOCX + JSON  (default)
      --format html   HTML report only
      --format pdf    PDF report only
      --format docx   Word document only
      --format json   Raw JSON data only
    """
    console.print(BANNER)

    cfg = get_config(config)
    if model:
        cfg["ollama"]["model"] = model
    if analyst:
        cfg["analyst"]["name"] = analyst

    from malyze.core.workflow import AnalysisWorkflow
    from malyze.report.generator import generate_report, generate_all

    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    if report_only:
        json_path = Path(file_path)
        if json_path.suffix != ".json":
            console.print("[red]--report-only requires a JSON analysis file[/red]")
            sys.exit(1)
        with open(json_path) as f:
            analysis = json.load(f)
        base = str(out_dir / json_path.stem)
        _generate_and_print(analysis, base, fmt, out_dir, console)
        return

    logs = []

    def log_fn(msg, level="info"):
        if level == "warning":
            console.print(f"[yellow]{msg}[/yellow]")
        elif level == "error":
            console.print(f"[red]{msg}[/red]")
        else:
            console.print(f"[dim]{msg}[/dim]")
        logs.append(msg)

    if no_ai:
        cfg["ollama"]["host"] = ""

    workflow = AnalysisWorkflow(cfg, log_fn=log_fn)

    try:
        analysis = workflow.run(
            file_path=file_path,
            analyst_name=analyst or cfg.get("analyst", {}).get("name", "Analyst"),
            run_dynamic=dynamic,
            output_dir=output,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Analysis error: {e}[/red]")
        raise

    sample_name = Path(file_path).stem
    base = str(out_dir / f"{sample_name}_report")
    report_paths = _generate_and_print(analysis, base, fmt, out_dir, console)


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--config", "-c", default="./config.yaml", show_default=True)
def identify(file_path, config):
    """Quickly identify a file type and compute hashes."""
    from malyze.core.file_identifier import identify_file
    result = identify_file(file_path)

    table = Table(title="File Identification", style="cyan")
    table.add_column("Property", style="dim")
    table.add_column("Value")

    table.add_row("Name",      result["name"])
    table.add_row("Type",      f"[bold cyan]{result['type']}[/bold cyan]")
    table.add_row("Extension", result["extension"])
    table.add_row("Size",      f"{result['hashes']['size']:,} bytes")
    table.add_row("MD5",       result["hashes"]["md5"])
    table.add_row("SHA1",      result["hashes"]["sha1"])
    table.add_row("SHA256",    result["hashes"]["sha256"])
    table.add_row("Magic",     result["magic_bytes"])
    table.add_row("Tools",     ", ".join(result["tools"]))

    console.print(table)


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
def strings(file_path):
    """Extract and categorize strings from a file."""
    from malyze.static.strings_extractor import extract_strings

    console.print(f"[cyan]Extracting strings from:[/cyan] {file_path}")
    result = extract_strings(file_path)

    console.print(f"\n[green]Extracted {result['total']} strings via {result['source']}[/green]")

    iocs = result.get("iocs", {})
    if iocs:
        console.print("\n[bold red]IOCs Found:[/bold red]")
        for cat, items in iocs.items():
            console.print(f"\n  [yellow]{cat.upper()}[/yellow]")
            for item in items[:20]:
                console.print(f"    {item}")

    console.print(f"\n[dim]First 50 strings:[/dim]")
    for s in result["strings"][:50]:
        console.print(f"  {s}")


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
def entropy(file_path):
    """Calculate file entropy to detect packing/encryption."""
    from malyze.static.entropy_analyzer import analyze_file_entropy

    result = analyze_file_entropy(file_path)

    color = "green"
    if result["suspicious"]:
        color = "red"
    elif result["overall_entropy"] >= 6.0:
        color = "yellow"

    panel = Panel(
        f"[bold]Entropy:[/bold] [{color}]{result['overall_entropy']}[/{color}]\n"
        f"[bold]Class:[/bold]   {result['classification']}\n"
        f"[bold]Suspicious:[/bold] [{color}]{result['suspicious']}[/{color}]\n"
        f"[bold]High Entropy Blocks:[/bold] {result['high_entropy_blocks']}/{result['total_blocks']}",
        title="Entropy Analysis",
        border_style=color,
    )
    console.print(panel)


@cli.command("mcp-server")
@click.option("--config", "-c", default="./config.yaml", show_default=True)
def mcp_server(config):
    """Start the Malyzer MCP server for Claude/AI tool integration."""
    console.print(BANNER)
    console.print("[green]Starting Malyzer MCP Server...[/green]")
    console.print("[dim]Claude and AI agents can now use Malyzer tools via MCP.[/dim]\n")

    # Change working dir to project root so config resolves correctly
    os.chdir(Path(__file__).parent)
    from malyze.mcp.server import main
    main()


def _generate_and_print(analysis, base, fmt, out_dir, console):
    from malyze.report.generator import generate_report, generate_all

    console.print("\n[cyan][7/7] Generating reports...[/cyan]")

    if fmt == "all":
        results = generate_all(analysis, base)
    else:
        out_path = f"{base}.{fmt}"
        try:
            path = generate_report(analysis, out_path, fmt=fmt)
            results = {fmt: path}
        except Exception as e:
            results = {fmt: f"ERROR: {e}"}

    table = Table(title="Generated Reports", style="cyan")
    table.add_column("Format", style="bold")
    table.add_column("File")
    table.add_column("Status")

    for f, p in results.items():
        if isinstance(p, str) and p.startswith("ERROR"):
            table.add_row(f.upper(), p, "[red]FAILED[/red]")
            console.print(f"[red]  {f.upper()} error:[/red] {p}")
        else:
            table.add_row(f.upper(), p, "[green]OK[/green]")

    console.print(table)
    _print_summary(analysis, results, console)
    return results


def _print_summary(analysis: dict, report_paths: dict, console: Console):
    from malyze.report.generator import _threat_level
    threat_level, _, _ = _threat_level(analysis)

    color_map = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "green"}
    color = color_map.get(threat_level, "white")

    console.print()
    console.print(Panel(
        f"[bold {color}]THREAT LEVEL: {threat_level}[/bold {color}]",
        title="Analysis Complete",
        border_style=color,
    ))

    table = Table(title="Summary", style="cyan")
    table.add_column("Category")
    table.add_column("Finding")

    fi = analysis.get("file_info", {})
    table.add_row("File", fi.get("name", "N/A"))
    table.add_row("Type", fi.get("type", "N/A"))
    table.add_row("SHA256", fi.get("hashes", {}).get("sha256", "N/A"))

    static = analysis.get("static", {})
    entropy_data = static.get("entropy", {})
    if entropy_data:
        e_color = "red" if entropy_data.get("suspicious") else "green"
        table.add_row("Entropy", f"[{e_color}]{entropy_data.get('overall_entropy')} — {entropy_data.get('classification')}[/{e_color}]")

    packer = static.get("packer", {})
    if packer:
        if packer.get("detected_packers"):
            table.add_row("Packers", f"[red]{', '.join(packer['detected_packers'][:3])}[/red]")
        else:
            table.add_row("Packers", "[green]None detected[/green]")

    pe = static.get("pe", {})
    if pe and not pe.get("error"):
        susp = pe.get("suspicious_imports", [])
        color_si = "red" if susp else "green"
        table.add_row("Suspicious Imports", f"[{color_si}]{len(susp)}[/{color_si}]")

    ai = analysis.get("ai_analysis", {})
    if ai.get("error"):
        table.add_row("AI Analysis", f"[red]Error: {ai['error']}[/red]")
    elif ai.get("analysis"):
        table.add_row("AI Analysis", "[green]Complete[/green]")

    if isinstance(report_paths, dict):
        for fmt, p in report_paths.items():
            if not (isinstance(p, str) and p.startswith("ERROR")):
                table.add_row(f"Report ({fmt.upper()})", p)
    elif isinstance(report_paths, str):
        table.add_row("Report", report_paths)

    console.print(table)


if __name__ == "__main__":
    cli()
