"""
Environment detection — OS, Python libs, CLI tools, system info.
Results are passed to the AI planner so it knows exactly what's available.
"""

import os
import sys
import platform
import subprocess
import importlib
import shutil
from pathlib import Path
from typing import Optional

from malyze.core.tool_registry import CATALOG, check_availability, T_BUILTIN, T_PYTHON_LIB, T_CLI


def get_os_info() -> dict:
    return {
        "system":   platform.system(),        # Windows / Linux / Darwin
        "release":  platform.release(),
        "version":  platform.version(),
        "machine":  platform.machine(),
        "is_windows": sys.platform == "win32",
        "is_linux":   sys.platform.startswith("linux"),
        "python":   sys.version,
    }


def scan_all_tools(cfg: dict = None) -> dict:
    """
    Check every tool in the catalog for availability.
    Returns: { tool_id: {available, path_or_module, recommendation, ...catalog meta} }
    """
    cfg = cfg or {}
    is_windows = sys.platform == "win32"
    results = {}

    for tool_id, entry in CATALOG.items():
        # Skip tools for wrong OS
        os_restriction = entry.get("os")
        if os_restriction:
            if is_windows and "windows" not in os_restriction:
                results[tool_id] = {
                    "available": False,
                    "skip": True,
                    "reason": f"Windows-only tool, current OS: {platform.system()}",
                    "name": entry.get("name", tool_id),
                }
                continue
            if not is_windows and "linux" not in os_restriction:
                results[tool_id] = {
                    "available": False,
                    "skip": True,
                    "reason": f"Linux-only tool, current OS: {platform.system()}",
                    "name": entry.get("name", tool_id),
                }
                continue

        status = check_availability(tool_id, cfg, is_windows)
        results[tool_id] = {
            **status,
            "name":        entry.get("name", tool_id),
            "description": entry.get("description", ""),
            "category":    entry.get("category", ""),
            "file_types":  entry.get("file_types", []),
            "type":        entry.get("type", ""),
        }

    return results


def get_available_tools(env_scan: dict) -> list:
    return [tid for tid, info in env_scan.items() if info.get("available") and not info.get("skip")]


def get_missing_tools(env_scan: dict) -> list:
    return [tid for tid, info in env_scan.items()
            if not info.get("available") and not info.get("skip")]


def format_env_for_ai(os_info: dict, env_scan: dict, file_type: str) -> str:
    """
    Build a concise text summary of the environment for the AI planner.
    """
    lines = [
        "## Analysis Environment",
        f"- OS: {os_info['system']} {os_info['release']}",
        f"- Architecture: {os_info['machine']}",
        f"- Python: {os_info['python'].split()[0]}",
        "",
        f"## Target File Type: {file_type}",
        "",
        "## Available Tools",
    ]

    # Group by category
    cats = {}
    for tid, info in env_scan.items():
        if info.get("available") and not info.get("skip"):
            cat = info.get("category", "other")
            cats.setdefault(cat, []).append((tid, info))

    for cat, tools in sorted(cats.items()):
        lines.append(f"\n### {cat.title()}")
        for tid, info in tools:
            lines.append(f"  - `{tid}`: {info.get('description','')}")

    missing_relevant = [
        (tid, info) for tid, info in env_scan.items()
        if not info.get("available") and not info.get("skip")
        and ("*" in info.get("file_types", []) or file_type in info.get("file_types", []))
    ]

    if missing_relevant:
        lines += ["", "## Missing Tools (relevant to this file type)"]
        for tid, info in missing_relevant[:15]:
            lines.append(f"  - `{tid}` ({info.get('name','')}): not found on this system")

    return "\n".join(lines)


def print_missing_tool_recommendations(env_scan: dict, file_type: str, log_fn=None):
    """
    Print install recommendations for missing tools relevant to the file type.
    """
    _print = log_fn or print
    missing = [
        (tid, info) for tid, info in env_scan.items()
        if not info.get("available") and not info.get("skip")
        and ("*" in info.get("file_types", []) or file_type in info.get("file_types", []))
        and info.get("recommendation")
    ]
    if not missing:
        return

    _print("\n[TOOL RECOMMENDATIONS]")
    _print(f"The following tools are not installed but could improve analysis of {file_type} files:")
    _print("-" * 60)
    for tid, info in missing:
        _print(f"\n  {info.get('name', tid)}")
        for line in info.get("recommendation", "").splitlines():
            _print(f"    {line}")
    _print("-" * 60)
