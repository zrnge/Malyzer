"""
Workflow entry point — thin wrapper around MalyzeAgent.
Kept for backward compatibility with MCP server and main.py.
"""
# Malyzer v2.0.0

import json
from pathlib import Path
from typing import Optional, Callable
import yaml

from malyze.core.agent import MalyzeAgent


DEFAULT_CONFIG = {
    "ollama": {
        "host":             "http://localhost:11434",
        "model":            "llama3.2",
        "timeout":          900,
        "planner_timeout":  120,
    },
    "flarevm": {
        "strings": "strings64.exe",
        "floss":   "floss.exe",
        "capa":    "capa.exe",
        "die":     "diec.exe",
    },
    "analysis": {
        "string_min_length":     4,
        "high_entropy_threshold": 7.0,
        "dynamic_timeout":       60,
        "max_strings":           5000,
    },
    "output": {"dir": "./output"},
    "analyst": {
        "name": "Security Analyst",
        "org":  "Malware Analysis Lab",
    },
}


def load_config(config_path: Optional[str] = None) -> dict:
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            user_cfg = yaml.safe_load(f) or {}
        cfg = dict(DEFAULT_CONFIG)
        for key, val in user_cfg.items():
            if isinstance(val, dict) and key in cfg:
                cfg[key] = {**cfg[key], **val}
            else:
                cfg[key] = val
        return cfg
    return dict(DEFAULT_CONFIG)


class AnalysisWorkflow:
    """Legacy wrapper — delegates to MalyzeAgent."""

    def __init__(self, config: dict, log_fn: Optional[Callable] = None):
        self.cfg   = config
        self.agent = MalyzeAgent(config, log_fn)

    def run(
        self,
        file_path: str,
        analyst_name: Optional[str] = None,
        run_dynamic: bool = False,
        output_dir: Optional[str] = None,
    ) -> dict:
        analyst = analyst_name or self.cfg.get("analyst", {}).get("name", "Analyst")

        if output_dir:
            self.cfg.setdefault("output", {})["dir"] = output_dir

        analysis = self.agent.run(
            file_path    = file_path,
            analyst_name = analyst,
            run_dynamic  = run_dynamic,
        )

        # Save raw JSON
        out_dir = Path(output_dir or self.cfg.get("output", {}).get("dir", "./output"))
        out_dir.mkdir(parents=True, exist_ok=True)
        sample_name = Path(file_path).stem
        json_path   = out_dir / f"{sample_name}_analysis.json"

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(_make_serializable(analysis), f, indent=2, ensure_ascii=False)

        self.agent.log(f"      Saved: {json_path}")
        return analysis


def _make_serializable(obj):
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_make_serializable(i) for i in obj]
    return obj
