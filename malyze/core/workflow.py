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
        "api_key":          "",
    },
    "flarevm": {
        "strings":    "strings64.exe",
        "floss":      "floss.exe",
        "capa":       "capa.exe",
        "die":        "diec.exe",
        "tshark":     "tshark.exe",
        "autorunsc":  "autorunsc.exe",
        "procdump":   "procdump64.exe",
        "fakenet":    "FakeNet.exe",
        "regshot":    "Regshot-x64-Unicode.exe",
    },
    "analysis": {
        "string_min_length":      4,
        "high_entropy_threshold": 7.0,
        "dynamic_timeout":        60,
        "max_strings":            5000,
        "max_static_iterations":  20,    # agentic loop cap (static)
        "max_dynamic_iterations": 10,    # agentic loop cap (dynamic)
        "tshark_capture_seconds": 60,
        "tshark_interface":       "",
    },
    "output": {"dir": "./output"},
    "analyst": {
        "name": "Security Analyst",
        "org":  "Malware Analysis Lab",
    },
    "intel": {
        "malwarebazaar":      True,
        "circl_hashlookup":   True,
        "virustotal_api_key": "",
        "shodan_api_key":     "",
        "otx_api_key":        "",
    },
    "web": {
        "api_key": "",
    },
}


def load_config(config_path: Optional[str] = None) -> dict:
    import os
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            user_cfg = yaml.safe_load(f) or {}
        cfg = dict(DEFAULT_CONFIG)
        for key, val in user_cfg.items():
            if isinstance(val, dict) and key in cfg:
                cfg[key] = {**cfg[key], **val}
            else:
                cfg[key] = val
    else:
        cfg = dict(DEFAULT_CONFIG)

    # Environment variable overrides — useful when Malyze runs in a sandbox
    # and Ollama runs on the host machine.
    # OLLAMA_HOST  e.g. http://192.168.1.10:11434
    # OLLAMA_MODEL e.g. mistral
    # OLLAMA_API_KEY
    env_host  = os.environ.get("OLLAMA_HOST", "").strip()
    env_model = os.environ.get("OLLAMA_MODEL", "").strip()
    env_key   = os.environ.get("OLLAMA_API_KEY", "").strip()
    if env_host:
        cfg.setdefault("ollama", {})["host"] = env_host
    if env_model:
        cfg.setdefault("ollama", {})["model"] = env_model
    if env_key:
        cfg.setdefault("ollama", {})["api_key"] = env_key

    return cfg


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
        run_static: bool = True,
        output_dir: Optional[str] = None,
    ) -> dict:
        analyst = analyst_name or self.cfg.get("analyst", {}).get("name", "Analyst")

        if output_dir:
            self.cfg.setdefault("output", {})["dir"] = output_dir

        analysis = self.agent.run(
            file_path    = file_path,
            analyst_name = analyst,
            run_dynamic  = run_dynamic,
            run_static   = run_static,
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
