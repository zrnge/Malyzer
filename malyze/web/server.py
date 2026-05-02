"""
Malyzer Web UI — Flask server with real-time SSE streaming.

Routes:
  GET  /                              Main UI
  GET  /api/tools                     Tool catalog + availability
  POST /api/analyze                   Upload file + start analysis job
  POST /api/batch                     Upload multiple files as a batch
  GET  /api/queue                     Batch queue status
  GET  /api/stream/<job_id>           SSE: live log stream
  GET  /api/status/<job_id>           Job status + result summary
  GET  /api/report/<job_id>           Inline HTML report
  GET  /api/download/<job_id>/<fmt>   Download PDF / DOCX / JSON / STIX
  POST /api/skip/<job_id>             Skip current tool
  POST /api/stop/<job_id>             Abort job
  GET  /api/ollama-models             Available local Ollama models
  GET  /api/ollama-status             Ollama reachability + active model

Authentication (optional):
  If config.yaml sets web.api_key, all /api/* routes require either:
    - Header:  Authorization: Bearer <key>
    - Query:   ?api_key=<key>
  The browser UI sends the key automatically once entered in the config panel.
"""

import functools
import json
import os
import queue
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from flask import (
    Flask, Response, jsonify, render_template, request,
    send_file, stream_with_context,
)

# ── Project root on path ─────────────────────────────────────────────────────
_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_ROOT))

app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # 512 MB max upload

_UPLOAD_DIR = _ROOT / "output" / "uploads"
_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ── Optional API-key authentication ──────────────────────────────────────────

def _get_configured_api_key() -> str:
    """Return the configured API key (empty string = auth disabled)."""
    try:
        from malyze.core.workflow import load_config
        cfg = load_config(str(_ROOT / "config.yaml"))
        return cfg.get("web", {}).get("api_key", "")
    except Exception:
        return ""


def _check_auth() -> bool:
    """Return True if request is authorised (or auth is disabled)."""
    key = _get_configured_api_key()
    if not key:
        return True
    # Accept from header or query string
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer ") and header[7:] == key:
        return True
    if request.args.get("api_key") == key:
        return True
    return False


def require_auth(fn):
    """Decorator — returns 401 if API key is configured but not provided."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not _check_auth():
            return jsonify({"error": "Unauthorized — provide a valid API key"}), 401
        return fn(*args, **kwargs)
    return wrapper

# ── Job registry ─────────────────────────────────────────────────────────────

@dataclass
class Job:
    job_id:      str
    status:      str = "pending"     # pending | running | done | error
    log_q:       queue.Queue = field(default_factory=queue.Queue)
    result:      Optional[dict] = None
    reports:     dict = field(default_factory=dict)   # {fmt: path}
    error:       Optional[str] = None
    sample:      str = ""
    threat:      str = ""
    skip_event:  threading.Event = field(default_factory=threading.Event)
    stop_event:  threading.Event = field(default_factory=threading.Event)
    current_tool: str = ""    # name of the tool currently running (for UI display)

_jobs: dict[str, Job] = {}
_jobs_lock = threading.Lock()


# ── Tool catalog API ──────────────────────────────────────────────────────────

@app.route("/api/tools")
def api_tools():
    """Return the full tool catalog with real-time availability for this system."""
    from malyze.core.tool_registry import CATALOG
    from malyze.core.environment import scan_all_tools
    from malyze.core.workflow import load_config

    cfg_path = str(_ROOT / "config.yaml")
    cfg = load_config(cfg_path)
    env_scan = scan_all_tools(cfg)

    tools = []
    for tid, meta in CATALOG.items():
        availability = env_scan.get(tid, {})
        tools.append({
            "tool_id":     tid,
            "name":        meta.get("name", tid),
            "description": meta.get("description", ""),
            "category":    meta.get("category", "static"),
            "file_types":  meta.get("file_types", ["*"]),
            "available":   availability.get("available", False),
            "install_cmd": (meta.get("install_cmd")
                            or meta.get("install_windows")
                            or meta.get("install_linux", "")),
            "source":      meta.get("source", ""),
            "note":        meta.get("note", ""),
            "timeout":     meta.get("timeout", 60),
        })

    # Sort: available first, then by category (static before dynamic), then name
    tools.sort(key=lambda t: (not t["available"], t["category"] == "dynamic", t["name"]))
    return jsonify(tools)


# ── File upload + analysis start ─────────────────────────────────────────────

@app.route("/api/analyze", methods=["POST"])
@require_auth
def api_analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    # Parse JSON config from form field
    try:
        cfg_raw    = request.form.get("config", "{}")
        ui_config  = json.loads(cfg_raw)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid config JSON"}), 400

    job_id  = uuid.uuid4().hex
    job     = Job(job_id=job_id, sample=f.filename)

    # Save uploaded file
    safe_name  = Path(f.filename).name
    upload_path = _UPLOAD_DIR / f"{job_id}_{safe_name}"
    f.save(str(upload_path))

    with _jobs_lock:
        _jobs[job_id] = job

    # Start analysis in background thread
    t = threading.Thread(
        target=_run_analysis,
        args=(job, str(upload_path), ui_config),
        daemon=True,
    )
    t.start()

    return jsonify({"job_id": job_id})


# ── Batch upload ──────────────────────────────────────────────────────────────

@app.route("/api/batch", methods=["POST"])
@require_auth
def api_batch():
    """
    Accept multiple files in one request and enqueue them all.
    Form fields:
      files[]    — one or more files
      config     — JSON config string (same schema as /api/analyze)
    Returns {batch_id, job_ids: [...], queued: N}
    """
    files = request.files.getlist("files[]") or request.files.getlist("file")
    if not files:
        return jsonify({"error": "No files uploaded"}), 400

    try:
        cfg_raw   = request.form.get("config", "{}")
        ui_config = json.loads(cfg_raw)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid config JSON"}), 400

    batch_id = uuid.uuid4().hex
    job_ids  = []

    for f in files:
        if not f.filename:
            continue
        job_id      = uuid.uuid4().hex
        safe_name   = Path(f.filename).name
        upload_path = _UPLOAD_DIR / f"{job_id}_{safe_name}"
        f.save(str(upload_path))

        job = Job(job_id=job_id, sample=f.filename)
        with _jobs_lock:
            _jobs[job_id] = job

        t = threading.Thread(
            target=_run_analysis,
            args=(job, str(upload_path), ui_config),
            daemon=True,
        )
        t.start()
        job_ids.append(job_id)

    return jsonify({"batch_id": batch_id, "job_ids": job_ids, "queued": len(job_ids)})


@app.route("/api/queue")
@require_auth
def api_queue():
    """Return a summary of all known jobs for queue monitoring."""
    with _jobs_lock:
        snapshot = list(_jobs.values())
    summary = [
        {
            "job_id":  j.job_id,
            "sample":  j.sample,
            "status":  j.status,
            "threat":  j.threat,
            "error":   j.error,
        }
        for j in snapshot
    ]
    counts = {s: sum(1 for j in snapshot if j.status == s)
              for s in ("pending", "running", "done", "error")}
    return jsonify({"jobs": summary, "counts": counts, "total": len(summary)})


def _run_analysis(job: Job, file_path: str, ui_config: dict):
    """Background thread: runs the full Malyzer pipeline and streams logs."""
    def log_fn(msg: str, level: str = "info"):
        job.log_q.put({"type": "log", "level": level, "msg": msg})

    job.status = "running"
    try:
        from malyze.core.workflow import load_config, AnalysisWorkflow
        from malyze.report.generator import generate_all
        from malyze.core.agent import set_skip_event, set_stop_event

        # Arm skip/stop signals for this analysis thread
        set_skip_event(job.skip_event)
        set_stop_event(job.stop_event)

        cfg_path = str(_ROOT / "config.yaml")
        cfg = load_config(cfg_path)

        # Apply UI overrides
        if ui_config.get("model"):
            cfg["ollama"]["model"] = ui_config["model"]
        if ui_config.get("api_key"):
            cfg["ollama"]["api_key"] = ui_config["api_key"]
        if ui_config.get("analyst"):
            cfg["analyst"]["name"] = ui_config["analyst"]

        analyst    = ui_config.get("analyst") or cfg.get("analyst", {}).get("name", "Analyst")
        dynamic    = bool(ui_config.get("dynamic", False))
        static     = bool(ui_config.get("static", True))
        quick_mode = bool(ui_config.get("quick", False))
        no_ai      = bool(ui_config.get("no_ai", False))

        excluded = set(ui_config.get("excluded_tools", []))
        cfg.setdefault("analysis", {})["excluded_tools"] = list(excluded)

        if quick_mode:
            cfg["analysis"]["max_static_iterations"] = 5
            cfg["analysis"]["quick_mode"] = True

        if no_ai:
            cfg["ollama"]["host"] = ""

        out_dir = str(_ROOT / "output" / "jobs" / job.job_id)
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        cfg["output"] = {"dir": out_dir}

        workflow = AnalysisWorkflow(cfg, log_fn=log_fn)
        result   = workflow.run(
            file_path    = file_path,
            analyst_name = analyst,
            run_dynamic  = dynamic,
            run_static   = static,
            output_dir   = out_dir,
        )

        # Generate all report formats
        sample_name = Path(file_path).stem
        base        = str(Path(out_dir) / f"{sample_name}_report")
        reports     = generate_all(result, base)

        job.result  = result
        job.reports = reports

        # Determine threat level for status display
        from malyze.report.generator import _threat_level
        level, _, _ = _threat_level(result)
        job.threat  = level
        job.status  = "done"
        job.log_q.put({"type": "done", "threat": level, "reports": {
            k: str(Path(v).name) for k, v in reports.items()
            if not str(v).startswith("ERROR")
        }})

    except Exception as exc:
        job.status = "error"
        job.error  = str(exc)
        log_fn(f"Analysis failed: {exc}", "error")
        job.log_q.put({"type": "error", "msg": str(exc)})


# ── SSE stream ────────────────────────────────────────────────────────────────

@app.route("/api/stream/<job_id>")
@require_auth
def api_stream(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "Unknown job"}), 404

    def generate():
        # Yield a keep-alive comment first so the browser connects immediately
        yield "data: {\"type\":\"connected\"}\n\n"
        while True:
            try:
                event = job.log_q.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") in ("done", "error"):
                    break
            except queue.Empty:
                # Keep-alive ping
                yield "data: {\"type\":\"ping\"}\n\n"
                if job.status in ("done", "error"):
                    break

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Status ────────────────────────────────────────────────────────────────────

@app.route("/api/status/<job_id>")
@require_auth
def api_status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "Unknown job"}), 404
    return jsonify({
        "status":  job.status,
        "threat":  job.threat,
        "sample":  job.sample,
        "error":   job.error,
        "reports": {k: str(Path(v).name) for k, v in job.reports.items()
                    if not str(v).startswith("ERROR")},
    })


# ── Report viewer ─────────────────────────────────────────────────────────────

@app.route("/api/report/<job_id>")
@require_auth
def api_report(job_id: str):
    job = _jobs.get(job_id)
    if not job or job.status != "done":
        return "Report not ready", 404
    html_path = job.reports.get("html", "")
    if not html_path or not Path(html_path).exists():
        return "HTML report not found", 404
    return send_file(html_path, mimetype="text/html")


# ── Download ──────────────────────────────────────────────────────────────────

@app.route("/api/download/<job_id>/<fmt>")
@require_auth
def api_download(job_id: str, fmt: str):
    job = _jobs.get(job_id)
    if not job or job.status != "done":
        return "Not ready", 404
    path = job.reports.get(fmt, "")
    if not path or not Path(path).exists():
        return f"{fmt} report not found", 404
    # Set appropriate MIME type for STIX JSON
    mimetype = "application/json" if fmt in ("json", "stix") else None
    return send_file(path, as_attachment=True, mimetype=mimetype)


# ── Skip / Stop controls ─────────────────────────────────────────────────────

@app.route("/api/skip/<job_id>", methods=["POST"])
def api_skip(job_id: str):
    job = _jobs.get(job_id)
    if not job or job.status != "running":
        return jsonify({"error": "Job not running"}), 400
    job.skip_event.set()
    return jsonify({"ok": True})


@app.route("/api/stop/<job_id>", methods=["POST"])
def api_stop(job_id: str):
    job = _jobs.get(job_id)
    if not job or job.status != "running":
        return jsonify({"error": "Job not running"}), 400
    job.stop_event.set()
    return jsonify({"ok": True})


# ── Ollama models list ────────────────────────────────────────────────────────

@app.route("/api/ollama-models")
def api_ollama_models():
    """Return list of locally installed Ollama models."""
    import requests as _req
    from malyze.core.workflow import load_config
    from malyze.ai.ollama_analyzer import _ollama_headers

    try:
        cfg     = load_config(str(_ROOT / "config.yaml"))
        ollama  = cfg.get("ollama", {})
        host    = ollama.get("host", "http://localhost:11434")
        api_key = ollama.get("api_key", "")
        resp    = _req.get(f"{host}/api/tags", headers=_ollama_headers(api_key), timeout=3)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            return jsonify({"models": models, "status": "online"})
        return jsonify({"models": [], "status": "offline"})
    except Exception:
        return jsonify({"models": [], "status": "offline"})


# ── Ollama status ─────────────────────────────────────────────────────────────

@app.route("/api/ollama-status")
def api_ollama_status():
    """Check whether Ollama is reachable and return the active model."""
    import requests as _req
    from malyze.core.workflow import load_config
    from malyze.ai.ollama_analyzer import _ollama_headers

    try:
        cfg     = load_config(str(_ROOT / "config.yaml"))
        ollama  = cfg.get("ollama", {})
        host    = ollama.get("host", "http://localhost:11434")
        model   = ollama.get("model", "llama3.2")
        api_key = ollama.get("api_key", "")
        resp    = _req.get(f"{host}/api/tags", headers=_ollama_headers(api_key), timeout=3)
        if resp.status_code == 200:
            return jsonify({"status": "online", "model": model})
        return jsonify({"status": "offline", "model": model})
    except Exception:
        return jsonify({"status": "offline", "model": "unknown"})


# ── Main page ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── Entry point ───────────────────────────────────────────────────────────────

def run_server(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    print(f"\n  Malyzer Web UI → http://{host}:{port}\n")
    app.run(host=host, port=port, debug=debug, threaded=True)
