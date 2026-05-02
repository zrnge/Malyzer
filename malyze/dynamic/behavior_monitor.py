"""Dynamic analysis orchestrator — wraps FakeNet-NG, Procmon, Regshot."""

import subprocess
import shutil
import sys
import time
import threading
from pathlib import Path
from typing import Optional

# ── Windows process-launch helpers ──────────────────────────────────────────
# On Windows every child process inherits the parent's console handles.
# When Procmon (a GUI app) or a console-based malware sample inherits our
# terminal, Windows reassigns console ownership to the child — the parent
# terminal breaks immediately.
#
# Flags used:
#   CREATE_NEW_PROCESS_GROUP  — own process group; Ctrl-C won't propagate
#   CREATE_NO_WINDOW          — no new console allocated for the child
#   STARTF_USESHOWWINDOW      — honour wShowWindow field
#   SW_HIDE (0)               — hide any window the child tries to open
#   stdin = DEVNULL           — child cannot read from our terminal

_IS_WINDOWS = sys.platform == "win32"


def _detached_kwargs() -> dict:
    kw: dict = {
        "stdin":  subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if _IS_WINDOWS:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0   # SW_HIDE
        kw["startupinfo"] = si
        kw["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP |
                               subprocess.CREATE_NO_WINDOW)
    return kw


def _popen_detached(cmd: list, **extra) -> subprocess.Popen:
    kw = _detached_kwargs()
    kw.update(extra)
    return subprocess.Popen(cmd, **kw)


def _run_detached(cmd: list, timeout: int = 30, **extra) -> None:
    kw = _detached_kwargs()
    kw.update(extra)
    try:
        subprocess.run(cmd, timeout=timeout, **kw)
    except Exception:
        pass


# ── Total hard cap for the whole dynamic phase ───────────────────────────────
_DYNAMIC_HARD_TIMEOUT = 300   # seconds — pipeline will never wait longer


class BehaviorMonitor:
    """
    Orchestrates dynamic analysis entirely in a background thread so the
    main analysis pipeline is never blocked or corrupted.

    All subprocesses are launched detached from the caller's terminal.
    All errors are caught and stored as partial results — run() never raises.
    """

    def __init__(self, config: dict, output_dir: str, log_fn=None):
        self.cfg = config
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._tracked: list = []                       # (label, Popen) pairs
        self._procmon_proc: Optional[subprocess.Popen] = None
        self._log_fn = log_fn or print

    def _log(self, msg: str, level: str = "info") -> None:
        try:
            self._log_fn(msg, level)
        except TypeError:
            self._log_fn(msg)

    # ------------------------------------------------------------------
    # Tool resolution
    # ------------------------------------------------------------------
    def _find_tool(self, name: str) -> Optional[str]:
        path = self.cfg.get("flarevm", {}).get(name, "")
        if path and Path(path).exists():
            return path
        return shutil.which(name)

    # ------------------------------------------------------------------
    # Process helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _alive(proc: subprocess.Popen) -> bool:
        try:
            return proc.poll() is None
        except Exception:
            return False

    @staticmethod
    def _safe_kill(proc: subprocess.Popen) -> None:
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
        except Exception:
            pass

    @staticmethod
    def _taskkill(image: str) -> None:
        if _IS_WINDOWS:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/IM", image],
                    **_detached_kwargs(),
                    timeout=8,
                )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Monitor launchers
    # ------------------------------------------------------------------
    def _start_fakenet(self) -> Optional[subprocess.Popen]:
        tool = self._find_tool("fakenet")
        if not tool:
            return None
        log_path = self.output_dir / "fakenet.log"
        try:
            proc = _popen_detached([tool, "-f", str(log_path)])
            self._tracked.append(("fakenet", proc))
            return proc
        except Exception:
            return None

    def _start_procmon(self, pml_path: str) -> Optional[subprocess.Popen]:
        tool = self._find_tool("procmon")
        if not tool:
            return None
        try:
            proc = _popen_detached(
                [tool, "/AcceptEula", "/Quiet", "/Minimized",
                 "/BackingFile", pml_path]
            )
            self._procmon_proc = proc
            return proc
        except Exception:
            return None

    def _stop_procmon(self) -> None:
        """
        Send /Terminate ONLY if our Procmon instance is still running.
        Calling procmon /Terminate when no Procmon is running would briefly
        launch a new instance, which can interfere with the PML file.
        """
        if self._procmon_proc is not None and self._alive(self._procmon_proc):
            tool = self._find_tool("procmon")
            if tool:
                _run_detached([tool, "/Terminate"], timeout=10)
                try:
                    self._procmon_proc.wait(timeout=8)
                except Exception:
                    pass
            if self._alive(self._procmon_proc):
                self._safe_kill(self._procmon_proc)
                self._taskkill("Procmon64.exe")
                self._taskkill("Procmon.exe")
        else:
            # Procmon already exited on its own — normal.
            pass
        # Always wait for the PML backing file to finish flushing before
        # a new Procmon instance opens it for CSV export.
        time.sleep(3)

    def _export_csv(self, pml_path: str) -> str:
        """Convert PML → CSV using Procmon's headless /OpenLog /SaveAs mode."""
        csv_path = pml_path.replace(".pml", ".csv")
        tool = self._find_tool("procmon")
        pml  = Path(pml_path)

        if not tool:
            self._log(f"      [DYN] _export_csv: Procmon binary not found")
            return csv_path

        if not pml.exists():
            self._log(f"      [DYN] _export_csv: PML not found at {pml_path}")
            return csv_path

        pml_size = pml.stat().st_size
        self._log(f"      [DYN] Exporting PML → CSV  ({pml_size:,} bytes) ...")

        if pml_size == 0:
            self._log(f"      [DYN] _export_csv: PML is empty (0 bytes) — Procmon may lack admin rights")
            return csv_path

        # Use subprocess.run directly so we can capture exit code + stderr.
        # /AcceptEula — suppresses the EULA dialog on fresh Procmon instances.
        # Do NOT use /NoFilter — not supported on all Procmon versions.
        try:
            kw: dict = {"stdin": subprocess.DEVNULL, "capture_output": True}
            if _IS_WINDOWS:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                kw["startupinfo"] = si
                kw["creationflags"] = subprocess.CREATE_NO_WINDOW
            r = subprocess.run(
                [tool, "/AcceptEula", "/OpenLog", pml_path, "/SaveAs", csv_path, "/Quiet"],
                timeout=120,
                **kw,
            )
            if r.returncode != 0:
                err = (r.stderr or b"").decode(errors="replace")[:300]
                self._log(f"      [DYN] Procmon /SaveAs exited {r.returncode}: {err}", "warning")
        except subprocess.TimeoutExpired:
            self._log(f"      [DYN] Procmon /SaveAs timed out after 120s", "warning")
        except Exception as exc:
            self._log(f"      [DYN] Procmon /SaveAs failed: {exc}", "warning")

        if Path(csv_path).exists():
            self._log(f"      [DYN] CSV exported: {Path(csv_path).stat().st_size:,} bytes")
        else:
            self._log(f"      [DYN] CSV still missing after export — check Procmon permissions", "warning")
            time.sleep(3)   # one last grace period

        return csv_path

    # ------------------------------------------------------------------
    # Sample execution  (also detached — malware must not touch our terminal)
    # ------------------------------------------------------------------
    def _execute_sample(self, sample_path: str, timeout: int) -> dict:
        import time as _time
        out_file = self.output_dir / "sample_stdout.txt"
        err_file = self.output_dir / "sample_stderr.txt"

        try:
            extra = {}
            if _IS_WINDOWS:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                extra["startupinfo"] = si
                # CREATE_NEW_PROCESS_GROUP so we can send CTRL_BREAK to the whole group.
                # Avoid PIPE — if the sample spawns children they inherit pipe handles
                # and communicate() blocks until ALL holders exit (hangs entire analysis).
                extra["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP |
                                          subprocess.CREATE_NO_WINDOW)

            with open(out_file, "wb") as fout, open(err_file, "wb") as ferr:
                proc = subprocess.Popen(
                    [sample_path],
                    stdin=subprocess.DEVNULL,
                    stdout=fout,
                    stderr=ferr,
                    cwd=str(Path(sample_path).parent),
                    **extra,
                )

            t_start   = _time.time()
            timed_out = False
            try:
                proc.wait(timeout=timeout)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                exit_code = None
                # Kill the entire process tree so no orphaned children survive
                try:
                    import psutil
                    parent = psutil.Process(proc.pid)
                    for child in parent.children(recursive=True):
                        try: child.kill()
                        except Exception: pass
                    parent.kill()
                except Exception:
                    try: proc.kill()
                    except Exception: pass

            elapsed = round(_time.time() - t_start, 1)

            stdout = stderr = ""
            try: stdout = out_file.read_text(errors="replace")[:2000]
            except Exception: pass
            try: stderr = err_file.read_text(errors="replace")[:2000]
            except Exception: pass

            return {
                "pid":       proc.pid,
                "exit_code": exit_code,
                "timed_out": timed_out,
                "elapsed_s": elapsed,
                "stdout":    stdout,
                "stderr":    stderr,
            }

        except FileNotFoundError:
            return {"error": f"Executable not found: {sample_path}"}
        except PermissionError:
            return {"error": f"Permission denied — AV may be blocking execution: {sample_path}"}
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Result parsers
    # ------------------------------------------------------------------
    def _read_fakenet_log(self) -> dict:
        log_path = self.output_dir / "fakenet.log"
        if not log_path.exists():
            return {"available": False}
        import re as _re
        try:
            content = log_path.read_text(errors="replace")
            lines   = content.splitlines()

            dns_queries:    list = []
            http_requests:  list = []
            tcp_connections: list = []
            seen_dns: set = set()
            seen_conn: set = set()

            for line in lines:
                # DNS: "DNS request for evil.com" / "Received DNS request for"
                m = _re.search(
                    r"DNS\s+(?:request|query|lookup)\s+for\s+([\w.\-]+)",
                    line, _re.IGNORECASE,
                )
                if m:
                    d = m.group(1).lower().rstrip(".")
                    if d not in seen_dns:
                        seen_dns.add(d)
                        dns_queries.append(d)

                # HTTP method line: GET /path HTTP/1.1
                m = _re.search(
                    r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP",
                    line, _re.IGNORECASE,
                )
                if m:
                    http_requests.append(f"{m.group(1).upper()} {m.group(2)}")

                # HTTP Host header
                m = _re.search(r"\bHost:\s*([\w.\-:]+)", line, _re.IGNORECASE)
                if m:
                    http_requests.append(f"Host: {m.group(1)}")

                # TCP/UDP connection: IP:port patterns
                m = _re.search(
                    r"[Cc]onnect\w*\s+(?:from\s+[\d.]+\s+to\s+)?([\d]{1,3}(?:\.[\d]{1,3}){3}):(\d+)",
                    line,
                )
                if m:
                    ip, port = m.group(1), m.group(2)
                    key = f"{ip}:{port}"
                    if key not in seen_conn and not ip.startswith(("127.", "0.", "255.")):
                        seen_conn.add(key)
                        tcp_connections.append({"ip": ip, "port": int(port)})

            return {
                "available":       True,
                "total_lines":     len(lines),
                "dns_queries":     dns_queries[:50],
                "http_requests":   list(dict.fromkeys(http_requests))[:50],
                "tcp_connections": tcp_connections[:50],
                "raw_path":        str(log_path),
            }
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _parse_procmon_csv(
        self,
        csv_path: str,
        sample_pid: str = "",
        sample_name: str = "",
    ) -> dict:
        """
        Parse Procmon CSV into categorised event lists.

        sample_pid / sample_name — events from the sample are placed at the
        top of each list so the AI sees malware activity, not the thousands of
        background events from Explorer / MsMpEng / Edge that dominate a
        system-wide capture.
        """
        if not Path(csv_path).exists():
            return {"available": False}
        try:
            import csv as _csv

            _NOISE = {
                "explorer.exe", "msmpeng.exe", "msmeng.exe", "svchost.exe",
                "msedge.exe", "chrome.exe", "firefox.exe",
                "procmon64.exe", "procmon.exe", "system", "registry", "idle",
                "searchindexer.exe", "taskhostw.exe", "ctfmon.exe",
            }

            # Paths that are Malyze tool artifacts — suppress even if sample wrote there.
            # These would otherwise confuse the AI into thinking they are IOCs.
            _output_dir_lower = str(self.output_dir).lower()
            _NOISE_PATHS = {
                # Prefetch writes are always done by the Windows Prefetch service
                "c:\\windows\\prefetch",
                # System32 DLL reads are normal loader activity
                "c:\\windows\\system32",
            }

            def _is_noise_path(path: str) -> bool:
                pl = path.lower()
                if pl.startswith(_output_dir_lower):
                    return True
                return any(pl.startswith(p) for p in _NOISE_PATHS)

            sample_pid  = str(sample_pid).strip()
            sample_name = sample_name.strip().lower()

            def _is_sample(pid: str, proc: str) -> bool:
                if sample_pid and pid == sample_pid:
                    return True
                if sample_name and sample_name in proc.lower():
                    return True
                return False

            buckets: dict = {
                "process":  [[], []],
                "file":     [[], []],
                "registry": [[], []],
                "network":  [[], []],
            }
            total_events = 0

            with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
                reader = _csv.DictReader(fh)
                if reader.fieldnames:
                    reader.fieldnames = [
                        f.strip().strip('"').strip("﻿") for f in reader.fieldnames
                    ]

                for row in reader:
                    total_events += 1

                    op   = row.get("Operation", "").strip()
                    proc = row.get("Process Name", "").strip()
                    pid  = row.get("PID", "").strip()
                    path = row.get("Path", "").strip()
                    res  = row.get("Result", "").strip()

                    summary  = f"[{pid}] {proc} | {op} | {path} | {res}"
                    is_samp  = _is_sample(pid, proc)
                    is_noise = (not is_samp) and (
                        proc.lower() in _NOISE or _is_noise_path(path)
                    )

                    if op.startswith("Process") or op == "Load Image" or op == "Thread Create":
                        cat = "process"
                    elif op in ("ReadFile", "WriteFile", "CreateFile",
                                "DeleteFile", "SetEndOfFile", "QueryInformationFile",
                                "RenameFile", "SetRenameInformationFile"):
                        cat = "file"
                    elif op.startswith("Reg"):
                        cat = "registry"
                    elif "TCP" in op or "UDP" in op or "Network" in op:
                        cat = "network"
                    else:
                        continue

                    samp_list, bg_list = buckets[cat]
                    if is_samp:
                        if len(samp_list) < 100:
                            samp_list.append(summary)
                    elif not is_noise:
                        if len(bg_list) < 50:
                            bg_list.append(summary)

            def _merge(cat: str) -> list:
                samp, bg = buckets[cat]
                return (samp + bg)[:100]

            db_path = str(self.output_dir / "procmon.db")
            from malyze.dynamic.rag_db import DynamicEventsDB
            db = DynamicEventsDB(db_path)
            db.load_csv(csv_path)

            return {
                "available":       True,
                "total_events":    total_events,
                "sample_pid":      sample_pid,
                "process_events":  _merge("process"),
                "file_events":     _merge("file"),
                "registry_events": _merge("registry"),
                "network_events":  _merge("network"),
                "raw_path":        csv_path,
                "db_path":         db_path,
            }
        except Exception as e:
            return {"available": False, "error": str(e)}

    # ------------------------------------------------------------------
    # Core worker — runs inside a background thread
    # ------------------------------------------------------------------
    def _worker(self, sample_path: str, timeout: int, result_bag: dict) -> None:
        """
        All dynamic-analysis logic lives here.  The method is called from a
        daemon thread so the main pipeline is never blocked.
        Any exception is caught and stored in result_bag["errors"].
        """
        pml_path = str(self.output_dir / "procmon.pml")
        errors: list = []

        try:
            fakenet_proc = self._start_fakenet()
            procmon_proc = self._start_procmon(pml_path)
            if fakenet_proc or procmon_proc:
                time.sleep(2)   # let monitors initialise
        except Exception as e:
            errors.append(f"monitor_start: {e}")
            fakenet_proc = procmon_proc = None

        exec_result: dict = {}
        try:
            exec_result = self._execute_sample(sample_path, timeout)
            time.sleep(3)       # let final I/O settle
        except Exception as e:
            errors.append(f"sample_exec: {e}")
            exec_result = {"error": str(e)}

        try:
            for label, proc in self._tracked:
                self._safe_kill(proc)
            self._stop_procmon()
            time.sleep(2)
        except Exception as e:
            errors.append(f"monitor_stop: {e}")

        network: dict = {"available": False}
        procmon_data: dict = {"available": False}
        try:
            csv_path     = self._export_csv(pml_path)
            network      = self._read_fakenet_log()
            procmon_data = self._parse_procmon_csv(csv_path)
        except Exception as e:
            errors.append(f"collect_results: {e}")

        result_bag["execution"]             = exec_result
        result_bag["network_activity"]      = network
        result_bag["process_file_registry"] = procmon_data
        result_bag["tools_available"]       = {
            "fakenet":  fakenet_proc is not None,
            "procmon":  procmon_proc is not None,
        }
        if errors:
            result_bag["errors"] = errors

    # ------------------------------------------------------------------
    # Public entry point — guaranteed to return a dict, never raises
    # ------------------------------------------------------------------
    def run(self, sample_path: str, timeout: int = 60) -> dict:
        """
        Run dynamic analysis in a background thread so the main pipeline
        is never blocked.  Waits at most *timeout* + 60 s then returns
        whatever partial results have been collected.

        WARNING: Only run in an isolated VM/sandbox environment!
        """
        # Hard cap: dynamic timeout + 60 s for cleanup, never more than
        # _DYNAMIC_HARD_TIMEOUT seconds total.
        thread_timeout = min(timeout + 60, _DYNAMIC_HARD_TIMEOUT)

        result_bag: dict = {
            "execution":             {},
            "network_activity":      {"available": False},
            "process_file_registry": {"available": False},
            "tools_available":       {"fakenet": False, "procmon": False},
        }

        t = threading.Thread(
            target=self._worker,
            args=(sample_path, timeout, result_bag),
            daemon=True,   # won't prevent process exit if main thread finishes
        )
        t.start()
        t.join(timeout=thread_timeout)

        if t.is_alive():
            # Thread timed out — clean up what we can and return partial data
            result_bag.setdefault("errors", []).append(
                f"dynamic analysis timed out after {thread_timeout}s"
            )
            # Best-effort kill of any lingering processes
            try:
                for _, proc in self._tracked:
                    self._safe_kill(proc)
                self._taskkill("Procmon64.exe")
                self._taskkill("Procmon.exe")
                self._taskkill("FakeNet.exe")
            except Exception:
                pass

        return result_bag
