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

    def __init__(self, config: dict, output_dir: str):
        self.cfg = config
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._tracked: list = []                       # (label, Popen) pairs
        self._procmon_proc: Optional[subprocess.Popen] = None

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
            # Procmon already exited on its own — normal; give it a moment to
            # finish flushing its PML backing file before we read it.
            time.sleep(1)

    def _export_csv(self, pml_path: str) -> str:
        """Convert PML → CSV using Procmon's headless /OpenLog /SaveAs mode."""
        csv_path = pml_path.replace(".pml", ".csv")
        tool = self._find_tool("procmon")
        if tool and Path(pml_path).exists():
            _run_detached(
                [tool, "/OpenLog", pml_path, "/SaveAs", csv_path, "/Quiet"],
                timeout=60,
            )
        return csv_path

    # ------------------------------------------------------------------
    # Sample execution  (also detached — malware must not touch our terminal)
    # ------------------------------------------------------------------
    def _execute_sample(self, sample_path: str, timeout: int) -> dict:
        try:
            # Use PIPE for stdout/stderr so we can capture output, but still
            # apply all the detached flags so the sample can't own our console.
            extra = {}
            if _IS_WINDOWS:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                extra["startupinfo"] = si
                extra["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP |
                                          subprocess.CREATE_NO_WINDOW)

            proc = subprocess.Popen(
                [sample_path],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(Path(sample_path).parent),
                **extra,
            )
            try:
                out, err = proc.communicate(timeout=timeout)
                return {
                    "pid":       proc.pid,
                    "exit_code": proc.returncode,
                    "stdout":    out.decode("utf-8", errors="replace")[:2000],
                    "stderr":    err.decode("utf-8", errors="replace")[:2000],
                    "timed_out": False,
                }
            except subprocess.TimeoutExpired:
                proc.kill()
                return {"pid": proc.pid, "exit_code": None, "timed_out": True}
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Result parsers
    # ------------------------------------------------------------------
    def _read_fakenet_log(self) -> dict:
        log_path = self.output_dir / "fakenet.log"
        if not log_path.exists():
            return {"available": False}
        try:
            content = log_path.read_text(errors="replace")
            lines = content.splitlines()
            conns = [l for l in lines
                     if "Connecting" in l or "Request" in l or "DNS" in l]
            return {
                "available":   True,
                "total_lines": len(lines),
                "connections": conns[:200],
                "raw_path":    str(log_path),
            }
        except Exception as e:
            return {"available": False, "error": str(e)}

    def _parse_procmon_csv(self, csv_path: str) -> dict:
        """
        Parse Procmon CSV using the column header row so we get structured data
        regardless of column order. Procmon's default columns are:
        Time of Day, Process Name, PID, Operation, Path, Result, Detail, TID, ...
        """
        if not Path(csv_path).exists():
            return {"available": False}
        try:
            import csv as _csv

            process_events: list  = []
            file_events: list     = []
            registry_events: list = []
            network_events: list  = []
            total_events          = 0

            with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
                reader = _csv.DictReader(fh)
                # Normalise header names (strip BOM, quotes, whitespace)
                if reader.fieldnames:
                    reader.fieldnames = [
                        f.strip().strip('"').strip("\ufeff") for f in reader.fieldnames
                    ]

                for row in reader:
                    total_events += 1
                    if total_events > 10_000:   # cap to avoid huge memory use
                        break

                    op   = row.get("Operation", "").strip()
                    proc = row.get("Process Name", "").strip()
                    pid  = row.get("PID", "").strip()
                    path = row.get("Path", "").strip()
                    res  = row.get("Result", "").strip()
                    det  = row.get("Detail", "")[:200].strip()

                    summary = f"[{pid}] {proc} | {op} | {path} | {res}"

                    if op.startswith("Process"):
                        if len(process_events) < 100:
                            process_events.append(summary)
                    elif op in ("ReadFile", "WriteFile", "CreateFile",
                                "DeleteFile", "SetEndOfFile", "QueryInformationFile"):
                        if len(file_events) < 100:
                            file_events.append(summary)
                    elif op.startswith("Reg"):
                        if len(registry_events) < 100:
                            registry_events.append(summary)
                    elif "TCP" in op or "UDP" in op or "Network" in op:
                        if len(network_events) < 100:
                            network_events.append(summary)

            return {
                "available":       True,
                "total_events":    total_events,
                "process_events":  process_events,
                "file_events":     file_events,
                "registry_events": registry_events,
                "network_events":  network_events,
                "raw_path":        csv_path,
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
