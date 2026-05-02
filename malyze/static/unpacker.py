"""
Automatic binary unpacker — strips UPX and similar single-pass packers.

After unpacking, callers should re-run strings/PE analysis on the resulting
file so all extracted IOCs come from the clean binary, not the stub.
"""

import shutil
import subprocess
from pathlib import Path


def try_unpack(file_path: str, cfg: dict = None) -> dict:
    """
    Attempt to unpack a file using all known unpackers.

    Returns one of:
      {"success": True,  "method": "upx", "unpacked_path": str,
       "original_size": int, "unpacked_size": int}
      {"success": False, "tried": [...], "errors": {...}}
    """
    tried  = []
    errors = {}

    # UPX — most common free packer; available on FLARE-VM and most distros
    upx_bin = (
        (cfg or {}).get("flarevm", {}).get("upx")
        or shutil.which("upx")
    )
    if upx_bin and Path(upx_bin).exists():
        tried.append("upx")
        result = _try_upx(upx_bin, file_path)
        if result.get("success"):
            return result
        errors["upx"] = result.get("error", "")

    return {"success": False, "tried": tried, "errors": errors}


def cleanup_unpacked(unpacked_path: str) -> None:
    """Remove the temp file created by try_unpack."""
    try:
        Path(unpacked_path).unlink(missing_ok=True)
    except Exception:
        pass


# ── Packer-specific helpers ───────────────────────────────────────────────────

def _try_upx(upx_bin: str, file_path: str) -> dict:
    src = Path(file_path)
    tmp = src.parent / f"_upx_unpacked_{src.name}"
    try:
        shutil.copy2(file_path, str(tmp))
        r = subprocess.run(
            [upx_bin, "-d", "--force", str(tmp)],
            capture_output=True,
            timeout=60,
        )
        if r.returncode == 0 and tmp.exists() and tmp.stat().st_size > 0:
            return {
                "success":        True,
                "method":         "upx",
                "unpacked_path":  str(tmp),
                "original_size":  src.stat().st_size,
                "unpacked_size":  tmp.stat().st_size,
            }
        # Failed — clean up
        tmp.unlink(missing_ok=True)
        stderr = (r.stderr or b"").decode("utf-8", errors="replace")[:300]
        return {"success": False, "error": stderr or "upx -d returned non-zero"}
    except subprocess.TimeoutExpired:
        tmp.unlink(missing_ok=True)
        return {"success": False, "error": "UPX timed out after 60 s"}
    except Exception as e:
        tmp.unlink(missing_ok=True)
        return {"success": False, "error": str(e)}
