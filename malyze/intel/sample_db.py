"""
SQLite-backed sample database — stores analysis results and enables cross-sample correlation.

Persists: hashes, file type, threat level, malware family, imphash, analysis date.
Enables: "have I seen this before?", "show me samples with the same imphash", "list HIGH+ samples".
"""

import json
import sqlite3
import datetime
from pathlib import Path
from typing import Optional


_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    sha256          TEXT PRIMARY KEY,
    md5             TEXT,
    sha1            TEXT,
    imphash         TEXT,
    file_name       TEXT,
    file_type       TEXT,
    file_size       INTEGER,
    threat_level    TEXT,
    malware_family  TEXT,
    malware_type    TEXT,
    analysis_date   TEXT,
    ttps            TEXT,   -- JSON array of TTP IDs
    ioc_count       INTEGER DEFAULT 0,
    known_malware   INTEGER DEFAULT 0,
    packer_detected INTEGER DEFAULT 0,
    is_dotnet       INTEGER DEFAULT 0,
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_imphash   ON samples(imphash);
CREATE INDEX IF NOT EXISTS idx_family    ON samples(malware_family);
CREATE INDEX IF NOT EXISTS idx_level     ON samples(threat_level);
CREATE INDEX IF NOT EXISTS idx_md5       ON samples(md5);
CREATE INDEX IF NOT EXISTS idx_sha1      ON samples(sha1);
"""


def _get_conn(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def save_sample(analysis: dict, db_path: str = "./output/samples.db") -> bool:
    """
    Persist key analysis fields to the database.
    Returns True on success, False on error.
    """
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    fi      = analysis.get("file_info", {})
    hashes  = fi.get("hashes", {})
    static  = analysis.get("static", {})
    ai      = analysis.get("ai_analysis", {})
    intel   = analysis.get("intel", {})
    ai_s    = ai.get("structured", {}) or {}

    sha256 = hashes.get("sha256")
    if not sha256:
        return False

    # Derive fields
    threat_level   = ai_s.get("threat_level") or _infer_threat(analysis)
    malware_family = (ai_s.get("malware_family")
                      or (intel.get("_summary", {}).get("consensus_family"))
                      or None)
    malware_type   = ai_s.get("malware_type")

    ttps      = json.dumps([t.get("id") for t in ai_s.get("ttps", []) if t.get("id")])
    ioc_count = _count_iocs(static)

    imphash         = static.get("pe", {}).get("imphash")
    is_dotnet       = 1 if static.get("pe", {}).get("is_dotnet") else 0
    packer_detected = 1 if static.get("packer", {}).get("suspicious") else 0
    known_malware   = 1 if intel.get("_summary", {}).get("known_malware") else 0

    try:
        conn = _get_conn(db_path)
        conn.execute("""
            INSERT OR REPLACE INTO samples
              (sha256, md5, sha1, imphash, file_name, file_type, file_size,
               threat_level, malware_family, malware_type, analysis_date,
               ttps, ioc_count, known_malware, packer_detected, is_dotnet)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            sha256,
            hashes.get("md5"),
            hashes.get("sha1"),
            imphash,
            fi.get("name"),
            fi.get("type"),
            hashes.get("size"),
            threat_level,
            malware_family,
            malware_type,
            datetime.datetime.utcnow().isoformat(),
            ttps,
            ioc_count,
            known_malware,
            packer_detected,
            is_dotnet,
        ))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def lookup_hash(hash_value: str, db_path: str = "./output/samples.db") -> Optional[dict]:
    """
    Look up a sample by any hash (SHA256, SHA1, or MD5).
    Returns the record as a dict, or None if not found.
    """
    if not Path(db_path).exists():
        return None
    try:
        conn = _get_conn(db_path)
        for col in ("sha256", "md5", "sha1"):
            row = conn.execute(
                f"SELECT * FROM samples WHERE {col} = ?", (hash_value.lower(),)
            ).fetchone()
            if row:
                conn.close()
                return dict(row)
        conn.close()
    except Exception:
        pass
    return None


def find_by_imphash(imphash: str, db_path: str = "./output/samples.db") -> list:
    """
    Find all previously analysed samples that share the same import hash.
    Same imphash = likely same compiler/linker configuration = potentially same threat actor.
    """
    if not imphash or not Path(db_path).exists():
        return []
    try:
        conn = _get_conn(db_path)
        rows = conn.execute(
            "SELECT sha256, file_name, malware_family, threat_level, analysis_date "
            "FROM samples WHERE imphash = ? ORDER BY analysis_date DESC LIMIT 20",
            (imphash,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def recent_samples(limit: int = 20, db_path: str = "./output/samples.db") -> list:
    """Return the N most recently analysed samples."""
    if not Path(db_path).exists():
        return []
    try:
        conn = _get_conn(db_path)
        rows = conn.execute(
            "SELECT sha256, file_name, file_type, threat_level, malware_family, analysis_date "
            "FROM samples ORDER BY analysis_date DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def stats(db_path: str = "./output/samples.db") -> dict:
    """Return aggregate statistics across all analysed samples."""
    if not Path(db_path).exists():
        return {"total": 0}
    try:
        conn = _get_conn(db_path)
        total = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
        by_level = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT threat_level, COUNT(*) FROM samples GROUP BY threat_level"
            ).fetchall()
        }
        known = conn.execute(
            "SELECT COUNT(*) FROM samples WHERE known_malware = 1"
        ).fetchone()[0]
        families = [
            dict(r) for r in conn.execute(
                "SELECT malware_family, COUNT(*) as count FROM samples "
                "WHERE malware_family IS NOT NULL "
                "GROUP BY malware_family ORDER BY count DESC LIMIT 10"
            ).fetchall()
        ]
        conn.close()
        return {
            "total":          total,
            "by_threat_level": by_level,
            "known_malware":  known,
            "top_families":   families,
        }
    except Exception:
        return {"total": 0}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _infer_threat(analysis: dict) -> str:
    """Fallback threat level from static indicators."""
    static = analysis.get("static", {})
    score  = 0
    if static.get("packer", {}).get("suspicious"):
        score += 2
    if static.get("entropy", {}).get("suspicious"):
        score += 2
    if len(static.get("pe", {}).get("suspicious_imports", [])) >= 4:
        score += 2
    if score >= 6:
        return "CRITICAL"
    if score >= 4:
        return "HIGH"
    if score >= 2:
        return "MEDIUM"
    return "LOW"


def _count_iocs(static: dict) -> int:
    iocs = static.get("strings", {}).get("iocs", {})
    total = 0
    for v in iocs.values():
        if isinstance(v, list):
            total += len(v)
    return total
