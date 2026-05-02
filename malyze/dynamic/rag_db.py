"""
RAG-Driven Dynamic Event Database
Loads Procmon CSV into an SQLite database to allow the AI to actively query events.
"""

import sqlite3
import csv
from pathlib import Path

class DynamicEventsDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
        
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS procmon_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time_of_day TEXT,
                    process_name TEXT,
                    pid TEXT,
                    operation TEXT,
                    path TEXT,
                    result TEXT,
                    detail TEXT
                )
            ''')
            
    def load_csv(self, csv_path: str):
        if not Path(csv_path).exists():
            return False
            
        try:
            with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
                reader = csv.DictReader(fh)
                if reader.fieldnames:
                    reader.fieldnames = [f.strip().strip('"').strip("\ufeff") for f in reader.fieldnames]
                    
                batch = []
                with sqlite3.connect(self.db_path) as conn:
                    # Clear existing events in case of re-run
                    conn.execute("DELETE FROM procmon_events")
                    
                    for row in reader:
                        batch.append((
                            row.get("Time of Day", ""),
                            row.get("Process Name", ""),
                            row.get("PID", ""),
                            row.get("Operation", ""),
                            row.get("Path", ""),
                            row.get("Result", ""),
                            row.get("Detail", "")
                        ))
                        if len(batch) >= 2000:
                            conn.executemany(
                                "INSERT INTO procmon_events (time_of_day, process_name, pid, operation, path, result, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                batch
                            )
                            batch = []
                    if batch:
                        conn.executemany(
                            "INSERT INTO procmon_events (time_of_day, process_name, pid, operation, path, result, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            batch
                        )
            return True
        except Exception as e:
            print(f"Error loading CSV to DB: {e}")
            return False

    def search_events(self, search_term: str, category: str = None) -> list:
        query = ("SELECT process_name, pid, operation, path, result, detail FROM procmon_events "
                 "WHERE (path LIKE ? OR detail LIKE ? OR process_name LIKE ? OR operation LIKE ?)")
        params = [f"%{search_term}%", f"%{search_term}%", f"%{search_term}%", f"%{search_term}%"]
        
        if category == "file":
            query += " AND operation IN ('ReadFile', 'WriteFile', 'CreateFile', 'DeleteFile', 'SetEndOfFile')"
        elif category == "registry":
            query += " AND operation LIKE 'Reg%'"
        elif category == "network":
            query += " AND (operation LIKE '%TCP%' OR operation LIKE '%UDP%' OR operation LIKE '%Network%')"
            
        query += " LIMIT 100"
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                results = []
                for row in cursor.fetchall():
                    results.append(f"[{row[1]}] {row[0]} | {row[2]} | {row[3]} | {row[4]} | {row[5]}")
                return results
        except Exception as e:
            return [f"Error searching database: {str(e)}"]
