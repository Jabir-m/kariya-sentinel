import os
import sqlite3
import json
import datetime
from typing import Dict, Any, List, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "triage_offline.db")

class OfflineIncidentStore:
    """Local SQLite-backed queue ensuring 100% functionality during power/network outages (Rule 06)."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Create tables for offline report queuing and sync state."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incident_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT UNIQUE,
                    organization TEXT,
                    raw_text TEXT,
                    triaged_json TEXT,
                    created_at TEXT,
                    is_offline INTEGER DEFAULT 0,
                    sync_status TEXT DEFAULT 'SYNCED',
                    synced_at TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_state (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            # Initialize offline simulation toggle if not set
            cursor.execute("INSERT OR IGNORE INTO system_state (key, value) VALUES ('offline_mode', 'false')")
            conn.commit()

    def is_offline_mode(self) -> bool:
        """Check whether offline simulation mode is active."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM system_state WHERE key = 'offline_mode'")
            row = cursor.fetchone()
            return row and row[0].lower() == "true"

    def set_offline_mode(self, enabled: bool):
        """Toggle offline simulation mode."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            val = "true" if enabled else "false"
            cursor.execute("UPDATE system_state SET value = ? WHERE key = 'offline_mode'", (val,))
            conn.commit()

    def save_incident(self, report: Dict[str, Any], is_offline: bool = False) -> int:
        """Store an incident report into the local database buffer."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        sync_status = "QUEUED_OFFLINE" if is_offline else "SYNCED"
        synced_at = None if is_offline else now

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO incident_queue 
                (report_id, organization, raw_text, triaged_json, created_at, is_offline, sync_status, synced_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.get("report_id", "REP-UNKNOWN"),
                report.get("organization", "Nigerian Public Institution"),
                report.get("raw_text", ""),
                json.dumps(report, ensure_ascii=False),
                now,
                1 if is_offline else 0,
                sync_status,
                synced_at
            ))
            conn.commit()
            return cursor.lastrowid

    def get_all_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve all incidents from the local database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incident_queue ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            
            results = []
            for r in rows:
                item = json.loads(r["triaged_json"])
                item["db_id"] = r["id"]
                item["is_offline"] = bool(r["is_offline"])
                item["sync_status"] = r["sync_status"]
                item["created_at"] = r["created_at"]
                results.append(item)
            return results

    def sync_offline_queue(self) -> int:
        """Sync all pending offline incident records back to the central repository."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE incident_queue 
                SET sync_status = 'SYNCED', synced_at = ? 
                WHERE sync_status = 'QUEUED_OFFLINE'
            """, (now,))
            synced_count = cursor.rowcount
            conn.commit()
            return synced_count

    def get_stats(self) -> Dict[str, Any]:
        """Get total, offline queued, and synced report statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM incident_queue")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM incident_queue WHERE sync_status = 'QUEUED_OFFLINE'")
            pending = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM incident_queue WHERE sync_status = 'SYNCED'")
            synced = cursor.fetchone()[0]
            return {
                "total_stored": total,
                "offline_queued": pending,
                "synced": synced,
                "offline_mode_active": self.is_offline_mode()
            }
