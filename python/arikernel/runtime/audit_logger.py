"""SQLite audit store with SHA-256 hash chain — compatible with the TypeScript runtime.

Writes to the same schema so the TS CLI trace/replay commands work on Python runs.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .hash_chain import compute_hash, GENESIS_HASH

MIGRATION_001 = """
CREATE TABLE IF NOT EXISTS runs (
  run_id        TEXT PRIMARY KEY,
  principal_id  TEXT NOT NULL,
  started_at    TEXT NOT NULL,
  ended_at      TEXT,
  event_count   INTEGER DEFAULT 0,
  config_json   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id            TEXT PRIMARY KEY,
  run_id        TEXT NOT NULL REFERENCES runs(run_id),
  sequence      INTEGER NOT NULL,
  timestamp     TEXT NOT NULL,
  principal_id  TEXT NOT NULL,
  tool_class    TEXT NOT NULL,
  action        TEXT NOT NULL,
  tool_call_json TEXT NOT NULL,
  decision_json  TEXT NOT NULL,
  result_json    TEXT,
  duration_ms    INTEGER,
  taint_sources  TEXT NOT NULL,
  verdict        TEXT NOT NULL,
  previous_hash  TEXT NOT NULL,
  hash           TEXT NOT NULL,
  UNIQUE(run_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, sequence);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);
CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool_class, action);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditStore:
    """SQLite-backed audit store compatible with the TypeScript implementation."""

    def __init__(self, db_path: str = "./arikernel-audit.db"):
        self._db = sqlite3.connect(db_path)
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.executescript(MIGRATION_001)
        self._db.commit()
        self._last_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        row = self._db.execute(
            "SELECT hash FROM events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS_HASH

    def start_run(
        self,
        run_id: str,
        principal_id: str,
        config: dict[str, Any],
    ) -> None:
        self._db.execute(
            "INSERT INTO runs (run_id, principal_id, started_at, config_json) VALUES (?, ?, ?, ?)",
            (run_id, principal_id, _now(), json.dumps(config)),
        )
        self._db.commit()

    def end_run(self, run_id: str) -> None:
        row = self._db.execute(
            "SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)
        ).fetchone()
        count = row[0] if row else 0
        self._db.execute(
            "UPDATE runs SET ended_at = ?, event_count = ? WHERE run_id = ?",
            (_now(), count, run_id),
        )
        self._db.commit()

    def append(
        self,
        event_id: str,
        tool_call: dict[str, Any],
        decision: dict[str, Any],
        result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append an audit event. Returns the complete event dict."""
        timestamp = _now()
        taint_labels = decision.get("taintLabels", [])
        taint_sources = ",".join(t.get("source", "") for t in taint_labels)

        event_data = json.dumps(
            {"toolCall": tool_call, "decision": decision, "result": result}
            if result
            else {"toolCall": tool_call, "decision": decision},
            separators=(",", ":"),
            sort_keys=False,
            ensure_ascii=False,
        )

        previous_hash = self._last_hash
        hash_val = compute_hash(event_data, previous_hash)
        self._last_hash = hash_val

        run_id = tool_call["runId"]
        row = self._db.execute(
            "SELECT COALESCE(MAX(sequence), -1) + 1 FROM events WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        sequence = row[0] if row else 0

        duration_ms = result.get("durationMs") if result else None

        self._db.execute(
            """INSERT INTO events (
                id, run_id, sequence, timestamp, principal_id, tool_class, action,
                tool_call_json, decision_json, result_json, duration_ms,
                taint_sources, verdict, previous_hash, hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                run_id,
                sequence,
                timestamp,
                tool_call["principalId"],
                tool_call["toolClass"],
                tool_call["action"],
                json.dumps(tool_call),
                json.dumps(decision),
                json.dumps(result) if result else None,
                duration_ms,
                taint_sources,
                decision["verdict"],
                previous_hash,
                hash_val,
            ),
        )
        self._db.commit()

        return {
            "id": event_id,
            "runId": run_id,
            "sequence": sequence,
            "timestamp": timestamp,
            "principalId": tool_call["principalId"],
            "toolCall": tool_call,
            "decision": decision,
            "result": result,
            "previousHash": previous_hash,
            "hash": hash_val,
        }

    def append_system_event(
        self,
        event_id: str,
        run_id: str,
        principal_id: str,
        action: str,
        reason: str,
        metadata: dict[str, Any],
        tool_call_id: str,
    ) -> dict[str, Any]:
        """Append a system event (quarantine, enforcement)."""
        timestamp = _now()

        tool_call: dict[str, Any] = {
            "id": tool_call_id,
            "runId": run_id,
            "sequence": 0,
            "timestamp": timestamp,
            "principalId": principal_id,
            "toolClass": "_system",
            "action": action,
            "parameters": metadata,
            "taintLabels": [],
        }

        decision: dict[str, Any] = {
            "verdict": "deny",
            "matchedRule": None,
            "reason": reason,
            "taintLabels": [],
            "timestamp": timestamp,
        }

        event_data = json.dumps(
            {"toolCall": tool_call, "decision": decision},
            separators=(",", ":"),
            sort_keys=False,
            ensure_ascii=False,
        )

        previous_hash = self._last_hash
        hash_val = compute_hash(event_data, previous_hash)
        self._last_hash = hash_val

        row = self._db.execute(
            "SELECT COALESCE(MAX(sequence), -1) + 1 FROM events WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        sequence = row[0] if row else 0

        self._db.execute(
            """INSERT INTO events (
                id, run_id, sequence, timestamp, principal_id, tool_class, action,
                tool_call_json, decision_json, result_json, duration_ms,
                taint_sources, verdict, previous_hash, hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                run_id,
                sequence,
                timestamp,
                principal_id,
                "_system",
                action,
                json.dumps(tool_call),
                json.dumps(decision),
                None,
                None,
                "",
                "deny",
                previous_hash,
                hash_val,
            ),
        )
        self._db.commit()

        return {
            "id": event_id,
            "runId": run_id,
            "sequence": sequence,
            "timestamp": timestamp,
            "principalId": principal_id,
            "toolCall": tool_call,
            "decision": decision,
            "previousHash": previous_hash,
            "hash": hash_val,
        }

    def query_run(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT * FROM events WHERE run_id = ? ORDER BY sequence",
            (run_id,),
        ).fetchall()
        cols = [d[0] for d in self._db.execute(
            "SELECT * FROM events LIMIT 0"
        ).description]
        return [self._row_to_event(dict(zip(cols, row))) for row in rows]

    def get_run_context(self, run_id: str) -> dict[str, Any] | None:
        row = self._db.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if not row:
            return None
        cols = [d[0] for d in self._db.execute("SELECT * FROM runs LIMIT 0").description]
        r = dict(zip(cols, row))
        return {
            "runId": r["run_id"],
            "principalId": r["principal_id"],
            "startedAt": r["started_at"],
            "endedAt": r.get("ended_at"),
            "eventCount": r.get("event_count", 0),
        }

    def list_runs(self) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT * FROM runs ORDER BY started_at DESC"
        ).fetchall()
        cols = [d[0] for d in self._db.execute("SELECT * FROM runs LIMIT 0").description]
        return [
            {
                "runId": r["run_id"],
                "principalId": r["principal_id"],
                "startedAt": r["started_at"],
                "endedAt": r.get("ended_at"),
                "eventCount": r.get("event_count", 0),
            }
            for r in (dict(zip(cols, row)) for row in rows)
        ]

    def close(self) -> None:
        self._db.close()

    @staticmethod
    def _row_to_event(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "runId": row["run_id"],
            "sequence": row["sequence"],
            "timestamp": row["timestamp"],
            "principalId": row["principal_id"],
            "toolCall": json.loads(row["tool_call_json"]),
            "decision": json.loads(row["decision_json"]),
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
            "previousHash": row["previous_hash"],
            "hash": row["hash"],
        }
