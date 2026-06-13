"""SQLite-backed Storage implementation (MVP persistence)."""

from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from orchestrator.core.state import SessionState, utcnow
from orchestrator.storage.base import Storage

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_goal TEXT,
    security_task_type TEXT,
    status TEXT,
    created_at TEXT,
    updated_at TEXT,
    state_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    step_id TEXT,
    label TEXT,
    diff_summary TEXT,
    created_at TEXT,
    seq INTEGER,
    state_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    session_id TEXT,
    type TEXT,
    source TEXT,
    content TEXT,
    hash TEXT,
    version INTEGER,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    session_id TEXT,
    name TEXT,
    type TEXT,
    content TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS model_calls (
    call_id TEXT PRIMARY KEY,
    session_id TEXT,
    model TEXT,
    agent TEXT,
    cost_usd REAL,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS tool_calls (
    call_id TEXT PRIMARY KEY,
    session_id TEXT,
    tool TEXT,
    agent TEXT,
    success INTEGER,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    source TEXT,
    observable TEXT,
    payload TEXT,
    created_at TEXT,
    PRIMARY KEY (source, observable)
);
CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id TEXT PRIMARY KEY,
    session_id TEXT,
    rule_json TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS analyst_feedback (
    feedback_id TEXT PRIMARY KEY,
    session_id TEXT,
    model_id TEXT,
    task_type TEXT,
    success INTEGER,
    payload TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    entry_id TEXT PRIMARY KEY,
    session_id TEXT,
    actor TEXT,
    action TEXT,
    detail TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS knowledge_base (
    kb_id TEXT PRIMARY KEY,
    topic TEXT,
    content TEXT,
    source_session TEXT,
    created_at TEXT
);
"""


class SQLiteStorage(Storage):
    def __init__(self, db_path: str = "aegis.sqlite") -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self.init_db()

    def init_db(self) -> None:
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # --- sessions ---
    def save_session(self, state: SessionState) -> None:
        state.touch()
        self._conn.execute(
            """INSERT INTO sessions
               (session_id, user_goal, security_task_type, status, created_at, updated_at, state_json)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(session_id) DO UPDATE SET
                 user_goal=excluded.user_goal, security_task_type=excluded.security_task_type,
                 status=excluded.status, updated_at=excluded.updated_at,
                 state_json=excluded.state_json""",
            (state.session_id, state.user_goal, state.security_task_type, state.status,
             state.created_at.isoformat(), state.updated_at.isoformat(), state.to_json(indent=None)),
        )
        self._index_session(state)
        self._conn.commit()

    def _index_session(self, state: SessionState) -> None:
        """Mirror queryable rows into side tables for the dashboard."""
        sid = state.session_id
        for ev in state.evidence_items:
            self._conn.execute(
                """INSERT OR REPLACE INTO evidence
                   (evidence_id, session_id, type, source, content, hash, version, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (ev.evidence_id, sid, ev.type, ev.source, ev.content, ev.hash,
                 ev.version, ev.collected_at.isoformat()),
            )
        for art in state.artifacts:
            self._conn.execute(
                """INSERT OR REPLACE INTO artifacts
                   (artifact_id, session_id, name, type, content, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (art.artifact_id, sid, art.name, art.type, art.content, art.created_at.isoformat()),
            )
        for mc in state.model_calls:
            self._conn.execute(
                """INSERT OR REPLACE INTO model_calls
                   (call_id, session_id, model, agent, cost_usd, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (mc.call_id, sid, mc.model, mc.agent, mc.cost_usd, mc.timestamp.isoformat()),
            )
        for tc in state.tool_calls:
            self._conn.execute(
                """INSERT OR REPLACE INTO tool_calls
                   (call_id, session_id, tool, agent, success, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (tc.call_id, sid, tc.tool, tc.agent, int(tc.success), tc.timestamp.isoformat()),
            )

    def load_session(self, session_id: str) -> SessionState:
        row = self._conn.execute(
            "SELECT state_json FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"session not found: {session_id}")
        return SessionState.from_json(row["state_json"])

    def list_sessions(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT session_id, user_goal, security_task_type, status, created_at, updated_at "
            "FROM sessions ORDER BY updated_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # --- checkpoints ---
    def save_checkpoint(
        self, session_id: str, state: SessionState, label: str = "", diff_summary: str = ""
    ) -> str:
        checkpoint_id = str(uuid.uuid4())
        seq_row = self._conn.execute(
            "SELECT COALESCE(MAX(seq), 0) AS m FROM checkpoints WHERE session_id=?", (session_id,)
        ).fetchone()
        seq = int(seq_row["m"]) + 1
        self._conn.execute(
            """INSERT INTO checkpoints
               (checkpoint_id, session_id, step_id, label, diff_summary, created_at, seq, state_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (checkpoint_id, session_id, state.current_step_id, label, diff_summary,
             utcnow().isoformat(), seq, state.to_json(indent=None)),
        )
        self._conn.commit()
        return checkpoint_id

    def load_checkpoint(self, checkpoint_id: str) -> SessionState:
        row = self._conn.execute(
            "SELECT state_json FROM checkpoints WHERE checkpoint_id=?", (checkpoint_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"checkpoint not found: {checkpoint_id}")
        return SessionState.from_json(row["state_json"])

    def list_checkpoints(self, session_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT checkpoint_id, session_id, step_id, label, diff_summary, created_at, seq "
            "FROM checkpoints WHERE session_id=? ORDER BY seq ASC", (session_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def latest_checkpoint_id(self, session_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT checkpoint_id FROM checkpoints WHERE session_id=? ORDER BY seq DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        return row["checkpoint_id"] if row else None

    # --- audit ---
    def append_audit(self, session_id: str, actor: str, action: str, detail: str = "") -> None:
        self._conn.execute(
            "INSERT INTO audit_log (entry_id, session_id, actor, action, detail, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), session_id, actor, action, detail, utcnow().isoformat()),
        )
        self._conn.commit()

    def get_audit(self, session_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT actor, action, detail, created_at FROM audit_log WHERE session_id=? "
            "ORDER BY created_at ASC", (session_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # --- threat-intel cache ---
    def cache_threat_intel(self, source: str, observable: str, payload: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO threat_intel_cache (source, observable, payload, created_at) "
            "VALUES (?,?,?,?)", (source, observable, payload, utcnow().isoformat()),
        )
        self._conn.commit()

    def get_cached_threat_intel(self, source: str, observable: str) -> str | None:
        row = self._conn.execute(
            "SELECT payload FROM threat_intel_cache WHERE source=? AND observable=?",
            (source, observable),
        ).fetchone()
        return row["payload"] if row else None

    # --- detection rules ---
    def save_detection_rule(self, session_id: str, rule_json: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO detection_rules (rule_id, session_id, rule_json, created_at) "
            "VALUES (?,?,?,?)",
            (str(uuid.uuid4()), session_id, rule_json, utcnow().isoformat()),
        )
        self._conn.commit()

    # --- analyst feedback ---
    def save_feedback(self, session_id: str, model_id: str, task_type: str, payload: dict) -> None:
        success = 1 if payload.get("classification_correct", True) else 0
        self._conn.execute(
            "INSERT INTO analyst_feedback "
            "(feedback_id, session_id, model_id, task_type, success, payload, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), session_id, model_id, task_type, success,
             json.dumps(payload), utcnow().isoformat()),
        )
        self._conn.commit()

    def feedback_success_rate(self, model_id: str, task_type: str) -> float | None:
        row = self._conn.execute(
            "SELECT AVG(success) AS rate, COUNT(*) AS n FROM analyst_feedback "
            "WHERE model_id=? AND task_type=?", (model_id, task_type),
        ).fetchone()
        if row is None or row["n"] == 0:
            return None
        return float(row["rate"])

    # --- knowledge base ---
    def add_knowledge(self, topic: str, content: str, source_session: str | None = None) -> None:
        self._conn.execute(
            "INSERT INTO knowledge_base (kb_id, topic, content, source_session, created_at) "
            "VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), topic, content, source_session, utcnow().isoformat()),
        )
        self._conn.commit()

    def get_knowledge(self, topic: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT content FROM knowledge_base WHERE topic=? ORDER BY created_at DESC", (topic,)
        ).fetchall()
        return [r["content"] for r in rows]

    def close(self) -> None:
        self._conn.close()
