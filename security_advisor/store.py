"""Small SQLite persistence layer."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, database_path: str) -> None:
        path = Path(database_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                chat_id INTEGER PRIMARY KEY,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_digest_at TEXT
            );
            CREATE TABLE IF NOT EXISTS subscriptions (
                chat_id INTEGER NOT NULL REFERENCES users(chat_id) ON DELETE CASCADE,
                group_name TEXT NOT NULL,
                PRIMARY KEY(chat_id, group_name)
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                osv_id TEXT PRIMARY KEY,
                first_seen_at TEXT NOT NULL DEFAULT '',
                modified TEXT NOT NULL,
                published TEXT,
                summary TEXT NOT NULL,
                details TEXT NOT NULL,
                aliases TEXT NOT NULL,
                ecosystems TEXT NOT NULL,
                affected_json TEXT NOT NULL DEFAULT '[]',
                references_json TEXT NOT NULL,
                withdrawn TEXT
            );
            CREATE TABLE IF NOT EXISTS deliveries (
                chat_id INTEGER NOT NULL REFERENCES users(chat_id) ON DELETE CASCADE,
                canonical_id TEXT NOT NULL,
                delivered_at TEXT NOT NULL,
                PRIMARY KEY(chat_id, canonical_id)
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY, value TEXT NOT NULL
            );
            """
        )
        user_columns = {
            row["name"] for row in self.connection.execute("PRAGMA table_info(users)")
        }
        if "last_digest_at" not in user_columns:
            self.connection.execute("ALTER TABLE users ADD COLUMN last_digest_at TEXT")
        columns = {
            row["name"] for row in self.connection.execute("PRAGMA table_info(vulnerabilities)")
        }
        if "affected_json" not in columns:
            self.connection.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN affected_json TEXT NOT NULL DEFAULT '[]'"
            )
        if "first_seen_at" not in columns:
            self.connection.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN first_seen_at TEXT NOT NULL DEFAULT ''"
            )
            self.connection.execute(
                "UPDATE vulnerabilities SET first_seen_at=modified WHERE first_seen_at=''"
            )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def get_meta(self, key: str) -> str | None:
        row = self.connection.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.connection.execute(
            "INSERT INTO metadata(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value)
        )
        self.connection.commit()

    def register(self, chat_id: int) -> None:
        now = utc_now()
        self.connection.execute(
            "INSERT INTO users(chat_id,active,created_at,last_digest_at) VALUES(?,1,?,?) "
            "ON CONFLICT(chat_id) DO UPDATE SET "
            "last_digest_at=CASE WHEN users.active=0 THEN excluded.last_digest_at "
            "ELSE users.last_digest_at END, active=1",
            (chat_id, now, now),
        )
        self.connection.commit()

    def digest_since(self, chat_id: int) -> str:
        row = self.connection.execute(
            "SELECT created_at,last_digest_at FROM users WHERE chat_id=?", (chat_id,)
        ).fetchone()
        if row is None:
            return utc_now()
        return row["last_digest_at"] or row["created_at"]

    def mark_digest_complete(self, chat_id: int) -> None:
        self.connection.execute(
            "UPDATE users SET last_digest_at=? WHERE chat_id=?", (utc_now(), chat_id)
        )
        self.connection.commit()

    def set_active(self, chat_id: int, active: bool) -> None:
        self.register(chat_id)
        self.connection.execute("UPDATE users SET active=? WHERE chat_id=?", (int(active), chat_id))
        self.connection.commit()

    def is_active(self, chat_id: int) -> bool:
        row = self.connection.execute("SELECT active FROM users WHERE chat_id=?", (chat_id,)).fetchone()
        return bool(row and row["active"])

    def selected_groups(self, chat_id: int) -> set[str]:
        rows = self.connection.execute(
            "SELECT group_name FROM subscriptions WHERE chat_id=?", (chat_id,)
        ).fetchall()
        return {row["group_name"] for row in rows}

    def toggle_group(self, chat_id: int, group_name: str) -> set[str]:
        selected = self.selected_groups(chat_id)
        if group_name in selected:
            self.connection.execute(
                "DELETE FROM subscriptions WHERE chat_id=? AND group_name=?", (chat_id, group_name)
            )
        else:
            self.connection.execute(
                "INSERT OR IGNORE INTO subscriptions(chat_id,group_name) VALUES(?,?)", (chat_id, group_name)
            )
        self.connection.commit()
        return self.selected_groups(chat_id)

    def active_chats(self) -> list[int]:
        rows = self.connection.execute("SELECT chat_id FROM users WHERE active=1").fetchall()
        return [int(row["chat_id"]) for row in rows]

    def save_vulnerability(self, record: dict[str, Any]) -> None:
        affected = record.get("affected") or []
        ecosystems = sorted({
            str(item.get("package", {}).get("ecosystem", ""))
            for item in affected if item.get("package", {}).get("ecosystem")
        })
        refs = [
            ref.get("url") for ref in record.get("references", [])
            if isinstance(ref, dict) and ref.get("url")
        ]
        self.connection.execute(
            """INSERT INTO vulnerabilities
            (osv_id,first_seen_at,modified,published,summary,details,aliases,ecosystems,affected_json,references_json,withdrawn)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(osv_id) DO UPDATE SET modified=excluded.modified, published=excluded.published,
              summary=excluded.summary, details=excluded.details, aliases=excluded.aliases,
              ecosystems=excluded.ecosystems, affected_json=excluded.affected_json,
              references_json=excluded.references_json, withdrawn=excluded.withdrawn""",
            (record["id"], utc_now(), record.get("modified", utc_now()), record.get("published"),
             record.get("summary") or record.get("id", "Security advisory"),
             record.get("details") or "", json.dumps(record.get("aliases") or []),
             json.dumps(ecosystems), json.dumps(affected), json.dumps(refs), record.get("withdrawn")),
        )
        self.connection.commit()

    def records_for_groups(self, groups: set[str], since: str | None = None) -> list[dict[str, Any]]:
        if not groups:
            return []
        rows = self.connection.execute(
            "SELECT * FROM vulnerabilities WHERE withdrawn IS NULL AND (published IS NULL OR published <= ?) "
            "ORDER BY first_seen_at DESC", (utc_now(),)
        ).fetchall()
        wanted = set(groups)
        result: list[dict[str, Any]] = []
        for row in rows:
            if since and row["first_seen_at"] and row["first_seen_at"] < since:
                continue
            ecosystems = set(json.loads(row["ecosystems"]))
            if not ecosystems.intersection(wanted):
                continue
            result.append(dict(row))
        return result

    def record_identifiers(self, record: dict[str, Any]) -> set[str]:
        return {record["osv_id"], *json.loads(record["aliases"])}

    def record_was_delivered(self, chat_id: int, record: dict[str, Any]) -> bool:
        identifiers = self.record_identifiers(record)
        placeholders = ",".join("?" for _ in identifiers)
        row = self.connection.execute(
            f"SELECT 1 FROM deliveries WHERE chat_id=? AND canonical_id IN ({placeholders}) LIMIT 1",
            (chat_id, *identifiers),
        ).fetchone()
        return row is not None

    def mark_record_delivered(self, chat_id: int, record: dict[str, Any]) -> None:
        delivered_at = utc_now()
        self.connection.executemany(
            "INSERT OR IGNORE INTO deliveries(chat_id,canonical_id,delivered_at) VALUES(?,?,?)",
            [(chat_id, identifier, delivered_at) for identifier in self.record_identifiers(record)],
        )
        self.connection.commit()
