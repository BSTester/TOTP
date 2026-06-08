from __future__ import annotations

import datetime as dt
import secrets
import sqlite3
import string
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .security import hash_api_key

ALPHABET = string.ascii_lowercase + string.digits


@dataclass(frozen=True)
class ApiKeyOwner:
    id: str
    name: str


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS totp_entries (
                    id TEXT PRIMARY KEY,
                    owner_key_id TEXT NOT NULL,
                    unique_id TEXT NOT NULL,
                    email TEXT NOT NULL,
                    random_suffix TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    account_name TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    digits INTEGER NOT NULL,
                    period INTEGER NOT NULL,
                    encrypted_secret TEXT NOT NULL,
                    secret_nonce TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(owner_key_id) REFERENCES api_keys(id) ON DELETE CASCADE,
                    UNIQUE(owner_key_id, unique_id)
                );

                CREATE INDEX IF NOT EXISTS idx_totp_owner ON totp_entries(owner_key_id);
                """
            )

    def create_api_key(self, name: str) -> tuple[str, str]:
        raw_key = f"tk_{secrets.token_urlsafe(24)}"
        key_hash = hash_api_key(raw_key)
        key_id = f"key_{uuid.uuid4().hex[:12]}"
        created_at = _now()

        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO api_keys(id, name, key_hash, active, created_at)
                VALUES (?, ?, ?, 1, ?)
                """,
                (key_id, name, key_hash, created_at),
            )

        return key_id, raw_key

    def resolve_owner(self, raw_api_key: str) -> ApiKeyOwner | None:
        key_hash = hash_api_key(raw_api_key)
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, name
                FROM api_keys
                WHERE key_hash = ? AND active = 1
                """,
                (key_hash,),
            ).fetchone()

        if not row:
            return None
        return ApiKeyOwner(id=row["id"], name=row["name"])

    def unique_id_exists(self, owner_key_id: str, unique_id: str) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT 1
                FROM totp_entries
                WHERE owner_key_id = ? AND unique_id = ?
                LIMIT 1
                """,
                (owner_key_id, unique_id),
            ).fetchone()
        return row is not None

    def generate_unique_id(self, owner_key_id: str, tries: int = 20) -> tuple[str, str]:
        for _ in range(tries):
            suffix = "".join(secrets.choice(ALPHABET) for _ in range(8))
            unique_id = suffix
            if not self.unique_id_exists(owner_key_id, unique_id):
                return unique_id, suffix

        raise RuntimeError("Unable to generate unique_id after retries")

    def create_totp_entry(
        self,
        owner_key_id: str,
        unique_id: str,
        email: str,
        random_suffix: str,
        issuer: str,
        account_name: str,
        algorithm: str,
        digits: int,
        period: int,
        encrypted_secret: str,
        secret_nonce: str,
    ) -> dict[str, Any]:
        row_id = f"totp_{uuid.uuid4().hex[:12]}"
        ts = _now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO totp_entries(
                    id, owner_key_id, unique_id, email, random_suffix,
                    issuer, account_name, algorithm, digits, period,
                    encrypted_secret, secret_nonce, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row_id,
                    owner_key_id,
                    unique_id,
                    email,
                    random_suffix,
                    issuer,
                    account_name,
                    algorithm,
                    digits,
                    period,
                    encrypted_secret,
                    secret_nonce,
                    ts,
                    ts,
                ),
            )
        return {
            "id": row_id,
            "unique_id": unique_id,
            "email": email,
            "random_suffix": random_suffix,
            "issuer": issuer,
            "account": account_name,
            "algorithm": algorithm,
            "digits": digits,
            "period": period,
            "created_at": ts,
        }

    def get_totp_entry(self, owner_key_id: str, unique_id: str) -> sqlite3.Row | None:
        normalized = unique_id.strip().lower()
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT *
                FROM totp_entries
                WHERE owner_key_id = ? AND (unique_id = ? OR random_suffix = ?)
                """,
                (owner_key_id, normalized, normalized),
            ).fetchone()

    def list_totp_entries(self, owner_key_id: str, include_secret: bool = False) -> list[dict[str, Any]]:
        secret_columns = ", encrypted_secret, secret_nonce" if include_secret else ""
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT id, unique_id, email, random_suffix, issuer, account_name, algorithm, digits, period, created_at
                    {secret_columns}
                FROM totp_entries
                WHERE owner_key_id = ?
                ORDER BY created_at DESC
                """,
                (owner_key_id,),
            ).fetchall()

        return [dict(row) for row in rows]


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()
