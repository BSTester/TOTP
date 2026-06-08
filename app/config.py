from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEV_MASTER_KEY_FILE = PROJECT_ROOT / ".dev_master_key"


def _decode_master_key(value: str) -> bytes:
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        key = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:  # pragma: no cover - defensive
        raise ValueError("APP_MASTER_KEY is not valid base64-url data") from exc
    if len(key) != 32:
        raise ValueError("APP_MASTER_KEY must decode to exactly 32 bytes")
    return key


def _resolve_master_key_file() -> Path:
    raw_path = os.getenv("APP_MASTER_KEY_FILE", "").strip()
    if not raw_path:
        return DEV_MASTER_KEY_FILE

    key_path = Path(raw_path)
    if not key_path.is_absolute():
        key_path = PROJECT_ROOT / key_path
    return key_path


def _load_master_key() -> bytes:
    env_value = os.getenv("APP_MASTER_KEY", "").strip()
    if env_value:
        return _decode_master_key(env_value)

    key_file = _resolve_master_key_file()
    if key_file.exists():
        return _decode_master_key(key_file.read_text(encoding="utf-8").strip())

    key = secrets.token_bytes(32)
    encoded = base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text(encoded, encoding="utf-8")
    return key


@dataclass(frozen=True)
class Settings:
    db_path: Path
    max_upload_bytes: int
    web_cookie_name: str
    master_key: bytes



def load_settings() -> Settings:
    db_path_value = os.getenv("APP_DB_PATH", "data.db").strip() or "data.db"
    db_path = Path(db_path_value)
    if not db_path.is_absolute():
        db_path = PROJECT_ROOT / db_path

    max_upload_bytes = int(os.getenv("APP_MAX_UPLOAD_BYTES", "2097152"))
    web_cookie_name = os.getenv("APP_WEB_COOKIE_NAME", "totp_api_key").strip() or "totp_api_key"

    return Settings(
        db_path=db_path,
        max_upload_bytes=max_upload_bytes,
        web_cookie_name=web_cookie_name,
        master_key=_load_master_key(),
    )
