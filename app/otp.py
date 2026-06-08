from __future__ import annotations

import base64
import binascii
import hashlib
import re
import time
from typing import Callable
from urllib.parse import parse_qs, unquote, urlparse

import pyotp

SUPPORTED_ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

_BASE32_RE = re.compile(r"^[A-Z2-7]+={0,6}$")


def _validate_totp_options(algorithm: str, digits: int, period: int) -> str:
    normalized_algorithm = algorithm.strip().upper() or "SHA1"
    if normalized_algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"不支持的算法：{normalized_algorithm}")

    if digits < 6 or digits > 10:
        raise ValueError("验证码位数必须在 6 到 10 之间")

    if period < 5 or period > 120:
        raise ValueError("刷新周期必须在 5 到 120 秒之间")

    return normalized_algorithm


def normalize_base32_secret(secret: str) -> str:
    """Normalize and validate a user-provided Base32 TOTP secret."""
    normalized = re.sub(r"[\s-]+", "", secret or "").upper()
    normalized = normalized.rstrip("=")

    if not normalized:
        raise ValueError("请输入 Base32 密钥")

    if not _BASE32_RE.fullmatch(normalized):
        raise ValueError("Base32 密钥只能包含 A-Z 和 2-7")

    padding = "=" * ((8 - len(normalized) % 8) % 8)
    try:
        decoded = base64.b32decode(normalized + padding, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Base32 密钥格式不正确") from exc

    if not decoded:
        raise ValueError("Base32 密钥格式不正确")

    return normalized


def parse_base32_secret(
    secret: str,
    issuer: str | None = None,
    account: str | None = None,
    algorithm: str = "SHA1",
    digits: int = 6,
    period: int = 30,
) -> dict[str, str | int]:
    normalized_secret = normalize_base32_secret(secret)
    normalized_algorithm = _validate_totp_options(algorithm, digits, period)

    return {
        "secret": normalized_secret,
        "issuer": (issuer or "").strip(),
        "account": (account or "").strip(),
        "algorithm": normalized_algorithm,
        "digits": digits,
        "period": period,
    }


def parse_otpauth_uri(uri: str) -> dict[str, str | int]:
    parsed = urlparse(uri.strip())

    if parsed.scheme != "otpauth":
        raise ValueError("请输入有效的 otpauth URI")

    if parsed.netloc.lower() != "totp":
        raise ValueError("当前仅支持 TOTP 类型")

    label = unquote(parsed.path.lstrip("/"))
    query = parse_qs(parsed.query)

    secret = query.get("secret", [""])[0].strip()
    if not secret:
        raise ValueError("otpauth URI 缺少 secret")

    issuer = query.get("issuer", [""])[0].strip()
    algorithm = query.get("algorithm", ["SHA1"])[0].strip().upper() or "SHA1"
    try:
        digits = int(query.get("digits", [6])[0])
        period = int(query.get("period", [30])[0])
    except ValueError as exc:
        raise ValueError("digits 或 period 参数格式不正确") from exc

    algorithm = _validate_totp_options(algorithm, digits, period)
    secret = normalize_base32_secret(secret)

    account = label
    if ":" in label:
        label_issuer, account = label.split(":", 1)
        if not issuer:
            issuer = label_issuer.strip()

    return {
        "secret": secret,
        "issuer": issuer,
        "account": account.strip(),
        "algorithm": algorithm,
        "digits": digits,
        "period": period,
    }


def guess_email(account_value: str) -> str | None:
    candidate = account_value.strip().lower()
    if "@" in candidate and "." in candidate.split("@", 1)[-1]:
        return candidate
    return None


def generate_totp_code(secret: str, digits: int, period: int, algorithm: str) -> tuple[str, int]:
    digest: Callable = SUPPORTED_ALGORITHMS[algorithm.upper()]
    normalized_secret = normalize_base32_secret(secret)
    totp = pyotp.TOTP(normalized_secret, digits=digits, interval=period, digest=digest)
    now = int(time.time())
    remaining = period - (now % period)
    return totp.at(now), remaining
