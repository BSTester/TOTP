from __future__ import annotations

import hmac
import io
import sqlite3
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from PIL import Image

from .config import load_settings
from .db import ApiKeyOwner, Database
from .otp import generate_totp_code, guess_email, normalize_base32_secret, parse_base32_secret, parse_otpauth_uri
from .schemas import (
    BatchCodesRequest,
    BatchCodesResponse,
    CodeFromUriResponse,
    GenerateApiKeyRequest,
    GenerateApiKeyResponse,
    ImportTotpResponse,
    ImportUriRequest,
    QrPreviewResponse,
    TotpCodeResponse,
    TotpListItemResponse,
    TotpListResponse,
)
from .security import decrypt_secret, encrypt_secret

settings = load_settings()
db = Database(settings.db_path)
db.init_schema()

app = FastAPI(title="Hosted TOTP", version="0.1.0")

BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    fields: list[str] = []
    for error in exc.errors():
        loc = [str(part) for part in error.get("loc", []) if part not in {"body", "query", "path", "header", "cookie"}]
        if loc:
            fields.append(".".join(loc))
    suffix = f"：{'; '.join(fields[:5])}" if fields else ""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": f"请求参数不正确{suffix}"},
    )


def get_owner(request: Request) -> ApiKeyOwner:
    raw_key = request.headers.get("X-API-Key") or request.cookies.get(settings.web_cookie_name)
    if not raw_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少 API Key")

    owner = db.resolve_owner(raw_key)
    if not owner:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API Key 无效")
    return owner



def _decode_qr(data: bytes) -> str:
    if not data:
        raise ValueError("图片文件为空")

    try:
        from pyzbar.pyzbar import decode as qr_decode
    except Exception as exc:
        raise ValueError("当前环境缺少二维码识别依赖") from exc

    try:
        image = Image.open(io.BytesIO(data))
    except Exception as exc:
        raise ValueError("不支持的图片格式") from exc

    decoded = qr_decode(image)
    if not decoded:
        raise ValueError("图片中未识别到二维码")

    value = decoded[0].data.decode("utf-8", errors="ignore")
    if not value:
        raise ValueError("二维码内容为空")

    return value


async def _read_upload_bytes(file: UploadFile) -> bytes:
    try:
        data = await file.read()
    finally:
        await file.close()

    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="图片文件过大")
    return data


def _config_from_payload(payload: ImportUriRequest) -> dict[str, str | int]:
    raw_uri = (payload.otpauth_uri or "").strip()
    raw_secret = (payload.base32_secret or "").strip()

    if raw_uri:
        if raw_uri.lower().startswith("otpauth://"):
            return parse_otpauth_uri(raw_uri)
        if raw_secret:
            raise ValueError("请只填写 otpauth URI 或 Base32 密钥中的一种")
        raw_secret = raw_uri

    if raw_secret:
        return parse_base32_secret(
            raw_secret,
            issuer=payload.issuer,
            account=payload.account,
            algorithm=payload.algorithm,
            digits=payload.digits,
            period=payload.period,
        )

    raise ValueError("请提供 otpauth URI 或 Base32 密钥")


def _code_from_config(config: dict[str, str | int]) -> tuple[str, int]:
    return generate_totp_code(
        secret=str(config["secret"]),
        digits=int(config["digits"]),
        period=int(config["period"]),
        algorithm=str(config["algorithm"]),
    )


def _code_from_payload(payload: ImportUriRequest) -> tuple[dict[str, str | int], str, int]:
    config = _config_from_payload(payload)
    code, remaining = _code_from_config(config)
    return config, code, remaining



def _normalize_unique_id(value: str) -> str:
    return value.strip().lower()


def _display_unique_id(row: dict) -> str:
    suffix = str(row.get("random_suffix") or "").strip().lower()
    if suffix:
        return suffix
    unique_id = str(row.get("unique_id") or "").strip().lower()
    return unique_id.rsplit("#", 1)[-1]


def _unique_id_from_config(owner_key_id: str, config: dict[str, str | int]) -> str:
    normalized_secret = normalize_base32_secret(str(config["secret"]))
    normalized_algorithm = str(config["algorithm"]).strip().upper() or "SHA1"
    payload = "\0".join(
        [
            "totp-unique-id-v1",
            owner_key_id,
            normalized_secret,
            normalized_algorithm,
            str(int(config["digits"])),
            str(int(config["period"])),
        ]
    ).encode("utf-8")
    # HMAC hides the secret while still producing a stable lookup id.
    return hmac.new(settings.master_key, payload, "sha256").hexdigest()[:16]


def _row_to_import_record(row: dict) -> dict:
    return {
        "id": row["id"],
        "unique_id": row["unique_id"],
        "email": row["email"],
        "random_suffix": row["random_suffix"],
        "issuer": row["issuer"],
        "account": row["account_name"],
        "algorithm": row["algorithm"],
        "digits": row["digits"],
        "period": row["period"],
        "created_at": row["created_at"],
    }

def _mask_api_key(value: str) -> str:
    value = value.strip()
    if len(value) <= 12:
        return f"{value[:3]}••••{value[-2:]}" if len(value) > 5 else "••••"
    return f"{value[:6]}••••••••{value[-6:]}"



def _import_uri(owner: ApiKeyOwner, payload: ImportUriRequest) -> dict:
    config = _config_from_payload(payload)
    unique_id = _unique_id_from_config(owner.id, config)

    existing = db.get_totp_entry(owner.id, unique_id)
    if existing:
        return _row_to_import_record(dict(existing))

    email = (payload.email or "").strip().lower()
    if not email:
        guessed = guess_email(str(config["account"]))
        if guessed:
            email = guessed

    encrypted_secret, nonce = encrypt_secret(str(config["secret"]), settings.master_key)

    try:
        return db.create_totp_entry(
            owner_key_id=owner.id,
            unique_id=unique_id,
            email=email,
            random_suffix=unique_id,
            issuer=str(config["issuer"]),
            account_name=str(config["account"]),
            algorithm=str(config["algorithm"]),
            digits=int(config["digits"]),
            period=int(config["period"]),
            encrypted_secret=encrypted_secret,
            secret_nonce=nonce,
        )
    except sqlite3.IntegrityError as exc:
        existing = db.get_totp_entry(owner.id, unique_id)
        if existing:
            return _row_to_import_record(dict(existing))
        raise exc



def _generate_code_from_row(row: dict) -> tuple[str, int]:
    secret = decrypt_secret(row["encrypted_secret"], row["secret_nonce"], settings.master_key)
    return generate_totp_code(
        secret=secret,
        digits=int(row["digits"]),
        period=int(row["period"]),
        algorithm=row["algorithm"],
    )


def _row_to_code_response(row: dict) -> TotpCodeResponse:
    code, remaining = _generate_code_from_row(row)
    return TotpCodeResponse(
        id=row["id"],
        unique_id=_display_unique_id(row),
        issuer=row["issuer"],
        account=row["account_name"],
        code=code,
        period=int(row["period"]),
        remaining=remaining,
    )


@app.get("/", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/api-docs", response_class=HTMLResponse)
def api_docs_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("api_docs.html", {"request": request})


@app.get("/app", response_class=HTMLResponse)
def app_page(request: Request) -> HTMLResponse:
    raw_key = request.cookies.get(settings.web_cookie_name)
    if not raw_key:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    owner = db.resolve_owner(raw_key)
    if not owner:
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie(settings.web_cookie_name)
        return response

    return templates.TemplateResponse(
        "app.html",
        {
            "request": request,
            "masked_api_key": _mask_api_key(raw_key),
        },
    )


@app.post("/web/login")
def web_login(api_key: str = Form(...)) -> RedirectResponse:
    owner = db.resolve_owner(api_key)
    if not owner:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API Key 无效")

    response = RedirectResponse(url="/app", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=settings.web_cookie_name,
        value=api_key,
        httponly=True,
        samesite="lax",
        secure=False,
    )
    return response


@app.post("/web/logout")
def web_logout() -> RedirectResponse:
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(settings.web_cookie_name)
    return response


@app.post("/api/keys/generate", response_model=GenerateApiKeyResponse)
def generate_api_key(payload: GenerateApiKeyRequest | None = None) -> GenerateApiKeyResponse:
    key_id, raw_key = db.create_api_key(name=payload.name if payload else "web-user")
    return GenerateApiKeyResponse(key_id=key_id, api_key=raw_key)


@app.post("/api/totp/import-uri", response_model=ImportTotpResponse)
@app.post("/api/totp/import-source", response_model=ImportTotpResponse)
def import_uri(payload: ImportUriRequest, owner: ApiKeyOwner = Depends(get_owner)) -> ImportTotpResponse:
    try:
        record = _import_uri(owner, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return ImportTotpResponse(
        id=record["id"],
        unique_id=record["random_suffix"],
        issuer=record["issuer"],
        account=record["account"],
        digits=record["digits"],
        period=record["period"],
    )


@app.post("/api/totp/import-qrcode", response_model=ImportTotpResponse)
async def import_qrcode(
    file: UploadFile = File(...),
    email: str | None = Form(None),
    owner: ApiKeyOwner = Depends(get_owner),
) -> ImportTotpResponse:
    data = await _read_upload_bytes(file)

    try:
        uri = _decode_qr(data)
        record = _import_uri(owner, ImportUriRequest(otpauth_uri=uri, email=email))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return ImportTotpResponse(
        id=record["id"],
        unique_id=record["random_suffix"],
        issuer=record["issuer"],
        account=record["account"],
        digits=record["digits"],
        period=record["period"],
    )


@app.post("/api/totp/preview-qrcode", response_model=QrPreviewResponse)
async def preview_qrcode(
    file: UploadFile = File(...),
    owner: ApiKeyOwner = Depends(get_owner),
) -> QrPreviewResponse:
    data = await _read_upload_bytes(file)

    try:
        uri = _decode_qr(data)
        _config_from_payload(ImportUriRequest(otpauth_uri=uri))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return QrPreviewResponse(otpauth_uri=uri)


@app.post("/api/totp/code-from-uri", response_model=CodeFromUriResponse)
@app.post("/api/totp/code-from-source", response_model=CodeFromUriResponse)
def code_from_uri(payload: ImportUriRequest, owner: ApiKeyOwner = Depends(get_owner)) -> CodeFromUriResponse:
    try:
        config, code, remaining = _code_from_payload(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    email = (payload.email or "").strip()
    if not email:
        return CodeFromUriResponse(
            code=code,
            period=int(config["period"]),
            remaining=remaining,
            persisted=False,
            unique_id=None,
        )

    try:
        record = _import_uri(owner, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return CodeFromUriResponse(
        code=code,
        period=int(config["period"]),
        remaining=remaining,
        persisted=True,
        unique_id=record["random_suffix"],
    )


@app.post("/api/totp/code-from-qrcode", response_model=CodeFromUriResponse)
async def code_from_qrcode(
    file: UploadFile = File(...),
    owner: ApiKeyOwner = Depends(get_owner),
) -> CodeFromUriResponse:
    data = await _read_upload_bytes(file)
    try:
        uri = _decode_qr(data)
        config, code, remaining = _code_from_payload(ImportUriRequest(otpauth_uri=uri))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return CodeFromUriResponse(
        code=code,
        period=int(config["period"]),
        remaining=remaining,
        persisted=False,
        unique_id=None,
    )


@app.get("/api/totp/code/{unique_id}", response_model=TotpCodeResponse)
def get_code(unique_id: str, owner: ApiKeyOwner = Depends(get_owner)) -> TotpCodeResponse:
    row = db.get_totp_entry(owner.id, _normalize_unique_id(unique_id))
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="未找到对应动态密码")
    return _row_to_code_response(dict(row))


@app.post("/api/totp/codes/batch", response_model=BatchCodesResponse)
def batch_codes(payload: BatchCodesRequest, owner: ApiKeyOwner = Depends(get_owner)) -> BatchCodesResponse:
    items: list[dict] = []
    for unique_id in payload.ids:
        normalized = _normalize_unique_id(unique_id)
        row = db.get_totp_entry(owner.id, normalized)
        if not row:
            items.append({"unique_id": normalized.rsplit("#", 1)[-1], "error": "未找到对应动态密码"})
            continue

        code_payload = _row_to_code_response(dict(row))
        items.append(code_payload.model_dump())

    return BatchCodesResponse(items=items)


@app.get("/api/totp/list", response_model=TotpListResponse)
def list_totp(owner: ApiKeyOwner = Depends(get_owner)) -> TotpListResponse:
    items: list[TotpListItemResponse] = []
    seen_ids: set[str] = set()
    for row in db.list_totp_entries(owner.id, include_secret=True):
        unique_id = _display_unique_id(row)
        if unique_id in seen_ids:
            continue
        seen_ids.add(unique_id)
        code, remaining = _generate_code_from_row(row)
        items.append(
            TotpListItemResponse(
                id=row["id"],
                unique_id=_display_unique_id(row),
                email=row["email"],
                issuer=row["issuer"],
                account=row["account_name"],
                code=code,
                period=int(row["period"]),
                remaining=remaining,
                created_at=row["created_at"],
            )
        )

    return TotpListResponse(items=items)
