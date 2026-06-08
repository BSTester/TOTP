from __future__ import annotations

from pydantic import BaseModel, Field


class GenerateApiKeyRequest(BaseModel):
    name: str = Field(default="web-user", min_length=2, max_length=60)


class GenerateApiKeyResponse(BaseModel):
    key_id: str
    api_key: str


class ImportUriRequest(BaseModel):
    otpauth_uri: str | None = None
    base32_secret: str | None = None
    email: str | None = None
    issuer: str | None = None
    account: str | None = None
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30


class ImportTotpResponse(BaseModel):
    id: str
    unique_id: str
    issuer: str
    account: str
    digits: int
    period: int


class QrPreviewResponse(BaseModel):
    otpauth_uri: str


class CodeOnlyResponse(BaseModel):
    code: str


class CodeFromUriResponse(BaseModel):
    code: str
    period: int
    remaining: int
    persisted: bool
    unique_id: str | None = None


class TotpCodeResponse(BaseModel):
    id: str
    unique_id: str
    issuer: str
    account: str
    code: str
    period: int
    remaining: int


class BatchCodesRequest(BaseModel):
    ids: list[str] = Field(default_factory=list, max_length=200)


class BatchCodesResponse(BaseModel):
    items: list[dict]


class TotpListItemResponse(BaseModel):
    id: str
    unique_id: str
    email: str
    issuer: str
    account: str
    code: str
    period: int
    remaining: int
    created_at: str


class TotpListResponse(BaseModel):
    items: list[TotpListItemResponse]
