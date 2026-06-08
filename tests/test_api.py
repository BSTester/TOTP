from __future__ import annotations

import base64
import importlib
import os
import secrets
import tempfile
from pathlib import Path
from urllib.parse import quote

import pytest
import qrcode
from fastapi.testclient import TestClient

TEST_SECRET = "JBSWY3DPEHPK3PXP"
TEST_URI = (
    "otpauth://totp/GitHub:alice@example.com"
    f"?secret={TEST_SECRET}&issuer=GitHub&algorithm=SHA1&digits=6&period=30"
)


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        master_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
        monkeypatch.setenv("APP_DB_PATH", str(tmp_path / "test.db"))
        monkeypatch.setenv("APP_MASTER_KEY", master_key)

        import app.config as config
        import app.main as main

        importlib.reload(config)
        main = importlib.reload(main)

        with TestClient(main.app) as test_client:
            yield test_client


def create_key(client: TestClient) -> str:
    response = client.post("/api/keys/generate")
    assert response.status_code == 200
    data = response.json()
    assert data["api_key"].startswith("tk_")
    return data["api_key"]


def test_import_list_single_and_batch_codes(client: TestClient) -> None:
    api_key = create_key(client)
    headers = {"X-API-Key": api_key}

    imported = client.post("/api/totp/import-uri", headers=headers, json={"otpauth_uri": TEST_URI})
    assert imported.status_code == 200
    imported_data = imported.json()
    assert len(imported_data["unique_id"]) == 8
    assert imported_data["digits"] == 6

    listed = client.get("/api/totp/list", headers=headers)
    assert listed.status_code == 200
    listed_items = listed.json()["items"]
    assert len(listed_items) == 1
    assert listed_items[0]["unique_id"] == imported_data["unique_id"]
    assert listed_items[0]["code"].isdigit()
    assert len(listed_items[0]["code"]) == 6
    assert 1 <= listed_items[0]["remaining"] <= 30
    assert "secret" not in listed_items[0]
    assert "encrypted_secret" not in listed_items[0]

    single = client.get(f"/api/totp/code/{quote(imported_data['unique_id'], safe='')}", headers=headers)
    assert single.status_code == 200
    single_data = single.json()
    assert single_data["code"] == listed_items[0]["code"]

    batch = client.post(
        "/api/totp/codes/batch",
        headers=headers,
        json={"ids": [imported_data["unique_id"], "ab12cd34"]},
    )
    assert batch.status_code == 200
    batch_items = batch.json()["items"]
    assert batch_items[0]["unique_id"] == imported_data["unique_id"]
    assert batch_items[0]["code"].isdigit()
    assert batch_items[1]["error"] == "未找到对应动态密码"


def test_code_from_uri_response_has_timer_and_optional_persist(client: TestClient) -> None:
    api_key = create_key(client)
    headers = {"X-API-Key": api_key}

    one_time = client.post("/api/totp/code-from-uri", headers=headers, json={"otpauth_uri": TEST_URI})
    assert one_time.status_code == 200
    one_time_data = one_time.json()
    assert one_time_data["persisted"] is False
    assert one_time_data["unique_id"] is None
    assert one_time_data["period"] == 30
    assert 1 <= one_time_data["remaining"] <= 30
    assert one_time_data["code"].isdigit()

    persisted = client.post(
        "/api/totp/code-from-uri",
        headers=headers,
        json={"otpauth_uri": TEST_URI, "email": "Alice@Example.com"},
    )
    assert persisted.status_code == 200
    persisted_data = persisted.json()
    assert persisted_data["persisted"] is True
    assert len(persisted_data["unique_id"]) == 8

    listed = client.get("/api/totp/list", headers=headers)
    assert listed.status_code == 200
    assert len(listed.json()["items"]) == 1


def test_code_from_qrcode_generates_one_time_code(client: TestClient) -> None:
    api_key = create_key(client)
    headers = {"X-API-Key": api_key}

    image = qrcode.make(TEST_URI)
    with tempfile.NamedTemporaryFile(suffix=".png") as image_file:
        image.save(image_file.name)
        image_file.seek(0)
        response = client.post(
            "/api/totp/code-from-qrcode",
            headers=headers,
            files={"file": ("qrcode.png", image_file.read(), "image/png")},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["persisted"] is False
    assert data["unique_id"] is None
    assert data["period"] == 30
    assert data["code"].isdigit()
    assert len(data["code"]) == 6


def test_base32_secret_import_and_one_time_code(client: TestClient) -> None:
    api_key = create_key(client)
    headers = {"X-API-Key": api_key}

    one_time = client.post(
        "/api/totp/code-from-source",
        headers=headers,
        json={"base32_secret": "jbsw y3dp-ehpk 3pxp"},
    )
    assert one_time.status_code == 200
    one_time_data = one_time.json()
    assert one_time_data["persisted"] is False
    assert one_time_data["unique_id"] is None
    assert one_time_data["period"] == 30
    assert one_time_data["code"].isdigit()
    assert len(one_time_data["code"]) == 6

    imported = client.post(
        "/api/totp/import-source",
        headers=headers,
        json={"base32_secret": "jbsw y3dp-ehpk 3pxp"},
    )
    assert imported.status_code == 200
    imported_data = imported.json()
    assert len(imported_data["unique_id"]) == 8

    listed = client.get("/api/totp/list", headers=headers)
    assert listed.status_code == 200
    items = listed.json()["items"]
    assert len(items) == 1
    assert items[0]["unique_id"] == imported_data["unique_id"]
    assert items[0]["code"].isdigit()


def test_invalid_base32_secret_returns_chinese_error(client: TestClient) -> None:
    api_key = create_key(client)
    headers = {"X-API-Key": api_key}

    response = client.post(
        "/api/totp/code-from-source",
        headers=headers,
        json={"base32_secret": "not-valid-0189"},
    )
    assert response.status_code == 400
    assert "Base32 密钥" in response.json()["detail"]


def test_api_key_data_isolation(client: TestClient) -> None:
    first_key = create_key(client)
    second_key = create_key(client)

    imported = client.post(
        "/api/totp/import-uri",
        headers={"X-API-Key": first_key},
        json={"otpauth_uri": TEST_URI},
    )
    assert imported.status_code == 200
    unique_id = imported.json()["unique_id"]

    forbidden_single = client.get(f"/api/totp/code/{quote(unique_id, safe='')}", headers={"X-API-Key": second_key})
    assert forbidden_single.status_code == 404

    isolated_list = client.get("/api/totp/list", headers={"X-API-Key": second_key})
    assert isolated_list.status_code == 200
    assert isolated_list.json()["items"] == []
