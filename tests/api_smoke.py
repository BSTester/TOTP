from __future__ import annotations

import json
import os
import sys
import tempfile
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import qrcode

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8010").rstrip("/")
TEST_URI = (
    "otpauth://totp/GitHub:smoke@example.com"
    "?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30"
)


def request(method: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> tuple[int, Any]:
    payload = None
    merged_headers = dict(headers or {})
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        merged_headers.setdefault("Content-Type", "application/json")

    req = Request(f"{BASE_URL}{path}", data=payload, headers=merged_headers, method=method)
    try:
        with urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else None
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = raw
        return exc.code, data


def multipart_file_request(path: str, file_path: str, headers: dict[str, str]) -> tuple[int, Any]:
    boundary = "----totp-smoke-boundary"
    with open(file_path, "rb") as stream:
        file_bytes = stream.read()
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="qrcode.png"\r\n'
        "Content-Type: image/png\r\n\r\n"
    ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")
    merged_headers = {
        **headers,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }
    req = Request(f"{BASE_URL}{path}", data=body, headers=merged_headers, method="POST")
    try:
        with urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else None
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = raw
        return exc.code, data


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    print(f"BASE_URL={BASE_URL}")

    status_code, key_data = request("POST", "/api/keys/generate")
    check(status_code == 200, f"generate key failed: {status_code} {key_data}")
    api_key = key_data["api_key"]
    headers = {"X-API-Key": api_key}
    print("生成 API Key: OK")

    status_code, imported = request("POST", "/api/totp/import-uri", {"otpauth_uri": TEST_URI}, headers)
    check(status_code == 200, f"import uri failed: {status_code} {imported}")
    unique_id = imported["unique_id"]
    check(len(unique_id) == 16, f"unexpected unique_id: {unique_id}")
    print(f"导入 URI: OK unique_id={unique_id}")

    status_code, listed = request("GET", "/api/totp/list", headers=headers)
    check(status_code == 200, f"list failed: {status_code} {listed}")
    items = listed["items"]
    check(len(items) >= 1, "list should contain imported record")
    first = next(item for item in items if item["unique_id"] == unique_id)
    check(first["code"].isdigit() and len(first["code"]) == 6, f"bad list code: {first}")
    check(1 <= first["remaining"] <= 30, f"bad remaining: {first}")
    check("secret" not in first and "encrypted_secret" not in first, "list leaked secret fields")
    print(f"列表当前码: OK code={first['code']} remaining={first['remaining']}")

    status_code, single = request("GET", f"/api/totp/code/{quote(unique_id, safe='')}", headers=headers)
    check(status_code == 200, f"single code failed: {status_code} {single}")
    check(single["unique_id"] == unique_id, f"single unique_id mismatch: {single}")
    check(single["code"].isdigit() and len(single["code"]) == 6, f"bad single code: {single}")
    print("单条取码: OK")

    status_code, batch = request(
        "POST",
        "/api/totp/codes/batch",
        {"ids": [unique_id, "ab12cd34"]},
        headers,
    )
    check(status_code == 200, f"batch failed: {status_code} {batch}")
    check(batch["items"][0]["unique_id"] == unique_id, f"batch first mismatch: {batch}")
    check(batch["items"][1]["error"] == "未找到对应动态密码", f"batch missing mismatch: {batch}")
    print("批量取码: OK")

    status_code, one_time = request("POST", "/api/totp/code-from-source", {"otpauth_uri": TEST_URI}, headers)
    check(status_code == 200, f"code-from-source uri failed: {status_code} {one_time}")
    check(one_time["persisted"] is False and one_time["unique_id"] is None, f"bad one-time response: {one_time}")
    check(one_time["period"] == 30 and 1 <= one_time["remaining"] <= 30, f"bad one-time timer: {one_time}")
    print("URI 一次性取码: OK")

    status_code, base32_one_time = request("POST", "/api/totp/code-from-source", {"base32_secret": "JBSW Y3DP EHPK 3PXP"}, headers)
    check(status_code == 200, f"code-from-source base32 failed: {status_code} {base32_one_time}")
    check(base32_one_time["persisted"] is False and base32_one_time["unique_id"] is None, f"bad base32 response: {base32_one_time}")
    check(base32_one_time["code"].isdigit() and len(base32_one_time["code"]) == 6, f"bad base32 code: {base32_one_time}")
    print("Base32 一次性取码: OK")

    qr_image = qrcode.make(TEST_URI)
    with tempfile.NamedTemporaryFile(suffix=".png") as image_file:
        qr_image.save(image_file.name)
        status_code, qr_one_time = multipart_file_request("/api/totp/code-from-qrcode", image_file.name, headers)
    check(status_code == 200, f"code-from-qrcode failed: {status_code} {qr_one_time}")
    check(qr_one_time["persisted"] is False and qr_one_time["unique_id"] is None, f"bad qrcode response: {qr_one_time}")
    check(qr_one_time["code"].isdigit() and len(qr_one_time["code"]) == 6, f"bad qrcode code: {qr_one_time}")
    print("二维码一次性取码: OK")

    print("接口测试通过")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"接口测试失败: {exc}", file=sys.stderr)
        raise SystemExit(1)
