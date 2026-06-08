from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM



def hash_api_key(raw_api_key: str) -> str:
    return hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()



def encrypt_secret(secret: str, master_key: bytes) -> tuple[str, str]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(master_key)
    encrypted = aesgcm.encrypt(nonce, secret.encode("utf-8"), associated_data=None)
    return _b64(encrypted), _b64(nonce)



def decrypt_secret(encrypted_secret: str, nonce: str, master_key: bytes) -> str:
    aesgcm = AESGCM(master_key)
    secret = aesgcm.decrypt(_unb64(nonce), _unb64(encrypted_secret), associated_data=None)
    return secret.decode("utf-8")



def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")



def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))
