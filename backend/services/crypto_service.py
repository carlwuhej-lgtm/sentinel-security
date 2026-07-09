"""
AES-256-GCM 对称加密服务

用于保护敏感配置数据（如 SMTP 密码），防止数据库泄露导致凭据泄露。
加密密钥从环境变量 SENTINEL_ENCRYPTION_KEY 读取，未设置时自动生成并持久化。
"""

import os
import json
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

_ENCRYPTION_KEY: bytes | None = None
_ENCRYPTION_NS: str | None = None


def _get_key() -> bytes:
    """加载或生成 256 位加密密钥。"""
    global _ENCRYPTION_KEY
    if _ENCRYPTION_KEY is not None:
        return _ENCRYPTION_KEY

    env_key = os.environ.get("SENTINEL_ENCRYPTION_KEY", "")
    if env_key:
        # 从环境变量派生 256 位密钥
        salt = b"sentinel-smtp-encrypt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=100_000, backend=default_backend(),
        )
        _ENCRYPTION_KEY = kdf.derive(env_key.encode())
        return _ENCRYPTION_KEY

    # 自动生成并持久化
    key_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".encryption_key")
    try:
        if os.path.isfile(key_file):
            with open(key_file, "rb") as f:
                saved = f.read()
            if len(saved) >= 32:
                _ENCRYPTION_KEY = saved[:32]
                return _ENCRYPTION_KEY
    except OSError:
        pass

    _ENCRYPTION_KEY = secrets.token_bytes(32)
    try:
        with open(key_file, "wb") as f:
            f.write(_ENCRYPTION_KEY)
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return _ENCRYPTION_KEY


def encrypt(plaintext: str) -> str:
    """加密字符串，返回 base64 编码的密文（包含 nonce）。"""
    if not plaintext:
        return ""
    key = _get_key()
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # 格式: nonce_hex:ciphertext_hex
    return nonce.hex() + ":" + ciphertext.hex()


def decrypt(encrypted: str) -> str:
    """解密字符串，明文可能混入旧格式，优先判断。"""
    if not encrypted:
        return ""
    # 旧格式: 明文存储（向后兼容）
    if ":" not in encrypted:
        return encrypted

    try:
        nonce_hex, ct_hex = encrypted.split(":", 1)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ct_hex)
        key = _get_key()
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
    except Exception:
        # 解密失败返回空（可能是旧明文恰好包含 :）
        return ""


def is_encrypted(value: str) -> bool:
    """判断字符串是否已加密。"""
    if not value or ":" not in value:
        return False
    try:
        parts = value.split(":", 1)
        return len(parts[0]) == 24 and all(c in "0123456789abcdef" for c in parts[0])
    except Exception:
        return False
