"""Criptografia de arquivos exportados (envelope protegido por senha).

Os arquivos gerados pela exportação (devices/alertas/vulnerabilidades) podem ser
cifrados com uma senha informada pelo usuário no momento da exportação. A mesma
senha é exigida na importação.

A chave é derivada da senha via **scrypt** (KDF resistente a força bruta) com um
salt aleatório por arquivo, e o conteúdo é cifrado com **Fernet** (AES-128-CBC +
HMAC-SHA256). Diferente do FERNET_KEY do servidor (usado para SNMP), este esquema
é portátil: o arquivo pode ser importado em outra instalação bastando a senha.

Formato do envelope (texto JSON, seguro para download/upload):

    {"nmenc": 1, "kdf": "scrypt", "n": 32768, "r": 8, "p": 1,
     "salt": "<base64>", "fmt": "json|csv", "data": "<fernet token>"}
"""

import base64
import json
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_MAGIC = "nmenc"
_VERSION = 1
_SALT_BYTES = 16
# Parâmetros scrypt (custo). n deve ser potência de 2; 2**15 = boa margem interativa.
_SCRYPT_N = 32768
_SCRYPT_R = 8
_SCRYPT_P = 1


def _derive_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    """Deriva uma chave Fernet (base64 url-safe de 32 bytes) a partir da senha."""
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    raw = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


class DecryptError(Exception):
    """Falha ao decifrar (senha incorreta ou arquivo corrompido/inválido)."""


def encrypt_payload(plaintext: str, password: str, fmt: str = "json") -> str:
    """Cifra `plaintext` com a `password` e retorna o envelope JSON (str)."""
    salt = os.urandom(_SALT_BYTES)
    key = _derive_key(password, salt, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
    token = Fernet(key).encrypt(plaintext.encode("utf-8")).decode("ascii")
    envelope = {
        _MAGIC: _VERSION,
        "kdf": "scrypt",
        "n": _SCRYPT_N,
        "r": _SCRYPT_R,
        "p": _SCRYPT_P,
        "salt": base64.b64encode(salt).decode("ascii"),
        "fmt": fmt,
        "data": token,
    }
    return json.dumps(envelope, ensure_ascii=False)


def is_encrypted_envelope(text: str) -> bool:
    """Detecta se `text` é um envelope cifrado por senha desta aplicação."""
    stripped = text.lstrip()
    if not stripped.startswith("{"):
        return False
    try:
        obj = json.loads(stripped)
    except (ValueError, TypeError):
        return False
    return isinstance(obj, dict) and _MAGIC in obj and "data" in obj


def decrypt_payload(envelope_text: str, password: str) -> tuple[str, str]:
    """Decifra o envelope. Retorna (plaintext, fmt).

    Lança DecryptError se a senha estiver incorreta ou o arquivo for inválido.
    """
    try:
        env = json.loads(envelope_text)
        salt = base64.b64decode(env["salt"])
        n = int(env.get("n", _SCRYPT_N))
        r = int(env.get("r", _SCRYPT_R))
        p = int(env.get("p", _SCRYPT_P))
        token = env["data"].encode("ascii")
        fmt = env.get("fmt", "json")
    except (ValueError, KeyError, TypeError) as exc:
        raise DecryptError("Arquivo cifrado inválido ou corrompido.") from exc

    key = _derive_key(password, salt, n, r, p)
    try:
        plaintext = Fernet(key).decrypt(token).decode("utf-8")
    except (InvalidToken, Exception) as exc:  # noqa: BLE001 - senha errada cai aqui
        raise DecryptError("Senha incorreta ou arquivo corrompido.") from exc
    return plaintext, fmt
