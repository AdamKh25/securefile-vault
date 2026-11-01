import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MAGIC = b"SFV1"
SALT_SIZE = 16


def _make_cipher(password: str, salt: bytes) -> Fernet:
    """Derive an encryption key from a password and random salt."""
    if not password:
        raise ValueError("A non-empty password is required.")

    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=2,
        lanes=1,
        memory_cost=19 * 1024,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return Fernet(key)


def encrypt_data(data: bytes, password: str) -> bytes:
    """Encrypt data using a password-derived key."""
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes.")

    salt = os.urandom(SALT_SIZE)
    cipher = _make_cipher(password, salt)

    return MAGIC + salt + cipher.encrypt(data)


def decrypt_data(blob: bytes, password: str) -> bytes:
    """Decrypt data and reject invalid or tampered ciphertext."""
    if not isinstance(blob, bytes):
        raise TypeError("Encrypted data must be bytes.")

    if not blob.startswith(MAGIC) or len(blob) <= len(MAGIC) + SALT_SIZE:
        raise ValueError("Unrecognized or incomplete SecureFile Vault data.")

    salt_start = len(MAGIC)
    salt_end = salt_start + SALT_SIZE

    salt = blob[salt_start:salt_end]
    token = blob[salt_end:]

    try:
        cipher = _make_cipher(password, salt)
        return cipher.decrypt(token)
    except InvalidToken as exc:
        raise ValueError("Incorrect password or corrupted data.") from exc
