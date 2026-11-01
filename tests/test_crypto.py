import pytest

from securefile_vault.crypto import decrypt_data, encrypt_data


@pytest.mark.parametrize(
    "original",
    [b"Hello SecureFile Vault!", b"", b"\x00\xffbinary"],
)
def test_encrypt_decrypt_round_trip(original):
    encrypted = encrypt_data(original, "correct horse battery staple")

    assert encrypted != original
    assert decrypt_data(encrypted, "correct horse battery staple") == original


def test_wrong_password():
    encrypted = encrypt_data(b"Confidential data", "correct-password")

    with pytest.raises(ValueError, match="Incorrect password"):
        decrypt_data(encrypted, "wrong-password")


def test_tampered_data():
    encrypted = bytearray(encrypt_data(b"Important data", "secret-passphrase"))
    encrypted[-15] ^= 1

    with pytest.raises(ValueError, match="corrupted data"):
        decrypt_data(bytes(encrypted), "secret-passphrase")


def test_random_salt():
    first = encrypt_data(b"Same data", "same-password")
    second = encrypt_data(b"Same data", "same-password")

    assert first != second


def test_invalid_format():
    with pytest.raises(ValueError, match="Unrecognized"):
        decrypt_data(b"NOT_A_SECUREFILE", "password")


def test_empty_password():
    with pytest.raises(ValueError, match="non-empty"):
        encrypt_data(b"Test", "")
