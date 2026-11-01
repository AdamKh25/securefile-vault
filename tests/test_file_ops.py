import pytest

from securefile_vault.file_ops import decrypt_file, encrypt_file


@pytest.mark.parametrize(
    "content",
    [b"Hello SecureFile Vault!", b"", b"\x00\xffbinary data"],
)
def test_file_round_trip(tmp_path, content):
    source = tmp_path / "original.bin"
    encrypted = tmp_path / "original.svault"
    recovered = tmp_path / "recovered.bin"

    source.write_bytes(content)

    encrypt_file(source, encrypted, "secure-password")

    assert encrypted.exists()
    assert encrypted.read_bytes() != content
    assert source.read_bytes() == content

    decrypt_file(encrypted, recovered, "secure-password")

    assert recovered.read_bytes() == content


def test_encryption_refuses_overwrite(tmp_path):
    source = tmp_path / "original.txt"
    output = tmp_path / "existing.svault"

    source.write_bytes(b"Important information")
    output.write_bytes(b"DO NOT REPLACE")

    with pytest.raises(FileExistsError):
        encrypt_file(source, output, "secure-password")

    assert output.read_bytes() == b"DO NOT REPLACE"


def test_decryption_refuses_overwrite(tmp_path):
    source = tmp_path / "original.txt"
    encrypted = tmp_path / "original.svault"
    output = tmp_path / "recovered.txt"

    source.write_bytes(b"Important information")
    encrypt_file(source, encrypted, "secure-password")
    output.write_bytes(b"DO NOT REPLACE")

    with pytest.raises(FileExistsError):
        decrypt_file(encrypted, output, "secure-password")

    assert output.read_bytes() == b"DO NOT REPLACE"


def test_wrong_password_creates_no_file(tmp_path):
    source = tmp_path / "original.txt"
    encrypted = tmp_path / "original.svault"
    output = tmp_path / "recovered.txt"

    source.write_bytes(b"Secret information")
    encrypt_file(source, encrypted, "correct-password")

    with pytest.raises(ValueError, match="Incorrect password"):
        decrypt_file(encrypted, output, "wrong-password")

    assert not output.exists()


def test_tampered_file_creates_no_output(tmp_path):
    source = tmp_path / "original.txt"
    encrypted = tmp_path / "original.svault"
    output = tmp_path / "recovered.txt"

    source.write_bytes(b"Confidential information")
    encrypt_file(source, encrypted, "secure-password")

    data = bytearray(encrypted.read_bytes())
    data[-15] ^= 1
    encrypted.write_bytes(data)

    with pytest.raises(ValueError, match="corrupted data"):
        decrypt_file(encrypted, output, "secure-password")

    assert not output.exists()


def test_plaintext_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr("securefile_vault.file_ops.MAX_PLAINTEXT_BYTES", 4)

    source = tmp_path / "large.bin"
    output = tmp_path / "large.svault"
    source.write_bytes(b"12345")

    with pytest.raises(ValueError, match="byte limit"):
        encrypt_file(source, output, "secure-password")

    assert not output.exists()


def test_encrypted_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr("securefile_vault.file_ops.MAX_ENCRYPTED_BYTES", 4)

    source = tmp_path / "large.svault"
    output = tmp_path / "recovered.bin"
    source.write_bytes(b"12345")

    with pytest.raises(ValueError, match="byte limit"):
        decrypt_file(source, output, "secure-password")

    assert not output.exists()
