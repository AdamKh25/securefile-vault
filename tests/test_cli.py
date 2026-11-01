"""Tests for the SecureFile Vault CLI."""

from securefile_vault.cli import main
from securefile_vault.file_ops import encrypt_file


def mock_passwords(monkeypatch, *passwords):
    values = iter(passwords)
    monkeypatch.setattr(
        "securefile_vault.cli.getpass.getpass",
        lambda prompt: next(values),
    )


def test_cli_round_trip(tmp_path, monkeypatch):
    source = tmp_path / "original.txt"
    encrypted = tmp_path / "original.svault"
    recovered = tmp_path / "recovered.txt"

    source.write_bytes(b"Secret document")

    mock_passwords(monkeypatch, "test-password", "test-password")
    assert main(["encrypt", str(source), str(encrypted)]) == 0

    mock_passwords(monkeypatch, "test-password")
    assert main(["decrypt", str(encrypted), str(recovered)]) == 0

    assert recovered.read_bytes() == source.read_bytes()


def test_cli_password_mismatch(tmp_path, monkeypatch, capsys):
    source = tmp_path / "original.txt"
    output = tmp_path / "original.svault"
    source.write_bytes(b"Confidential")

    mock_passwords(monkeypatch, "password-one", "password-two")

    assert main(["encrypt", str(source), str(output)]) == 1
    assert not output.exists()
    assert "passwords do not match" in capsys.readouterr().err


def test_cli_wrong_password(tmp_path, monkeypatch, capsys):
    source = tmp_path / "original.txt"
    encrypted = tmp_path / "original.svault"
    output = tmp_path / "recovered.txt"

    source.write_bytes(b"Confidential")
    encrypt_file(source, encrypted, "correct-password")

    mock_passwords(monkeypatch, "wrong-password")

    assert main(["decrypt", str(encrypted), str(output)]) == 1
    assert not output.exists()
    assert "Incorrect password" in capsys.readouterr().err


def test_cli_missing_input(tmp_path, monkeypatch, capsys):
    source = tmp_path / "missing.txt"
    output = tmp_path / "output.svault"

    mock_passwords(monkeypatch, "test-password", "test-password")

    assert main(["encrypt", str(source), str(output)]) == 1
    assert not output.exists()
    assert "existing regular file" in capsys.readouterr().err


def test_cli_refuses_overwrite(tmp_path, monkeypatch, capsys):
    source = tmp_path / "original.txt"
    output = tmp_path / "existing.svault"

    source.write_bytes(b"Important data")
    output.write_bytes(b"DO NOT REPLACE")

    mock_passwords(monkeypatch, "test-password", "test-password")

    assert main(["encrypt", str(source), str(output)]) == 1
    assert output.read_bytes() == b"DO NOT REPLACE"
    assert "Error:" in capsys.readouterr().err
