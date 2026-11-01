from pathlib import Path

from securefile_vault.crypto import decrypt_data, encrypt_data

# Fernet processes the entire file in memory.
# Limit plaintext to 10 MiB for this initial version.
MAX_PLAINTEXT_BYTES = 10 * 1024 * 1024

# Encrypted Fernet tokens are larger than the original data.
MAX_ENCRYPTED_BYTES = 2 * MAX_PLAINTEXT_BYTES + 4096


def _read_limited(path: Path, limit: int) -> bytes:
    """Read a regular file without exceeding a size limit."""
    if not path.is_file():
        raise ValueError("Input must be an existing regular file.")

    with path.open("rb") as file:
        data = file.read(limit + 1)

    if len(data) > limit:
        raise ValueError(f"Input file exceeds the {limit} byte limit.")

    return data


def _write_new_file(path: Path, data: bytes) -> Path:
    """Create a new output file without replacing an existing file."""
    created = False

    try:
        with path.open("xb") as file:
            created = True
            file.write(data)
    except BaseException:
        if created:
            path.unlink(missing_ok=True)
        raise

    return path


def encrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    password: str,
) -> Path:
    """Encrypt a file without modifying the original."""
    source = Path(input_path)
    destination = Path(output_path)

    plaintext = _read_limited(source, MAX_PLAINTEXT_BYTES)
    encrypted = encrypt_data(plaintext, password)

    return _write_new_file(destination, encrypted)


def decrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    password: str,
) -> Path:
    """Decrypt a file without overwriting existing files."""
    source = Path(input_path)
    destination = Path(output_path)

    encrypted = _read_limited(source, MAX_ENCRYPTED_BYTES)

    # Authentication happens before any output file is created.
    plaintext = decrypt_data(encrypted, password)

    return _write_new_file(destination, plaintext)
