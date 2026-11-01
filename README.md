
# SecureFile Vault

A Python command-line application for password-protected file encryption and decryption.

> **Status:** Development-stage cybersecurity portfolio project. Not independently security-audited. Do not rely on it as the sole protection for sensitive or irreplaceable files.

## Features

- Password-based file encryption and decryption
- Argon2id password-based key derivation
- Fernet authenticated encryption
- Random salt generation
- Detection of incorrect passwords and tampered data
- Protection against overwriting existing files
- Preservation of original files
- 10 MiB plaintext file-size limit
- Automated tests using pytest
- Code quality checks using Ruff

## Technology Stack

- Python 3.13+
- cryptography
- pytest
- Ruff

## Installation

Clone the repository and open its directory.

Create a virtual environment:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the project:

```powershell
python -m pip install -e ".[dev]"
```

## Usage

Encrypt a file:

```powershell
securefile-vault encrypt sample.txt sample.svault
```

Decrypt a file:

```powershell
securefile-vault decrypt sample.svault recovered.txt
```

Passwords are entered through a hidden terminal prompt.

## Testing

Run all automated tests:

```powershell
python -m pytest -v
```

Check code quality:

```powershell
python -m ruff check src tests
python -m ruff format --check src tests
```

## Security Considerations

- Original files are not automatically deleted.
- Existing output files are not overwritten.
- Passwords are not included in command-line arguments.
- Forgotten passwords cannot be recovered by the application.
- The current version processes files in memory.
- File permissions, symbolic-link handling, and interrupted-write recovery require further hardening.
- The application has not undergone an independent security audit.

## Project Status

Core encryption, file operations, and CLI functionality have been implemented and tested.

Further security testing, hardening, and improvements are planned.
