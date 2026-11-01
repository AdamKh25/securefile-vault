"""Command-line interface for SecureFile Vault."""

import argparse
import getpass
import sys

from securefile_vault.file_ops import decrypt_file, encrypt_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="securefile-vault",
        description="Password-protected file encryption and decryption.",
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    for command in ("encrypt", "decrypt"):
        subparser = commands.add_parser(
            command,
            help=f"{command.capitalize()} a file",
        )
        subparser.add_argument("input", help="Input file path")
        subparser.add_argument("output", help="Output file path")

    args = parser.parse_args(argv)

    try:
        password = getpass.getpass("Password: ")

        if args.command == "encrypt":
            confirmation = getpass.getpass("Confirm password: ")

            if password != confirmation:
                print("Error: passwords do not match.", file=sys.stderr)
                return 1

            result = encrypt_file(
                args.input,
                args.output,
                password,
            )
        else:
            result = decrypt_file(
                args.input,
                args.output,
                password,
            )

    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"File saved successfully: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
