#!/usr/bin/env python3
"""Generate strong local secrets for Inventory without committing credentials."""
from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import string
from pathlib import Path

GENERATORS = {
    "SECRET_KEY": lambda: secrets.token_hex(48),
    "SESSION_SALT": lambda: secrets.token_hex(32),
    "INVENTORY_INGEST_TOKEN": lambda: secrets.token_urlsafe(48),
    "DB_PASS": lambda: secrets.token_urlsafe(36),
    "ADMIN_PASSWORD": lambda: strong_password(32),
    "ASSET_WEBHOOK_TOKEN": lambda: secrets.token_urlsafe(48),
}


def strong_password(length: int = 32) -> str:
    """Return a dotenv-safe password with guaranteed character classes."""
    if length < 16:
        raise ValueError("password length must be >= 16")
    alphabet = string.ascii_letters + string.digits + "!@%_-"
    chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@%_-"),
    ]
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def parse_env(lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def render_env(lines: list[str], replacements: dict[str, str]) -> str:
    out: list[str] = []
    for raw in lines:
        stripped = raw.strip()
        if stripped and not stripped.startswith("#") and "=" in raw:
            key = raw.split("=", 1)[0].strip()
            if key in replacements:
                newline = "\n" if raw.endswith("\n") else ""
                out.append(f"{key}={replacements[key]}{newline}")
                continue
        out.append(raw)
    return "".join(out)


def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    os.chmod(path, mode)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create/update Inventory .env with cryptographically strong secrets."
    )
    parser.add_argument("--template", default=".env.example", help="dotenv template")
    parser.add_argument("--env", default=".env", help="destination dotenv file")
    parser.add_argument("--hashes", default=".env.hashes", help="SHA-256 fingerprint file")
    parser.add_argument(
        "--force",
        action="store_true",
        help="rotate generated fields even when they already contain a value",
    )
    args = parser.parse_args()

    template = Path(args.template)
    env_path = Path(args.env)
    hashes_path = Path(args.hashes)

    if not template.is_file():
        parser.error(f"template not found: {template}")

    source = env_path if env_path.is_file() else template
    lines = source.read_text(encoding="utf-8").splitlines(keepends=True)
    current = parse_env(lines)

    replacements: dict[str, str] = {}
    for key, factory in GENERATORS.items():
        if key not in current:
            raise SystemExit(f"required key {key!r} is missing from {source}")
        if args.force or not current.get(key):
            replacements[key] = factory()

    if replacements:
        atomic_write(env_path, render_env(lines, replacements))
    elif env_path.is_file():
        os.chmod(env_path, 0o600)
    else:
        atomic_write(env_path, "".join(lines))

    final_lines = env_path.read_text(encoding="utf-8").splitlines(keepends=True)
    final_values = parse_env(final_lines)
    digest_lines = [
        "# SHA-256 fingerprints only. Do not use these values as login passwords.\n",
        "# Generated from the local .env; this file must not be committed.\n",
    ]
    for key in GENERATORS:
        value = final_values.get(key, "")
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""
        digest_lines.append(f"{key}_SHA256={digest}\n")
    atomic_write(hashes_path, "".join(digest_lines))

    action = "rotated" if args.force else "generated"
    fields = ", ".join(replacements) if replacements else "none (existing values preserved)"
    print(f"Inventory environment {action}: {env_path}")
    print(f"Updated fields: {fields}")
    print(f"SHA-256 fingerprints: {hashes_path}")
    print("Secrets were not printed. Both files should remain outside Git.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
