"""Credential storage for AiDot CLI tools.

Priority order:
  1. Environment variables: AIDOT_USERNAME, AIDOT_PASSWORD, AIDOT_COUNTRY
     Works in Docker containers, Home Assistant addons, CI systems.
  2. Fernet-encrypted file pair at ~/.config/aidot/:
       credentials.enc  — ciphertext (0600)
       .key             — random symmetric key (0600)
     Cross-platform, no OS-specific APIs required.
  3. Plain JSON file at ~/.config/aidot/credentials.json (0600)
     Legacy fallback; auto-migrated to encrypted on first load.
"""

import json
import os
import stat
from typing import Optional

_CONFIG_DIR = os.path.expanduser("~/.config/aidot")
_DEFAULT_CREDS_FILE = os.path.join(_CONFIG_DIR, "credentials.json")
_ENC_FILE = os.path.join(_CONFIG_DIR, "credentials.enc")
_KEY_FILE = os.path.join(_CONFIG_DIR, ".key")


# ── Public API ───────────────────────────────────────────────────────────────

def load_credentials(creds_path: Optional[str] = None) -> dict:
    """Return {"username": ..., "password": ..., "country": ...}.

    Checks environment variables first, then encrypted file, then plain JSON.
    Raises FileNotFoundError / ValueError if nothing is found.
    """
    # Priority 1: environment variables
    env_user = os.environ.get("AIDOT_USERNAME")
    env_pass = os.environ.get("AIDOT_PASSWORD")
    if env_user and env_pass:
        return {
            "username": env_user,
            "password": env_pass,
            "country":  os.environ.get("AIDOT_COUNTRY", "US"),
        }

    # Priority 2: Fernet-encrypted file
    enc = creds_path and creds_path + ".enc"
    key = creds_path and creds_path + ".key"
    enc_path = enc or _ENC_FILE
    key_path = key or _KEY_FILE
    if os.path.exists(enc_path) and os.path.exists(key_path):
        try:
            return _load_encrypted(enc_path, key_path)
        except Exception as exc:
            raise ValueError(f"Failed to decrypt {enc_path}: {exc}") from exc

    # Priority 3: plain JSON (legacy)
    plain = creds_path or _DEFAULT_CREDS_FILE
    if os.path.exists(plain):
        data = _load_plain(plain)
        # Auto-migrate to encrypted storage
        try:
            _save_encrypted(data["username"], data["password"],
                            data.get("country", "US"), enc_path, key_path)
            os.unlink(plain)
        except Exception:
            pass
        return data

    raise FileNotFoundError(
        "No credentials found. Options:\n"
        "  • Set AIDOT_USERNAME / AIDOT_PASSWORD / AIDOT_COUNTRY env vars\n"
        "  • Run with --save-credentials to store them encrypted\n"
        f"  • Place credentials.json in {_CONFIG_DIR}"
    )


def save_credentials(
    username: str,
    password: str,
    country: str = "US",
    creds_path: Optional[str] = None,
) -> str:
    """Encrypt and store credentials. Returns the path where they were saved."""
    enc_path = (creds_path + ".enc") if creds_path else _ENC_FILE
    key_path = (creds_path + ".key") if creds_path else _KEY_FILE
    _save_encrypted(username, password, country, enc_path, key_path)
    return enc_path


def delete_credentials(creds_path: Optional[str] = None) -> None:
    """Remove stored credentials (encrypted and/or plain JSON)."""
    for path in (
        (creds_path + ".enc") if creds_path else _ENC_FILE,
        (creds_path + ".key") if creds_path else _KEY_FILE,
        creds_path or _DEFAULT_CREDS_FILE,
    ):
        if path and os.path.exists(path):
            try:
                os.unlink(path)
            except Exception:
                pass


# ── Internal helpers ─────────────────────────────────────────────────────────

def _fernet():
    try:
        from cryptography.fernet import Fernet
        return Fernet
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required for encrypted credentials. "
            "Install it with: pip install cryptography"
        ) from exc


def _load_encrypted(enc_path: str, key_path: str) -> dict:
    Fernet = _fernet()
    with open(key_path, "rb") as f:
        key = f.read().strip()
    with open(enc_path, "rb") as f:
        token = f.read().strip()
    plaintext = Fernet(key).decrypt(token)
    data = json.loads(plaintext)
    for field in ("username", "password"):
        if field not in data:
            raise ValueError(f"Encrypted credentials missing field {field!r}")
    return data


def _save_encrypted(
    username: str, password: str, country: str,
    enc_path: str, key_path: str,
) -> None:
    Fernet = _fernet()
    os.makedirs(os.path.dirname(os.path.abspath(enc_path)), exist_ok=True)

    # Generate or reuse key
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            key = f.read().strip()
    else:
        key = Fernet.generate_key()
        _write_secret(key_path, key)

    payload = json.dumps({"username": username, "password": password,
                          "country": country}).encode()
    token = Fernet(key).encrypt(payload)
    _write_secret(enc_path, token)


def _load_plain(path: str) -> dict:
    with open(path) as f:
        data = json.load(f)
    for field in ("username", "password"):
        if field not in data:
            raise ValueError(f"Credentials file {path!r} missing {field!r}")
    return data


def _write_secret(path: str, data: bytes) -> None:
    """Write binary data to path with 0600 permissions."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
        f.write(b"\n")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
