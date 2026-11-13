# -*- coding: utf-8 -*-
"""Crypto helpers: password hashing, Fernet credential vault, tokens, SSRF guard."""
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("FAMGATE_DATA_DIR", os.path.join(BASE_DIR, "data"))
KEY_PATH = os.path.join(DATA_DIR, "vault.key")

_PBKDF2_ITER = 210_000


# ---------------- password hashing (pbkdf2_hmac, stdlib) ----------------

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ITER)
    return f"pbkdf2_sha256${_PBKDF2_ITER}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt, hexhash = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), hexhash)
    except Exception:
        return False


def hash_otp(otp: str) -> str:
    return hashlib.sha256(("famgate-otp-v1:" + otp).encode()).hexdigest()


# ---------------- credential vault (Fernet — AES-128-CBC + HMAC-SHA256) ----------------

_fernet = None


def _fernet_from_any_secret(secret: str):
    """Accept either (a) a real Fernet key (44-char url-safe b64, decodes to 32 bytes)
    or (b) any other secret string, from which a Fernet key is derived deterministically
    via SHA-256. (b) exists so a bad key in .env breaks nothing at runtime; deployments
    that already encrypt with a valid Fernet key are unaffected."""
    from cryptography.fernet import Fernet
    import base64
    try:
        return Fernet(secret.encode()), False
    except Exception:
        derived = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
        return Fernet(derived), True


def _get_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet
    from cryptography.fernet import Fernet

    env_key = os.environ.get("FAMGATE_VAULT_KEY", "").strip()
    if env_key:
        f, derived = _fernet_from_any_secret(env_key)
        if derived:
            import sys
            print("[famgate] WARNING: FAMGATE_VAULT_KEY is not a valid Fernet key; "
                  "deriving one via SHA-256. Fine for existing installs, but prefer a real Fernet key "
                  "(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())') "
                  "and re-encrypt stored secrets if you create one.", file=sys.stderr, flush=True)
        _fernet = f
        return _fernet
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(KEY_PATH):
        key = Fernet.generate_key()
        fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    else:
        with open(KEY_PATH, "rb") as f:
            key = f.read().strip()
    _fernet = Fernet(key)
    return _fernet


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str:
    if not token:
        return ""
    try:
        return _get_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception:
        return ""


# ---------------- misc tokens ----------------

def new_session_token() -> str:
    return secrets.token_urlsafe(48)


def new_api_key() -> str:
    return "fp_live_" + secrets.token_hex(24)


def new_api_secret() -> str:
    return "fp_sec_" + secrets.token_hex(28)


def new_webhook_secret() -> str:
    return "whsec_" + secrets.token_hex(28)


def new_order_id() -> str:
    return "ord_" + secrets.token_hex(11)


def hmac_sha256_hex(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


# ---------------- SSRF guard for merchant webhook URLs ----------------

_BLOCKED_HOSTNAMES = {
    "localhost", "ip6-localhost", "ip6-loopback", "broadcasthost", "metadata",
    "metadata.google.internal", "instance-data",
}
_BLOCKED_SUFFIXES = (".internal", ".local", ".lan", ".home", ".corp", ".localdomain")


def webhook_url_allowed(url: str) -> tuple:
    """Returns (ok: bool, reason: str). Blocks non-http(s), loopback, private & link-local ranges,
    unless FAMGATE_WEBHOOK_ALLOW_PRIVATE=1 (self-hosted dev opt-in for testing against LAN endpoints)."""
    allow_private = os.environ.get("FAMGATE_WEBHOOK_ALLOW_PRIVATE", "0").strip().lower() in ("1", "true", "yes")
    try:
        p = urlparse(url.strip())
    except Exception:
        return False, "Invalid URL"
    if p.scheme not in ("http", "https"):
        return False, "Only http:// and https:// URLs are allowed"
    if not p.hostname:
        return False, "URL has no host"
    host = p.hostname.strip().lower().rstrip(".")
    if allow_private:
        if p.username or p.password:
            return False, "URLs with embedded credentials are not allowed"
        return True, "ok"
    if host in _BLOCKED_HOSTNAMES or any(host.endswith(s) for s in _BLOCKED_SUFFIXES):
        return False, "This hostname is not allowed"
    try:
        ip = ipaddress.ip_address(host)
        ips = [ip]
    except ValueError:
        # Not a literal IP. Cheap static check only; DNS is intentionally not resolved here.
        ips = []
    for ip in ips:
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        ):
            return False, "Private, loopback or reserved IP addresses are not allowed"
    # literal quad with hex/octal tricks is rejected by ipaddress already; block raw user:pass@
    if p.username or p.password:
        return False, "URLs with embedded credentials are not allowed"
    return True, "ok"


def clean_utr(raw: str) -> str:
    return re.sub(r"[^0-9A-Za-z]", "", str(raw or "")).strip()
