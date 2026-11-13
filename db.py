# -*- coding: utf-8 -*-
"""
FamGate — SQLite data layer.
All queries are parameterised. WAL mode, foreign keys enforced.
"""
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("FAMGATE_DATA_DIR", os.path.join(BASE_DIR, "data"))
DB_PATH = os.environ.get("FAMGATE_DB", os.path.join(DATA_DIR, "famgate.db"))
os.makedirs(DATA_DIR, exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS merchants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  business_name TEXT NOT NULL,
  email_verified INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS email_otps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  otp_hash TEXT NOT NULL,
  purpose TEXT NOT NULL DEFAULT 'signup',
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  merchant_id INTEGER NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS merchant_settings (
  merchant_id INTEGER PRIMARY KEY REFERENCES merchants(id) ON DELETE CASCADE,
  -- FamPay (Gmail IMAP verification of payment confirmation emails)
  fampay_enabled INTEGER NOT NULL DEFAULT 0,
  fampay_email TEXT NOT NULL DEFAULT '',
  fampay_app_password_enc TEXT NOT NULL DEFAULT '',
  fampay_upi TEXT NOT NULL DEFAULT '',
  imap_host TEXT NOT NULL DEFAULT 'imap.gmail.com',
  imap_port INTEGER NOT NULL DEFAULT 993,
  imap_folder TEXT NOT NULL DEFAULT 'INBOX',
  -- BharatPe (enterprise dashboard API: merchant ID + token)
  bharatpe_enabled INTEGER NOT NULL DEFAULT 0,
  bharatpe_mid TEXT NOT NULL DEFAULT '',
  bharatpe_token_enc TEXT NOT NULL DEFAULT '',
  bharatpe_vpa TEXT NOT NULL DEFAULT '',
  -- general
  display_name TEXT NOT NULL DEFAULT '',
  decimal_offset INTEGER NOT NULL DEFAULT 1,
  default_provider TEXT NOT NULL DEFAULT 'fampay',
  updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  merchant_id INTEGER NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
  label TEXT NOT NULL DEFAULT 'Default key',
  api_key TEXT UNIQUE NOT NULL,
  secret_enc TEXT NOT NULL,
  secret_preview TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL DEFAULT 0,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  merchant_id INTEGER NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
  provider TEXT NOT NULL DEFAULT 'fampay',
  client_ref TEXT NOT NULL DEFAULT '',
  base_amount REAL NOT NULL,
  exact_amount REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'INR',
  status TEXT NOT NULL DEFAULT 'PENDING',
  note TEXT NOT NULL DEFAULT '',
  customer_name TEXT NOT NULL DEFAULT '',
  customer_email TEXT NOT NULL DEFAULT '',
  upi_uri TEXT NOT NULL DEFAULT '',
  utr TEXT NOT NULL DEFAULT '',
  payer_name TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'api',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  paid_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_orders_merchant ON orders(merchant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_orders_match ON orders(status, exact_amount, created_at);
CREATE TABLE IF NOT EXISTS provider_credentials (
  merchant_id INTEGER NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  config_enc TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (merchant_id, provider)
);
CREATE TABLE IF NOT EXISTS used_utrs (
  utr TEXT PRIMARY KEY,
  order_id TEXT,
  merchant_id INTEGER,
  amount REAL,
  payer_name TEXT NOT NULL DEFAULT '',
  claimed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS webhook_settings (
  merchant_id INTEGER PRIMARY KEY REFERENCES merchants(id) ON DELETE CASCADE,
  url TEXT NOT NULL DEFAULT '',
  secret_enc TEXT NOT NULL DEFAULT '',
  secret_preview TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  merchant_id INTEGER NOT NULL,
  order_id TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL DEFAULT '',
  event TEXT NOT NULL DEFAULT 'payment.verified',
  status_code INTEGER NOT NULL DEFAULT 0,
  success INTEGER NOT NULL DEFAULT 0,
  response_snippet TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliveries ON webhook_deliveries(merchant_id, id DESC);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        # --- lightweight migrations for existing installs ---
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(orders)").fetchall()}
        if "provider_ref" not in cols:
            conn.execute("ALTER TABLE orders ADD COLUMN provider_ref TEXT NOT NULL DEFAULT ''")
        if "provider_token" not in cols:
            conn.execute("ALTER TABLE orders ADD COLUMN provider_token TEXT NOT NULL DEFAULT ''")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_orders_provider_ref ON orders(provider, provider_ref)")
        mcols = {r["name"] for r in conn.execute("PRAGMA table_info(merchants)").fetchall()}
        if "banned_at" not in mcols:
            conn.execute("ALTER TABLE merchants ADD COLUMN banned_at INTEGER NOT NULL DEFAULT 0")
        if "ban_reason" not in mcols:
            conn.execute("ALTER TABLE merchants ADD COLUMN ban_reason TEXT NOT NULL DEFAULT ''")


def _now() -> int:
    return int(time.time())


# ---------------- merchants & auth ----------------

def create_merchant(email: str, password_hash: str, business_name: str) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO merchants (email, password_hash, business_name, email_verified, created_at) VALUES (?,?,?,0,?)",
            (email.lower().strip(), password_hash, business_name.strip(), _now()),
        )
        mid = int(cur.lastrowid)
        conn.execute(
            "INSERT OR IGNORE INTO merchant_settings (merchant_id, display_name, updated_at) VALUES (?,?,?)",
            (mid, business_name.strip(), _now()),
        )
        conn.execute(
            "INSERT OR IGNORE INTO webhook_settings (merchant_id, updated_at) VALUES (?,?)",
            (mid, _now()),
        )
        return mid


def get_merchant_by_email(email: str) -> Optional[sqlite3.Row]:
    with connect() as conn:
        return conn.execute("SELECT * FROM merchants WHERE email=?", (email.lower().strip(),)).fetchone()


def get_merchant_by_id(mid: int) -> Optional[sqlite3.Row]:
    with connect() as conn:
        return conn.execute("SELECT * FROM merchants WHERE id=?", (mid,)).fetchone()


def set_merchant_verified(mid: int) -> None:
    with connect() as conn:
        conn.execute("UPDATE merchants SET email_verified=1 WHERE id=?", (mid,))


def create_session(token: str, merchant_id: int, ttl_seconds: int = 30 * 24 * 3600) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sessions (token, merchant_id, expires_at, created_at) VALUES (?,?,?,?)",
            (token, merchant_id, _now() + ttl_seconds, _now()),
        )


def get_session_merchant(token: str) -> Optional[sqlite3.Row]:
    if not token:
        return None
    with connect() as conn:
        row = conn.execute(
            "SELECT m.* FROM sessions s JOIN merchants m ON m.id = s.merchant_id WHERE s.token=? AND s.expires_at > ? AND m.banned_at = 0",
            (token, _now()),
        ).fetchone()
        return row


def delete_session(token: str) -> None:
    if not token:
        return
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))


# ---------------- OTPs ----------------

def create_otp(email: str, otp_hash: str, purpose: str, ttl_seconds: int = 15 * 60) -> None:
    with connect() as conn:
        conn.execute("UPDATE email_otps SET consumed=1 WHERE email=? AND purpose=? AND consumed=0", (email, purpose))
        conn.execute(
            "INSERT INTO email_otps (email, otp_hash, purpose, expires_at, consumed, created_at) VALUES (?,?,?,?,0,?)",
            (email.lower().strip(), otp_hash, purpose, _now() + ttl_seconds, _now()),
        )


def consume_otp(email: str, otp_hash: str, purpose: str) -> bool:
    with connect() as conn:
        row = conn.execute(
            "SELECT id FROM email_otps WHERE email=? AND purpose=? AND consumed=0 AND expires_at>? ORDER BY id DESC LIMIT 1",
            (email.lower().strip(), purpose, _now()),
        ).fetchone()
        if not row:
            return False
        # compare hash of the latest live OTP
        live = conn.execute("SELECT otp_hash FROM email_otps WHERE id=?", (row["id"],)).fetchone()
        if live and live["otp_hash"] == otp_hash:
            conn.execute("UPDATE email_otps SET consumed=1 WHERE id=?", (row["id"],))
            return True
        return False


# ---------------- settings / providers ----------------

def get_settings(mid: int) -> sqlite3.Row:
    with connect() as conn:
        row = conn.execute("SELECT * FROM merchant_settings WHERE merchant_id=?", (mid,)).fetchone()
        if not row:
            conn.execute("INSERT OR IGNORE INTO merchant_settings (merchant_id, updated_at) VALUES (?,?)", (mid, _now()))
            row = conn.execute("SELECT * FROM merchant_settings WHERE merchant_id=?", (mid,)).fetchone()
        return row


def save_settings(mid: int, fields: Dict[str, Any]) -> None:
    if not fields:
        return
    allowed = {
        "fampay_enabled", "fampay_email", "fampay_app_password_enc", "fampay_upi",
        "imap_host", "imap_port", "imap_folder",
        "bharatpe_enabled", "bharatpe_mid", "bharatpe_token_enc", "bharatpe_vpa",
        "display_name", "decimal_offset", "default_provider",
    }
    sets = [f"{k}=?" for k in fields if k in allowed]
    vals = [fields[k] for k in fields if k in allowed]
    if not sets:
        return
    sets.append("updated_at=?")
    vals.append(_now())
    vals.append(mid)
    with connect() as conn:
        conn.execute(f"UPDATE merchant_settings SET {', '.join(sets)} WHERE merchant_id=?", vals)


def all_provider_settings() -> List[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM merchant_settings WHERE fampay_enabled=1 OR bharatpe_enabled=1"
        ).fetchall()


# ---------------- API keys ----------------

def create_api_key(mid: int, label: str, api_key: str, secret_enc: str, secret_preview: str) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO api_keys (merchant_id, label, api_key, secret_enc, secret_preview, created_at) VALUES (?,?,?,?,?,?)",
            (mid, label.strip()[:80] or "Default key", api_key, secret_enc, secret_preview, _now()),
        )
        return int(cur.lastrowid)


def list_api_keys(mid: int) -> List[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT id, label, api_key, secret_enc, secret_preview, created_at, last_used_at, revoked FROM api_keys WHERE merchant_id=? ORDER BY id DESC",
            (mid,),
        ).fetchall()


def get_api_key(key: str) -> Optional[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT k.*, m.business_name, m.email FROM api_keys k JOIN merchants m ON m.id = k.merchant_id WHERE k.api_key=? AND k.revoked=0",
            (key,),
        ).fetchone()


def touch_api_key(key_id: int) -> None:
    now = _now()
    with connect() as conn:
        row = conn.execute("SELECT last_used_at FROM api_keys WHERE id=?", (key_id,)).fetchone()
        if row and now - int(row["last_used_at"] or 0) >= 60:
            conn.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (now, key_id))


def revoke_api_key(mid: int, key_id: int) -> bool:
    with connect() as conn:
        cur = conn.execute("UPDATE api_keys SET revoked=1 WHERE id=? AND merchant_id=?", (key_id, mid))
        return cur.rowcount > 0


# ---------------- orders ----------------

def create_order(o: Dict[str, Any]) -> None:
    with connect() as conn:
        conn.execute(
            """INSERT INTO orders (id, merchant_id, provider, client_ref, base_amount, exact_amount, currency,
               status, note, customer_name, customer_email, upi_uri, source, created_at, expires_at, provider_ref, provider_token)
               VALUES (?,?,?,?,?,?,?,'PENDING',?,?,?,?,?,?,?,?,?)""",
            (
                o["id"], o["merchant_id"], o["provider"], o.get("client_ref", ""),
                float(o["base_amount"]), float(o["exact_amount"]), o.get("currency", "INR"),
                o.get("note", "")[:200], o.get("customer_name", "")[:120],
                o.get("customer_email", "")[:160], o.get("upi_uri", "")[:600],
                o.get("source", "api"), int(o["created_at"]), int(o["expires_at"]),
                o.get("provider_ref", "")[:120], o.get("provider_token", "")[:4000],
            ),
        )


def update_order_provider_ref(order_id: str, provider_ref: str, provider_token: str = "") -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE orders SET provider_ref=?, provider_token=? WHERE id=?",
            (provider_ref[:120], provider_token[:4000], order_id),
        )


def get_order_by_provider_ref(provider: str, provider_ref: str) -> Optional[sqlite3.Row]:
    if not provider_ref:
        return None
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM orders WHERE provider=? AND provider_ref=? ORDER BY created_at DESC LIMIT 1",
            (provider, provider_ref),
        ).fetchone()


def get_order(order_id: str) -> Optional[sqlite3.Row]:
    with connect() as conn:
        return conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()


def get_order_by_merchant(order_id: str, mid: int) -> Optional[sqlite3.Row]:
    with connect() as conn:
        return conn.execute("SELECT * FROM orders WHERE id=? AND merchant_id=?", (order_id, mid)).fetchone()


def get_order_by_client_ref(mid: int, client_ref: str) -> Optional[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM orders WHERE merchant_id=? AND client_ref=? ORDER BY created_at DESC LIMIT 1",
            (mid, client_ref),
        ).fetchone()


def list_orders(mid: int, status: Optional[str] = None, limit: int = 100, offset: int = 0) -> List[sqlite3.Row]:
    with connect() as conn:
        if status:
            return conn.execute(
                "SELECT * FROM orders WHERE merchant_id=? AND status=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (mid, status.upper(), limit, offset),
            ).fetchall()
        return conn.execute(
            "SELECT * FROM orders WHERE merchant_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (mid, limit, offset),
        ).fetchall()


def count_orders_by_status(mid: int) -> Dict[str, int]:
    with connect() as conn:
        rows = conn.execute("SELECT status, COUNT(*) c FROM orders WHERE merchant_id=? GROUP BY status", (mid,)).fetchall()
        return {r["status"]: int(r["c"]) for r in rows}


def stats_today(mid: int) -> Dict[str, Any]:
    ist = _now() + 19800  # shift to IST (UTC+5:30)
    day_start = (ist - (ist % 86400)) - 19800  # IST midnight expressed as UTC epoch
    with connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) c, COALESCE(SUM(exact_amount),0) s FROM orders WHERE merchant_id=? AND status='PAID' AND paid_at>=?",
            (mid, day_start),
        ).fetchone()
        pending = conn.execute(
            "SELECT COUNT(*) c FROM orders WHERE merchant_id=? AND status='PENDING'", (mid,)
        ).fetchone()
        return {"paid_today_count": int(row["c"]), "paid_today_sum": float(row["s"]), "pending": int(pending["c"])}


def active_exact_amounts(mid: int) -> set:
    now = _now()
    with connect() as conn:
        rows = conn.execute(
            "SELECT exact_amount FROM orders WHERE merchant_id=? AND status IN ('PENDING','CANCELLED') AND expires_at>?",
            (mid, now),
        ).fetchall()
        return {round(float(r["exact_amount"]), 2) for r in rows}


def find_pending_match(mid: int, amount: float, since_ts: int) -> Optional[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            """SELECT * FROM orders WHERE merchant_id=? AND status='PENDING' AND ABS(exact_amount-?)<0.005 AND created_at>=?
               ORDER BY created_at ASC LIMIT 1""",
            (mid, amount, since_ts),
        ).fetchone()


def mark_order_paid(order_id: str, utr: str, payer_name: str = "") -> bool:
    with connect() as conn:
        cur = conn.execute(
            "UPDATE orders SET status='PAID', utr=?, payer_name=?, paid_at=? WHERE id=? AND status='PENDING'",
            (utr, payer_name[:120], _now(), order_id),
        )
        return cur.rowcount > 0


def expire_old_orders() -> int:
    with connect() as conn:
        cur = conn.execute(
            "UPDATE orders SET status='EXPIRED' WHERE status='PENDING' AND expires_at < ?", (_now(),)
        )
        return cur.rowcount


# ---------------- UTR dedup (global anti-replay) ----------------

def is_utr_used(utr: str) -> bool:
    if not utr:
        return False
    with connect() as conn:
        return conn.execute("SELECT 1 FROM used_utrs WHERE utr=?", (utr,)).fetchone() is not None


def mark_utr_used(utr: str, order_id: str, merchant_id: int, amount: float, payer_name: str = "") -> None:
    if not utr:
        return
    with connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO used_utrs (utr, order_id, merchant_id, amount, payer_name, claimed_at) VALUES (?,?,?,?,?,?)",
            (utr, order_id, merchant_id, float(amount), payer_name[:120], _now()),
        )


# ---------------- provider credentials (official gateways) ----------------

def get_provider_credentials(mid: int) -> Dict[str, Dict[str, Any]]:
    """Returns {provider: {enabled: bool, config: dict, updated_at: int}} for all rows of this merchant."""
    import security
    import json as _json

    with connect() as conn:
        rows = conn.execute("SELECT * FROM provider_credentials WHERE merchant_id=?", (mid,)).fetchall()
    out: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        cfg: Dict[str, Any] = {}
        try:
            raw = security.decrypt_secret(r["config_enc"]) if r["config_enc"] else ""
            cfg = _json.loads(raw) if raw else {}
        except Exception:
            cfg = {}
        out[r["provider"]] = {"enabled": bool(r["enabled"]), "config": cfg, "updated_at": int(r["updated_at"] or 0)}
    return out


def save_provider_credentials(mid: int, provider: str, enabled: bool, config: Dict[str, Any]) -> None:
    import security
    import json as _json

    blob = security.encrypt_secret(_json.dumps(config, separators=(",", ":")))
    with connect() as conn:
        conn.execute(
            """INSERT INTO provider_credentials (merchant_id, provider, enabled, config_enc, updated_at)
               VALUES (?,?,?,?,?)
               ON CONFLICT(merchant_id, provider) DO UPDATE SET enabled=excluded.enabled, config_enc=excluded.config_enc, updated_at=excluded.updated_at""",
            (mid, provider, 1 if enabled else 0, blob, _now()),
        )


# ---------------- webhooks ----------------

def get_webhook(mid: int) -> sqlite3.Row:
    with connect() as conn:
        row = conn.execute("SELECT * FROM webhook_settings WHERE merchant_id=?", (mid,)).fetchone()
        if not row:
            conn.execute("INSERT OR IGNORE INTO webhook_settings (merchant_id, updated_at) VALUES (?,?)", (mid, _now()))
            row = conn.execute("SELECT * FROM webhook_settings WHERE merchant_id=?", (mid,)).fetchone()
        return row


def save_webhook(mid: int, url: str, secret_enc: Optional[str] = None, secret_preview: Optional[str] = None) -> None:
    with connect() as conn:
        if secret_enc is not None:
            conn.execute(
                "UPDATE webhook_settings SET url=?, secret_enc=?, secret_preview=?, updated_at=? WHERE merchant_id=?",
                (url.strip(), secret_enc, secret_preview or "", _now(), mid),
            )
        else:
            conn.execute("UPDATE webhook_settings SET url=?, updated_at=? WHERE merchant_id=?", (url.strip(), _now(), mid))


def log_webhook_delivery(mid: int, order_id: str, url: str, event: str, status_code: int, success: bool, snippet: str) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO webhook_deliveries (merchant_id, order_id, url, event, status_code, success, response_snippet, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (mid, order_id, url[:400], event, int(status_code), 1 if success else 0, (snippet or "")[:300], _now()),
        )


def list_webhook_deliveries(mid: int, limit: int = 25) -> List[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM webhook_deliveries WHERE merchant_id=? ORDER BY id DESC LIMIT ?", (mid, limit)
        ).fetchall()


# ---------------- admin console ----------------

def set_merchant_banned(mid: int, banned: bool, reason: str = "") -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE merchants SET banned_at=?, ban_reason=? WHERE id=?",
            (_now() if banned else 0, reason.strip()[:280] if banned else "", mid),
        )
        if banned:
            conn.execute("DELETE FROM sessions WHERE merchant_id=?", (mid,))


def admin_stats() -> Dict[str, Any]:
    with connect() as conn:
        def one(q):
            return conn.execute(q).fetchone()[0]
        return {
            "merchants": one("SELECT COUNT(*) FROM merchants"),
            "verified": one("SELECT COUNT(*) FROM merchants WHERE email_verified=1"),
            "banned": one("SELECT COUNT(*) FROM merchants WHERE banned_at>0"),
            "orders": one("SELECT COUNT(*) FROM orders"),
            "paid": one("SELECT COUNT(*) FROM orders WHERE status='PAID'"),
            "pending": one("SELECT COUNT(*) FROM orders WHERE status='PENDING'"),
            "gmv": one("SELECT COALESCE(SUM(exact_amount),0) FROM orders WHERE status='PAID'"),
            "keys_active": one("SELECT COUNT(*) FROM api_keys WHERE revoked=0"),
            "deliveries": one("SELECT COUNT(*) FROM webhook_deliveries"),
        }


def admin_list_users(search: str = "", limit: int = 30, offset: int = 0):
    q = (search or "").strip().lower()
    like = f"%{q}%"
    sel = ("SELECT m.id, m.email, m.business_name, m.email_verified, m.created_at, m.banned_at, m.ban_reason, "
           "(SELECT COUNT(*) FROM orders o WHERE o.merchant_id=m.id) AS orders, "
           "(SELECT COALESCE(SUM(exact_amount),0) FROM orders o WHERE o.merchant_id=m.id AND o.status='PAID') AS gmv "
           "FROM merchants m")
    with connect() as conn:
        if q:
            where = " WHERE lower(m.email) LIKE ? OR lower(m.business_name) LIKE ?"
            rows = conn.execute(sel + where + " ORDER BY m.created_at DESC LIMIT ? OFFSET ?", (like, like, limit, offset)).fetchall()
            total = conn.execute("SELECT COUNT(*) FROM merchants m" + where, (like, like)).fetchone()[0]
        else:
            rows = conn.execute(sel + " ORDER BY m.created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
            total = conn.execute("SELECT COUNT(*) FROM merchants").fetchone()[0]
        return rows, total


def admin_user_detail(mid: int):
    with connect() as conn:
        m = conn.execute("SELECT * FROM merchants WHERE id=?", (mid,)).fetchone()
        if not m:
            return None
        orders = conn.execute(
            "SELECT id, provider, exact_amount, status, created_at, utr FROM orders WHERE merchant_id=? ORDER BY created_at DESC LIMIT 15",
            (mid,),
        ).fetchall()
        keys = conn.execute(
            "SELECT label, secret_preview, revoked, created_at, last_used_at FROM api_keys WHERE merchant_id=? ORDER BY created_at DESC",
            (mid,),
        ).fetchall()
        paid = conn.execute("SELECT COUNT(*), COALESCE(SUM(exact_amount),0) FROM orders WHERE merchant_id=? AND status='PAID'", (mid,)).fetchone()
        total = conn.execute("SELECT COUNT(*) FROM orders WHERE merchant_id=?", (mid,)).fetchone()[0]
        return {"merchant": m, "orders": orders, "keys": keys, "paid_n": paid[0], "gmv": paid[1], "orders_n": total}


def admin_list_orders(status: str = "", provider: str = "", search: str = "", limit: int = 40, offset: int = 0):
    where, args = [], []
    if status:
        where.append("o.status=?"); args.append(status.upper())
    if provider:
        where.append("o.provider=?"); args.append(provider.lower())
    if search:
        s = search.strip().lower(); like = f"%{s}%"
        where.append("(lower(o.id) LIKE ? OR lower(m.email) LIKE ? OR lower(o.client_ref) LIKE ? OR lower(o.utr) LIKE ? OR lower(o.customer_email) LIKE ?)")
        args.extend([like, like, like, like, like])
    w = (" WHERE " + " AND ".join(where)) if where else ""
    with connect() as conn:
        rows = conn.execute(
            "SELECT o.id, o.provider, o.base_amount, o.exact_amount, o.status, o.created_at, o.paid_at, o.utr, o.client_ref, m.email AS merchant_email "
            "FROM orders o JOIN merchants m ON m.id=o.merchant_id" + w + " ORDER BY o.created_at DESC LIMIT ? OFFSET ?",
            (*args, limit, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM orders o JOIN merchants m ON m.id=o.merchant_id" + w, args).fetchone()[0]
        return rows, total


def admin_order_status_counts() -> Dict[str, int]:
    with connect() as conn:
        return {r["status"]: r["n"] for r in conn.execute("SELECT status, COUNT(*) AS n FROM orders GROUP BY status")}


def admin_recent_orders(limit: int = 8):
    with connect() as conn:
        return conn.execute(
            "SELECT o.id, o.exact_amount, o.status, o.provider, o.created_at, m.email AS merchant_email "
            "FROM orders o JOIN merchants m ON m.id=o.merchant_id ORDER BY o.created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()


def admin_recent_users(limit: int = 6):
    with connect() as conn:
        return conn.execute("SELECT id, email, business_name, created_at, email_verified, banned_at FROM merchants ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
