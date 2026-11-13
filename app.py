# -*- coding: utf-8 -*-
"""FamGate — FamPay & BharatPe payment gateway (FastAPI)."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Optional
from urllib.parse import quote

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.templating import Jinja2Templates

import db
import mailer
import security
import upi
import verifiers
import providers as pg

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_NAME = "FamGate"

db.init_db()
verifiers.start()

app = FastAPI(title="FamGate — FamPay & BharatPe Payment Gateway", version="1.0.0", docs_url=None, redoc_url=None)
app.add_middleware(GZipMiddleware, minimum_size=800)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

# Cache-busting asset version: content hash of the styles. Referenced as
# ?v=... in templates so stale browser/CDN caches can never serve old CSS.
_asset_hasher = hashlib.sha256()
for _f in ("style.css", "favicon.svg"):
    try:
        with open(os.path.join(BASE_DIR, "static", _f), "rb") as fh:
            _asset_hasher.update(fh.read())
    except OSError:
        pass
ASSET_V = _asset_hasher.hexdigest()[:12]

templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
templates.env.filters["dt"] = lambda ts: time.strftime("%d %b %H:%M", time.localtime(int(ts or 0)))
templates.env.globals["provider_title"] = pg.title_of


# ---------------------------------------------------------------- helpers

def _admin_emails() -> set:
    return {e.strip().lower() for e in os.environ.get("FAMGATE_ADMIN_EMAILS", "").split(",") if e.strip()}


def is_admin_merchant(m) -> bool:
    return bool(m) and (m["email"] or "").lower() in _admin_emails()


def render(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
    if "manual_csrf" in globals():
        ctx.setdefault("manual_csrf", manual_csrf(request))
    ctx.setdefault("request", request)
    ctx.setdefault("app_name", APP_NAME)
    ctx.setdefault("merchant", None)
    ctx.setdefault("is_admin", is_admin_merchant(ctx.get("merchant")))
    ctx.setdefault("ok", request.query_params.get("ok", ""))
    ctx.setdefault("err", request.query_params.get("err", ""))
    ctx.setdefault("smtp_live", mailer.smtp_configured())
    ctx.setdefault("asset_v", ASSET_V)
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def flash_redirect(url: str, ok: str = "", err: str = "") -> RedirectResponse:
    from urllib.parse import urlencode

    q = urlencode({k: v for k, v in (("ok", ok), ("err", err)) if v})
    sep = "&" if "?" in url else "?"
    return RedirectResponse(url + (sep + q if q else ""), status_code=303)


def current_merchant(request: Request):
    token = request.cookies.get("famgate_session", "")
    try:
        return db.get_session_merchant(token)
    except Exception as exc:  # DB locked/corrupt/unreachable must not take down the whole page
        import sys
        print(f"[famgate] session lookup failed: {exc!r}", file=sys.stderr, flush=True)
        return None


def require_merchant(request: Request):
    m = current_merchant(request)
    return m


_rate_buckets: dict = {}
_rate_lock = threading.Lock()

# One-time server-side flash for freshly minted secrets (never in URLs / logs / history)
_flash_lock = threading.Lock()
_flash_store: dict = {}


def flash_set(request: Request, **payload) -> None:
    token = request.cookies.get("famgate_session", "")
    if not token:
        return
    with _flash_lock:
        # cheap GC of stale entries
        cutoff = time.time() - 300
        for k in [k for k, v in _flash_store.items() if v.get("_at", 0) < cutoff]:
            _flash_store.pop(k, None)
        _flash_store[token] = {"_at": time.time(), **payload}


def flash_pop(request: Request) -> dict:
    token = request.cookies.get("famgate_session", "")
    if not token:
        return {}
    with _flash_lock:
        d = _flash_store.pop(token, None)
    if not d or time.time() - d.get("_at", 0) > 120:
        return {}
    return d


def rate_ok(key: str, limit: int, window: int) -> bool:
    now = time.time()
    with _rate_lock:
        q = _rate_buckets.get(key)
        if q is None:
            q = []
            _rate_buckets[key] = q
        cutoff = now - window
        while q and q[0] < cutoff:
            q.pop(0)
        if len(q) >= limit:
            return False
        q.append(now)
        return True


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Env-gated maintenance mode (FAMGATE_MAINTENANCE=1): freeze the site,
    # but keep health checks, static assets and in-flight payment pages alive.
    if os.environ.get("FAMGATE_MAINTENANCE", "0").strip().lower() in ("1", "true", "yes"):
        path = request.url.path
        allowed = path == "/api/v1/health" or path.startswith("/static/") or path.startswith("/pay/")
        if not allowed:
            if path.startswith("/api/"):
                return JSONResponse({"success": False, "error": "FamGate is under maintenance. Retry shortly."}, status_code=503)
            return render(request, "maintenance.html", status_code=503)
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if request.url.path.startswith("/pay/"):
        resp.headers["Content-Security-Policy"] = "frame-ancestors *"
    else:
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    if not request.url.path.startswith("/static/"):
        resp.headers.setdefault("Cache-Control", "no-cache")
    return resp


# ---------------------------------------------------------------- API auth + rate limit

def api_auth(request: Request, limit: int = 300, window: int = 60):
    """Returns (merchant_row, settings_row, error_response_or_None)."""
    ip = client_ip(request)
    if not rate_ok(f"ip:{ip}", 300, 60):
        return None, None, JSONResponse({"success": False, "error": "Rate limit exceeded (IP). Slow down."}, status_code=429)
    key = request.headers.get("x-api-key", "").strip()
    if not key:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            key = auth[7:].strip()
    if not key:
        return None, None, JSONResponse(
            {"success": False, "error": "Missing API key. Send X-Api-Key: fp_live_... header."}, status_code=401
        )
    row = db.get_api_key(key)
    if not row:
        return None, None, JSONResponse({"success": False, "error": "Invalid or revoked API key."}, status_code=401)
    owner = db.get_merchant_by_id(row["merchant_id"])
    if owner and int(owner["banned_at"] or 0) > 0:
        return None, None, JSONResponse({"success": False, "error": "This merchant account is suspended."}, status_code=403)
    if not rate_ok(f"key:{row['id']}", limit, window):
        return None, None, JSONResponse({"success": False, "error": "Rate limit exceeded for this key."}, status_code=429)
    db.touch_api_key(row["id"])
    settings = db.get_settings(row["merchant_id"])
    return row, settings, None


def _provider_vpa(settings, provider: str) -> str:
    if provider == "bharatpe":
        return (settings["bharatpe_vpa"] or "").strip()
    return (settings["fampay_upi"] or "").strip()


def _provider_ready(settings, provider: str) -> tuple:
    if provider == "bharatpe":
        if not settings["bharatpe_enabled"]:
            return False, "BharatPe is not enabled for this merchant (enable it in Dashboard → Payments)."
        if not (settings["bharatpe_mid"] and settings["bharatpe_token_enc"] and settings["bharatpe_vpa"]):
            return False, "BharatPe needs Merchant ID, API token and UPI VPA (Dashboard → Payments)."
        return True, ""
    if not settings["fampay_enabled"]:
        return False, "FamPay is not enabled for this merchant (enable it in Dashboard → Payments)."
    if not (settings["fampay_email"] and settings["fampay_app_password_enc"] and settings["fampay_upi"]):
        return False, "FamPay needs Gmail address, app password and UPI ID (Dashboard → Payments)."
    return True, ""


def _iso(ts: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))


def create_payment_order(mid: int, settings, provider: str, amount: float, *, client_ref="", note="",
                         customer_name="", customer_email="", expiry_minutes=15, source="api", merchant_name="") -> dict:
    base = round(max(float(amount), 1.0), 2)
    if pg.is_pg_provider(provider):
        # Official gateways match on their own reference, not on paise offsets
        exact = base
        upi_uri = ""
    else:
        if int(settings["decimal_offset"] or 0):
            exact = upi.pick_exact_amount(base, db.active_exact_amounts(mid))
        else:
            exact = base
        vpa = _provider_vpa(settings, provider)
        display = (merchant_name or settings["display_name"] or "Merchant").strip()
        note_text = (note or f"Payment to {display}").strip()[:80]
        upi_uri = upi.build_upi_uri(vpa, display, exact, note_text)
    display = (merchant_name or settings["display_name"] or "Merchant").strip()
    order_id = security.new_order_id()
    expires_at = int(time.time()) + int(expiry_minutes) * 60
    record = {
        "id": order_id, "merchant_id": mid, "provider": provider,
        "client_ref": str(client_ref or "")[:80], "base_amount": base, "exact_amount": exact,
        "currency": "INR", "note": note, "customer_name": customer_name, "customer_email": customer_email,
        "upi_uri": upi_uri, "source": source, "created_at": int(time.time()), "expires_at": expires_at,
    }
    db.create_order(record)
    if merchant_name:
        with db.connect() as conn:
            conn.execute("INSERT INTO order_display_names(order_id,merchant_name) VALUES (?,?)", (order_id,merchant_name[:80]))
    return record


def order_payload(request: Request, order, settings=None) -> dict:
    mid_host = str(request.base_url).rstrip("/")
    p = {
        "success": True,
        "order_id": order["id"],
        "provider": order["provider"],
        "status": order["status"],
        "amount": round(float(order["base_amount"]), 2),
        "exact_amount": round(float(order["exact_amount"]), 2),
        "currency": order["currency"],
        "client_ref": order["client_ref"],
        "note": order["note"],
        "payment_url": f"{mid_host}/pay/{order['id']}",
        "upi_link": order["upi_uri"],
        "created_at": order["created_at"],
        "expires_at": order["expires_at"],
        "expires_at_iso": _iso(order["expires_at"]),
    }
    if order["status"] == "PAID":
        p["utr"] = order["utr"]
        p["payer_name"] = order["payer_name"]
        p["paid_at"] = order["paid_at"]
    return p


# =================================================================
#  PUBLIC WEBSITE
# =================================================================

@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    m = current_merchant(request)
    return render(request, "index.html", merchant=m)


@app.get("/docs", response_class=HTMLResponse)
def docs_page(request: Request):
    return render(request, "docs.html", merchant=current_merchant(request), base=str(request.base_url).rstrip("/"))


@app.get("/guide", response_class=HTMLResponse)
def guide_page(request: Request):
    return render(request, "guide.html", merchant=current_merchant(request), base=str(request.base_url).rstrip("/"))


@app.get("/terms", response_class=HTMLResponse)
def terms_page(request: Request):
    return render(request, "terms.html", merchant=current_merchant(request))


# ---------------------------------------------------------------- auth

@app.get("/signup", response_class=HTMLResponse)
def signup_form(request: Request):
    if current_merchant(request):
        return RedirectResponse("/dashboard", 303)
    return render(request, "signup.html")


@app.post("/signup")
def signup_submit(request: Request, business_name: str = Form(...), email: str = Form(...),
                  password: str = Form(...), confirm: str = Form(...)):
    email = email.strip().lower()
    business_name = business_name.strip()
    if not business_name or len(business_name) < 2:
        return flash_redirect("/signup", err="Business name is required.")
    if "@" not in email or len(email) > 160:
        return flash_redirect("/signup", err="Enter a valid email address.")
    if len(password) < 8:
        return flash_redirect("/signup", err="Password must be at least 8 characters.")
    if password != confirm:
        return flash_redirect("/signup", err="Passwords do not match.")
    if db.get_merchant_by_email(email):
        return flash_redirect("/signup", err="An account with this email already exists. Log in instead.")
    merchant_id = db.create_merchant(email, security.hash_password(password), business_name)
    token = security.new_session_token()
    db.create_session(token, merchant_id)
    resp = RedirectResponse("/dashboard?ok=Welcome+to+FamGate.", 303)
    resp.set_cookie("famgate_session", token, max_age=30 * 24 * 3600, httponly=True, samesite="lax")
    return resp


# Compatibility redirects for old verification links/forms. They never authenticate by email.
@app.get("/verify-email", response_class=HTMLResponse)
def verify_email_get(request: Request):
    return RedirectResponse("/dashboard" if current_merchant(request) else "/login", 303)


@app.post("/verify-email")
def verify_email(request: Request):
    return RedirectResponse("/dashboard" if current_merchant(request) else "/login", 303)


@app.post("/verify-email/resend")
def verify_email_resend(request: Request):
    return RedirectResponse("/dashboard" if current_merchant(request) else "/login", 303)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if current_merchant(request):
        return RedirectResponse("/dashboard", 303)
    return render(request, "login.html")


@app.post("/login")
def login_submit(request: Request, email: str = Form(...), password: str = Form(...)):
    ip = client_ip(request)
    if not rate_ok(f"login:{ip}", 20, 300):
        return flash_redirect("/login", err="Too many attempts. Try again in a few minutes.")
    m = db.get_merchant_by_email(email)
    if not m or not security.verify_password(password, m["password_hash"]):
        return flash_redirect("/login", err="Wrong email or password.")
    if int(m["banned_at"] or 0) > 0:
        return flash_redirect("/login", err="This account has been suspended. Contact the operator.")
    token = security.new_session_token()
    db.create_session(token, m["id"])
    resp = RedirectResponse("/dashboard", 303)
    resp.set_cookie("famgate_session", token, max_age=30 * 24 * 3600, httponly=True, samesite="lax")
    return resp


@app.post("/logout")
def logout(request: Request):
    token = request.cookies.get("famgate_session", "")
    db.delete_session(token)
    resp = RedirectResponse("/", 303)
    resp.delete_cookie("famgate_session")
    return resp


# =================================================================
#  MERCHANT DASHBOARD
# =================================================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    settings = db.get_settings(m["id"])
    stats = db.stats_today(m["id"])
    counts = db.count_orders_by_status(m["id"])
    recent = db.list_orders(m["id"], limit=8)
    total = sum(counts.values())
    paid = counts.get("PAID", 0)
    success_rate = round(100 * paid / total, 1) if total else 100.0
    return render(
        request, "dashboard.html", merchant=m, settings=settings, stats=stats, counts=counts,
        recent=recent, success_rate=success_rate, total_orders=total,
        webhook=db.get_webhook(m["id"]),
    )


@app.get("/orders", response_class=HTMLResponse)
def orders_page(request: Request, status: str = ""):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    status_filter = (status or "").upper().strip()
    if status_filter not in ("", "PENDING", "PAID", "EXPIRED", "CANCELLED"):
        status_filter = ""
    orders = db.list_orders(m["id"], status_filter or None, limit=200)
    return render(request, "orders.html", merchant=m, orders=orders, status_filter=status_filter,
                  counts=db.count_orders_by_status(m["id"]))


# ---------------------------------------------------------------- payments / provider settings

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    settings = db.get_settings(m["id"])
    fampay_ready, _ = _provider_ready(settings, "fampay")
    bharatpe_ready, _ = _provider_ready(settings, "bharatpe")
    pg_creds = db.get_provider_credentials(m["id"])
    pg_panels = []
    for name in pg.PG_PROVIDERS:
        cls = pg.PG_PROVIDERS[name]
        entry = pg_creds.get(name) or {"enabled": False, "config": {}}
        cfg = entry.get("config") or {}
        adapter = pg.make(name, cfg)
        masked = {}
        for field, label, secret in pg.field_specs(name):
            val = str(cfg.get(field) or "")
            if secret:
                masked[field] = ("••••" + val[-4:]) if val else ""
            else:
                masked[field] = val
        pg_panels.append({
            "name": name, "title": cls.title, "icon": cls.icon, "cta_note": cls.cta_note,
            "fields": pg.field_specs(name), "field_help": cls.field_help,
            "enabled": bool(entry.get("enabled")), "masked": masked,
        })
    return render(request, "settings.html", merchant=m, settings=settings,
                  fampay_ready=fampay_ready, bharatpe_ready=bharatpe_ready, pg_panels=pg_panels)


@app.post("/settings/pg/{provider}")
async def settings_pg_save(request: Request, provider: str):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    if not pg.is_pg_provider(provider):
        return flash_redirect("/settings", err="Unknown provider.")
    current = (db.get_provider_credentials(m["id"]).get(provider) or {}).get("config") or {}
    form = await request.form()
    cfg = dict(current)
    for field, label, secret in pg.field_specs(provider):
        val = str(form.get(field) or "").strip()
        if secret:
            if val:  # blank means "keep existing"
                cfg[field] = val
        elif field == "env":
            cfg[field] = val if val in ("sandbox", "staging", "production") else {"razorpay": "", "cashfree": "sandbox", "phonepe": "sandbox", "paytm": "staging"}.get(provider, "sandbox")
        else:
            cfg[field] = val
    enabled = form.get("enabled") == "on"
    db.save_provider_credentials(m["id"], provider, enabled, cfg)
    adapter = pg.make(provider, cfg)
    return flash_redirect("/settings", ok=f"{adapter.title} settings saved.")


@app.post("/settings/pg/{provider}/test")
async def settings_pg_test(request: Request, provider: str):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    if not pg.is_pg_provider(provider):
        return flash_redirect("/settings", err="Unknown provider.")
    form = await request.form()
    entry = db.get_provider_credentials(m["id"]).get(provider) or {}
    stored = entry.get("config") or {}
    merged = {}
    for field, label, secret in pg.field_specs(provider):
        val = (form.get(field) or "").strip()
        if secret and not val:          # blank = keep saved secret
            val = str(stored.get(field) or "")
        elif not secret and not val:    # non-secret blank = fall back to stored
            val = str(stored.get(field) or "")
        merged[field] = val
    adapter = pg.make(provider, merged)
    ok, msg = adapter.test_connection()
    return flash_redirect("/settings", ok=("✓ " + msg) if ok else "", err="" if ok else msg)


@app.post("/settings/general")
def settings_general(request: Request, display_name: str = Form(""), decimal_offset: str = Form("off"),
                     default_provider: str = Form("fampay")):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    db.save_settings(m["id"], {
        "display_name": display_name.strip()[:80],
        "decimal_offset": 1 if decimal_offset == "on" else 0,
        "default_provider": default_provider if default_provider in pg.ALL_PROVIDERS else "fampay",
    })
    return flash_redirect("/settings", ok="General settings saved.")


@app.post("/settings/fampay")
def settings_fampay(request: Request, fampay_enabled: str = Form("off"), fampay_email: str = Form(""),
                    fampay_app_password: str = Form(""), fampay_upi: str = Form(""),
                    imap_host: str = Form("imap.gmail.com"), imap_folder: str = Form("INBOX")):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    current = db.get_settings(m["id"])
    fields = {
        "fampay_enabled": 1 if fampay_enabled == "on" else 0,
        "fampay_email": fampay_email.strip()[:160],
        "fampay_upi": fampay_upi.strip()[:80],
        "imap_host": (imap_host or "imap.gmail.com").strip()[:120],
        "imap_folder": (imap_folder or "INBOX").strip()[:60],
    }
    pw = fampay_app_password.replace(" ", "").strip()
    if pw:
        fields["fampay_app_password_enc"] = security.encrypt_secret(pw)
    elif not current["fampay_app_password_enc"]:
        fields["fampay_enabled"] = 0
    db.save_settings(m["id"], fields)
    return flash_redirect("/settings", ok="FamPay settings saved." + ("" if pw or current["fampay_app_password_enc"] else " Add the Gmail app password to enable."))


@app.post("/settings/fampay/test")
async def settings_fampay_test(request: Request):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    form = await request.form()
    stored = db.get_settings(m["id"])
    email_addr = (form.get("fampay_email") or stored["fampay_email"] or "").strip()
    pw = (form.get("fampay_app_password") or "").strip()
    if not pw:  # blank = keep saved secret
        pw = security.decrypt_secret(stored["fampay_app_password_enc"]) or ""
    host = (form.get("imap_host") or stored["imap_host"] or "imap.gmail.com").strip()
    folder = (form.get("imap_folder") or stored["imap_folder"] or "INBOX").strip()
    ok, msg = verifiers.test_imap_login(email_addr, pw, host, int(stored["imap_port"] or 993), folder)
    return flash_redirect("/settings", ok=("✓ " + msg) if ok else "", err="" if ok else msg)


@app.post("/settings/bharatpe")
def settings_bharatpe(request: Request, bharatpe_enabled: str = Form("off"), bharatpe_mid: str = Form(""),
                      bharatpe_token: str = Form(""), bharatpe_vpa: str = Form("")):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    current = db.get_settings(m["id"])
    fields = {
        "bharatpe_enabled": 1 if bharatpe_enabled == "on" else 0,
        "bharatpe_mid": bharatpe_mid.strip()[:60],
        "bharatpe_vpa": bharatpe_vpa.strip()[:80],
    }
    tok = bharatpe_token.strip()
    if tok:
        fields["bharatpe_token_enc"] = security.encrypt_secret(tok)
    elif not current["bharatpe_token_enc"]:
        fields["bharatpe_enabled"] = 0
    db.save_settings(m["id"], fields)
    return flash_redirect("/settings", ok="BharatPe settings saved." + ("" if tok or current["bharatpe_token_enc"] else " Add the API token to enable."))


@app.post("/settings/bharatpe/test")
async def settings_bharatpe_test(request: Request):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    form = await request.form()
    stored = db.get_settings(m["id"])
    mid_value = (form.get("bharatpe_mid") or stored["bharatpe_mid"] or "").strip()
    token = (form.get("bharatpe_token") or "").strip()
    if not token:  # blank = keep saved secret
        token = security.decrypt_secret(stored["bharatpe_token_enc"]) or ""
    ok, msg = verifiers.test_bharatpe_token(mid_value, token)
    return flash_redirect("/settings", ok=("✓ " + msg) if ok else "", err="" if ok else msg)


# ---------------------------------------------------------------- api keys

@app.get("/api-keys", response_class=HTMLResponse)
def api_keys_page(request: Request):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    keys = db.list_api_keys(m["id"])
    flash = flash_pop(request)
    return render(request, "api_keys.html", merchant=m, keys=keys,
                  new_key=flash.get("new_key", ""), new_secret=flash.get("new_secret", ""),
                  base=str(request.base_url).rstrip("/"))


@app.post("/api-keys/create")
def api_keys_create(request: Request, label: str = Form("Default key")):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    api_key = security.new_api_key()
    secret = security.new_api_secret()
    preview = secret[:10] + "…" + secret[-4:]
    db.create_api_key(m["id"], label, api_key, security.encrypt_secret(secret), preview)
    flash_set(request, new_key=api_key, new_secret=secret)
    return RedirectResponse("/api-keys", 303)


@app.post("/api-keys/{key_id}/revoke")
def api_keys_revoke(request: Request, key_id: int):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    ok = db.revoke_api_key(m["id"], key_id)
    return flash_redirect("/api-keys", ok="API key revoked." if ok else "", err="" if ok else "Key not found.")


# ---------------------------------------------------------------- webhooks

@app.get("/webhooks", response_class=HTMLResponse)
def webhooks_page(request: Request):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    wh = db.get_webhook(m["id"])
    deliveries = db.list_webhook_deliveries(m["id"], 30)
    flash = flash_pop(request)
    return render(request, "webhooks.html", merchant=m, webhook=wh, deliveries=deliveries,
                  new_secret=flash.get("new_secret", ""), base=str(request.base_url).rstrip("/"))


@app.post("/webhooks/save")
def webhooks_save(request: Request, url: str = Form("")):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    url = url.strip()
    if url:
        ok, reason = security.webhook_url_allowed(url)
        if not ok:
            return flash_redirect("/webhooks", err=f"Webhook URL rejected: {reason}")
    db.save_webhook(m["id"], url)
    return flash_redirect("/webhooks", ok="Webhook URL saved.")


@app.post("/webhooks/regen-secret")
def webhooks_regen(request: Request):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    secret = security.new_webhook_secret()
    wh = db.get_webhook(m["id"])
    db.save_webhook(m["id"], wh["url"] if wh else "", security.encrypt_secret(secret), secret[:10] + "…" + secret[-4:])
    flash_set(request, new_secret=secret)
    return RedirectResponse("/webhooks", 303)


@app.post("/webhooks/test")
def webhooks_test(request: Request):
    m = require_merchant(request)
    if not m:
        return RedirectResponse("/login", 303)
    payload = {
        "event": "payment.test",
        "order_id": "ord_test_sample",
        "provider": "fampay",
        "amount": 100.42,
        "currency": "INR",
        "utr": "TESTUTR123456",
        "message": "This is a FamGate test webhook. Your endpoint is reachable.",
        "sent_at": int(time.time()),
    }
    res = verifiers.fire_webhook(m["id"], "ord_test_sample", payload, event="payment.test")
    if res.get("sent"):
        return flash_redirect("/webhooks", ok=f"Test webhook delivered (HTTP {res.get('status_code')}).")
    return flash_redirect("/webhooks", err=f"Test webhook failed: {res.get('detail', 'unknown error')}")


# =================================================================
#  INBOUND CALLBACKS from official gateways  (/webhooks/<provider>)
# =================================================================

def _provider_callback_flow(provider: str, request: Request, raw: bytes, cfg_adapter_map=None):
    """Peek ref → locate order+merchant → verify signature → settle (idempotent)."""
    uh = {k.lower(): v for k, v in request.headers.items()}
    ref = pg.peek_ref(provider, uh, raw)
    order = db.get_order_by_provider_ref(provider, ref) if ref else None
    if not order:
        # fallback: Paytm's ORDERID is our own order id
        if ref and db.get_order(ref):
            order = db.get_order(ref)
    if not order:
        return None, JSONResponse({"success": False, "error": "unknown reference"}, status_code=404)
    entry = (db.get_provider_credentials(order["merchant_id"]) or {}).get(provider) or {}
    cfg = entry.get("config") or {}
    adapter = pg.make(provider, cfg)
    verified = adapter.verify_callback(uh, raw, cfg)
    if not verified:
        db.log_webhook_delivery(order["merchant_id"], order["id"], f"inbound:{provider}", "callback", 401, False, "signature mismatch — rejected")
        return None, JSONResponse({"success": False, "error": "invalid signature"}, status_code=401)
    result = {"settled": False}
    if verified.get("ok"):
        # settle_via_callback performs the settle + outbound webhook and logs its own delivery row
        result = verifiers.settle_via_callback(provider, verified.get("provider_ref") or order["provider_ref"] or order["id"],
                                               verified.get("utr", ""), verified.get("amount"), event="payment.verified", order=order)
    else:
        db.log_webhook_delivery(order["merchant_id"], order["id"], f"inbound:{provider}", "callback", 200, True,
                                "callback verified — event not a success state, ignored")
    return order, JSONResponse({"success": True, "event": "ok" if verified.get("ok") else "ignored", **({} if not result else {"detail": result.get("detail", "")})})


@app.api_route("/webhooks/razorpay", methods=["GET", "POST"])
async def razorpay_webhook(request: Request):
    if request.method == "GET":
        # Browser callback from a Razorpay payment link (no signature on GET — verify the triple)
        q = request.query_params
        plink, pid, sig = q.get("razorpay_payment_link_id", ""), q.get("razorpay_payment_id", ""), q.get("razorpay_signature", "")
        order = db.get_order_by_provider_ref("razorpay", plink) if plink else None
        if order:
            entry = (db.get_provider_credentials(order["merchant_id"]) or {}).get("razorpay") or {}
            secret = (entry.get("config") or {}).get("key_secret", "").strip()
            expected = hmac.new(secret.encode(), f"{plink}|{pid}".encode(), hashlib.sha256).hexdigest() if secret else ""
            if secret and hmac.compare_digest(expected, sig or ""):
                verifiers.settle_via_callback("razorpay", plink, pid, None, event="payment.verified")
            return RedirectResponse(f"/pay/{order['id']}", 303)
        return RedirectResponse("/", 303)
    raw = await request.body()
    order, resp = _provider_callback_flow("razorpay", request, raw)
    return resp


@app.post("/webhooks/phonepe")
async def phonepe_webhook(request: Request):
    raw = await request.body()
    _, resp = _provider_callback_flow("phonepe", request, raw)
    return resp


@app.post("/webhooks/cashfree")
async def cashfree_webhook(request: Request):
    raw = await request.body()
    _, resp = _provider_callback_flow("cashfree", request, raw)
    return resp


@app.post("/webhooks/paytm")
async def paytm_webhook(request: Request):
    raw = await request.body()
    order, resp = _provider_callback_flow("paytm", request, raw)
    ctype = request.headers.get("content-type", "")
    if order is not None and ("application/x-www-form-urlencoded" in ctype or "multipart/form-data" in ctype):
        # Paytm's browser callback — send the customer back to the checkout status page
        return RedirectResponse(f"/pay/{order['id']}", 303)
    return resp


@app.post("/webhooks/mobikwik")
async def mobikwik_webhook(request: Request):
    raw = await request.body()
    order, resp = _provider_callback_flow("mobikwik", request, raw)
    ctype = request.headers.get("content-type", "")
    if order is not None and ("application/x-www-form-urlencoded" in ctype or "multipart/form-data" in ctype):
        # Zaakpay's browser returnUrl POST — customer bounce back to the status page
        return RedirectResponse(f"/pay/{order['id']}", 303)
    return resp


# =================================================================
#  MERCHANT REST API  (v1)
# =================================================================

def _api_json(data: dict, status: int = 200) -> JSONResponse:
    return JSONResponse(data, status_code=status)


@app.get("/api/v1/health")
def api_health():
    return {"ok": True, "service": "famgate", "time": int(time.time())}


@app.post("/api/v1/order/create")
async def api_order_create(request: Request):
    merchant, settings, err = api_auth(request, limit=60, window=60)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        return _api_json({"success": False, "error": "Body must be valid JSON."}, 400)
    try:
        amount = float(body.get("amount"))
    except (TypeError, ValueError):
        return _api_json({"success": False, "error": "Field 'amount' (number, ₹) is required."}, 400)
    if amount <= 0 or amount > 500000:
        return _api_json({"success": False, "error": "Amount must be between ₹1 and ₹5,00,000."}, 400)

    provider = str(body.get("provider") or settings["default_provider"] or "fampay").lower()
    if provider == "auto":
        provider = settings["default_provider"] or "fampay"
    if provider not in pg.ALL_PROVIDERS:
        return _api_json({"success": False,
                          "error": "provider must be one of: fampay, bharatpe, phonepe, paytm, razorpay, cashfree (or 'auto')."}, 400)

    expiry = body.get("expiry_minutes", 15)
    try:
        expiry = max(1, min(60, int(expiry)))
    except (TypeError, ValueError):
        expiry = 15
    customer_email = str(body.get("customer_email") or "").strip()[:160]
    if customer_email and "@" not in customer_email:
        return _api_json({"success": False, "error": "customer_email is not a valid email."}, 400)

    base_url = str(request.base_url).rstrip("/")
    mid = merchant["merchant_id"]

    # ---------- official gateways: create the payment ON the provider ----------
    if pg.is_pg_provider(provider):
        creds = db.get_provider_credentials(mid)
        entry = creds.get(provider) or {}
        pcfg = entry.get("config") or {}
        adapter = pg.make(provider, pcfg)
        if not entry.get("enabled"):
            return _api_json({"success": False, "error": f"{adapter.title} is not enabled. Enable it in Dashboard → Payments."}, 400)
        missing = adapter.missing_fields()
        if missing:
            return _api_json({"success": False, "error": f"{adapter.title} is missing: {', '.join(missing)} — Dashboard → Payments."}, 400)
        order = create_payment_order(
            mid, settings, provider, amount,
            client_ref=str(body.get("order_id") or body.get("client_ref") or "")[:80],
            note=str(body.get("note") or ""), customer_name=str(body.get("customer_name") or "")[:120],
            customer_email=customer_email, expiry_minutes=expiry, source=getattr(request.state,"manual_source","api"),
            merchant_name=getattr(request.state,"manual_name",""),
        )
        try:
            result = adapter.create_payment(db.get_order(order["id"]), base_url)
        except Exception as e:  # never let a gateway SDK crash become a 500
            result = pg.base.PGResult(False, error=f"unexpected gateway error: {e}")
        if not result.ok:
            with db.connect() as conn:
                conn.execute("UPDATE orders SET status='EXPIRED' WHERE id=?", (order["id"],))
            return _api_json({"success": False, "error": f"{adapter.title} rejected the request: {result.error}"}, 502)
        db.update_order_provider_ref(order["id"], result.provider_ref, result.provider_token or result.payment_url)
        qr_bytes = upi.qr_png_bytes(result.payment_url)
        return _api_json({
            "success": True,
            "order_id": order["id"],
            "provider": provider,
            "amount": order["base_amount"],
            "exact_amount": order["exact_amount"],
            "currency": "INR",
            "client_ref": order["client_ref"],
            "payment_url": result.payment_url,
            "hosted_checkout_url": f"{base_url}/pay/{order['id']}",
            "upi_link": "",
            "qr_base64": "data:image/png;base64," + base64.b64encode(qr_bytes).decode(),
            "expires_at": order["expires_at"],
            "expires_at_iso": _iso(order["expires_at"]),
            "expires_in_sec": max(0, order["expires_at"] - int(time.time())),
        })

    # ---------- direct UPI rails: decimal-offset QR + IMAP/feed verification ----------
    ready, why = _provider_ready(settings, provider)
    if not ready:
        return _api_json({"success": False, "error": why}, 400)

    order = create_payment_order(
        mid, settings, provider, amount,
        client_ref=str(body.get("order_id") or body.get("client_ref") or "")[:80],
        note=str(body.get("note") or ""), customer_name=str(body.get("customer_name") or "")[:120],
        customer_email=customer_email, expiry_minutes=expiry, source=getattr(request.state,"manual_source","api"),
            merchant_name=getattr(request.state,"manual_name",""),
    )
    qr_bytes = upi.qr_png_bytes(order["upi_uri"])
    return _api_json({
        "success": True,
        "order_id": order["id"],
        "provider": provider,
        "amount": order["base_amount"],
        "exact_amount": order["exact_amount"],
        "currency": "INR",
        "client_ref": order["client_ref"],
        "payment_url": f"{base_url}/pay/{order['id']}",
        "hosted_checkout_url": f"{base_url}/pay/{order['id']}",
        "upi_link": order["upi_uri"],
        "qr_base64": "data:image/png;base64," + base64.b64encode(qr_bytes).decode(),
        "expires_at": order["expires_at"],
        "expires_at_iso": _iso(order["expires_at"]),
        "expires_in_sec": max(0, order["expires_at"] - int(time.time())),
    })


@app.api_route("/api/v1/order/status", methods=["GET", "POST"])
async def api_order_status(request: Request):
    merchant, settings, err = api_auth(request, limit=600, window=60)
    if err:
        return err
    order_id = request.query_params.get("order_id", "")
    client_ref = request.query_params.get("client_ref", "")
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        order_id = str(body.get("order_id") or order_id or "")
        client_ref = str(body.get("client_ref") or client_ref or "")
    mid = merchant["merchant_id"]
    order = db.get_order_by_merchant(order_id, mid) if order_id else (db.get_order_by_client_ref(mid, client_ref) if client_ref else None)
    if not order:
        return _api_json({"success": False, "error": "Order not found."}, 404)
    if order["status"] == "PENDING":
        verifiers.verify_on_demand(mid, order["provider"])
        order = db.get_order(order["id"])
    p = order_payload(request, order)
    p["time_remaining"] = max(0, int(order["expires_at"]) - int(time.time()))
    return _api_json(p)


@app.post("/api/v1/order/verify-utr")
async def api_verify_utr(request: Request):
    merchant, settings, err = api_auth(request, limit=60, window=60)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        return _api_json({"success": False, "error": "Body must be valid JSON."}, 400)
    mid = merchant["merchant_id"]
    order_id = str(body.get("order_id") or "")
    raw_utr = security.clean_utr(body.get("utr") or "")
    if not order_id or len(raw_utr) < 8:
        return _api_json({"success": False, "error": "order_id and a valid utr (8+ chars) are required."}, 400)
    order = db.get_order_by_merchant(order_id, mid)
    if not order:
        return _api_json({"success": False, "error": "Order not found."}, 404)
    if pg.is_pg_provider(order["provider"]):
        return _api_json({"success": False,
                          "error": "Orders on official gateways settle via the provider's webhook/status — poll /api/v1/order/status instead of verify-utr."}, 400)
    if order["status"] == "PAID":
        return _api_json({"success": True, "status": "PAID", "order_id": order_id, "utr": order["utr"]})
    if db.is_utr_used(raw_utr):
        return _api_json({"success": False, "error": f"UTR {raw_utr} was already used for another order."}, 409)
    # Force an immediate scan for this merchant, then re-check
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM merchant_settings WHERE merchant_id=?", (mid,)).fetchone()
    try:
        if order["provider"] == "bharatpe" and row and row["bharatpe_enabled"]:
            mid_value = row["bharatpe_mid"].strip()
            token = security.decrypt_secret(row["bharatpe_token_enc"])
            txns = verifiers.fetch_bharatpe_transactions(mid_value, token, force=True)
            for t in txns:
                t_utr = security.clean_utr(t.get("bankReferenceNo") or t.get("internalUtr") or "")
                if str(t.get("status") or "").upper() == "SUCCESS" and (raw_utr == t_utr or raw_utr in t_utr or t_utr in raw_utr):
                    amt = float(t.get("amount") or 0)
                    if db.mark_order_paid(order_id, t_utr, str(t.get("payerName") or "")):
                        db.mark_utr_used(t_utr, order_id, mid, amt, str(t.get("payerName") or ""))
                        verifiers.settle_post_actions(mid, order_id, "bharatpe", amt, t_utr,
                                                      str(t.get("payerName") or ""), order["customer_email"] or "", order["customer_name"] or "")
                        return _api_json({"success": True, "status": "PAID", "order_id": order_id, "utr": t_utr, "amount": amt})
        elif order["provider"] == "fampay" and row and row["fampay_enabled"]:
            verifiers.check_fampay_imap(row)
            order = db.get_order(order_id)
            if order["status"] == "PAID":
                return _api_json({"success": True, "status": "PAID", "order_id": order_id, "utr": order["utr"]})
    except RuntimeError as e:
        return _api_json({"success": False, "error": str(e)}, 502)
    order = db.get_order(order_id)
    return _api_json({"success": False, "status": order["status"],
                      "error": "Payment not visible yet. UPI/IMAP data can take 10–60s — retry shortly."}, 202)


@app.get("/api/v1/order/status")
def api_order_status(request: Request, order_id: str = "", client_ref: str = ""):
    """Poll a single order by our order_id or your client_ref. Docs: GET /api/v1/order/status"""
    merchant, settings, err = api_auth(request, limit=180, window=60)
    if err:
        return err
    mid = merchant["merchant_id"]
    order = None
    if order_id:
        cand = db.get_order(order_id.strip())
        if cand and int(cand["merchant_id"]) == int(mid):
            order = cand
    elif client_ref:
        order = db.get_order_by_client_ref(int(mid), client_ref.strip())
    if not order:
        return _api_json({"success": False, "error": "Order not found."}, 404)
    return _api_json(order_payload(request, order, settings))


@app.get("/api/v1/orders")
def api_orders_list(request: Request, status: str = "", limit: int = 25):
    merchant, settings, err = api_auth(request, limit=120, window=60)
    if err:
        return err
    try:
        limit = max(1, min(100, int(limit)))
    except (TypeError, ValueError):
        limit = 25
    mid = merchant["merchant_id"]
    rows = db.list_orders(mid, (status or "").upper().strip() or None, limit=limit)
    return _api_json({"success": True, "count": len(rows), "orders": [order_payload(request, r) for r in rows]})


# =================================================================
#  HOSTED CHECKOUT  (/pay/<order_id>)
# =================================================================

@app.get("/pay/{order_id}", response_class=HTMLResponse)
def checkout(request: Request, order_id: str):
    order = db.get_order(order_id)
    if not order:
        return render(request, "error.html", status_code=404, code=404, message="This payment link is invalid or has expired.")
    settings = db.get_settings(order["merchant_id"])
    merchant = db.get_merchant_by_id(order["merchant_id"])
    with db.connect() as conn:
        named = conn.execute("SELECT merchant_name FROM order_display_names WHERE order_id=?", (order_id,)).fetchone()
    merchant = dict(merchant)
    merchant['business_name'] = named['merchant_name'] if named else (settings['display_name'] or merchant['business_name'])
    if order['status'] == 'PENDING' and order['expires_at'] <= int(time.time()):
        with db.connect() as conn:
            conn.execute("UPDATE orders SET status='EXPIRED' WHERE id=? AND status='PENDING'", (order_id,))
        order = db.get_order(order_id)
    if order['status'] not in ('PENDING','PAID'):
        return render(request,'payment_closed.html',order=order,merchant=merchant)
    links = upi.app_deep_links(order["upi_uri"]) if order["upi_uri"] else {}
    mobikwik_form = {}
    mobikwik_action = ""
    if order["provider"] == "mobikwik" and order["provider_token"]:
        try:
            mobikwik_form = json.loads(order["provider_token"])
        except Exception:
            mobikwik_form = {}
        entry = (db.get_provider_credentials(order["merchant_id"]) or {}).get("mobikwik") or {}
        base_host = str(request.base_url).rstrip("/")
        live = str((entry.get("config") or {}).get("env") or "sandbox") == "production"
        mobikwik_action = ("https://api.zaakpay.com" if live else "https://zaakstaging.zaakpay.com") + "/api/paymentTransact/V13"
        # provider_token stores the full signed form — never trust client input, re-render from it
    paytm_js = ""
    paytm_cfg = {}
    if order["provider"] == "paytm" and order["provider_token"]:
        entry = (db.get_provider_credentials(order["merchant_id"]) or {}).get("paytm") or {}
        paytm_cfg = entry.get("config") or {}
        mid_value = (paytm_cfg.get("mid") or "").strip()
        staging = str(paytm_cfg.get("env") or "staging") != "production"
        paytm_js = (f"https://securegw-stg.paytm.in/merchantpgpui/checkoutjs/merchants/{mid_value}.js" if staging
                    else f"https://securegw.paytm.in/merchantpgpui/checkoutjs/merchants/{mid_value}.js")
    return render(request, "pay.html", order=order, settings=settings, merchant=merchant, links=links,
                  base=str(request.base_url).rstrip("/"), pg_title=pg.title_of(order["provider"]),
                  is_pg=pg.is_pg_provider(order["provider"]), paytm_js=paytm_js, paytm_cfg=paytm_cfg,
                  mobikwik_form=mobikwik_form, mobikwik_action=mobikwik_action, cancel_token=cancel_token_for(order_id))


@app.get("/pay/{order_id}/qr.png")
def checkout_qr(order_id: str):
    order = db.get_order(order_id)
    if not order:
        return Response(status_code=404)
    if order["status"] != "PENDING" or order["expires_at"] <= int(time.time()):
        return Response(status_code=410)
    target = order["upi_uri"]
    if not target and order["provider_token"].startswith("http"):
        target = order["provider_token"]  # PG checkout URLs scan fine in phone browsers
    if not target:
        return Response(status_code=404)
    png = upi.qr_png_bytes(target, box_size=10, border=2)
    return Response(content=png, media_type="image/png", headers={"Cache-Control": "no-store"})


@app.get("/pay/{order_id}/status")
def checkout_status(request: Request, order_id: str):
    order = db.get_order(order_id)
    if not order:
        return JSONResponse({"success": False, "error": "not found"}, status_code=404)
    if not rate_ok(f"paystatus:{order_id}", 120, 60):
        return JSONResponse({"success": False, "error": "poll less frequently"}, status_code=429)
    if order["status"] == "PENDING":
        verifiers.verify_on_demand(order["merchant_id"], order["provider"])
        order = db.get_order(order_id)
    return JSONResponse({
        "success": True,
        "status": order["status"],
        "exact_amount": round(float(order["exact_amount"]), 2),
        "base_amount": round(float(order["base_amount"]), 2),
        "time_remaining": max(0, int(order["expires_at"]) - int(time.time())),
        "utr": order["utr"] if order["status"] == "PAID" else "",
        "payer_name": order["payer_name"] if order["status"] == "PAID" else "",
        "paid_at": order["paid_at"],
    })


@app.post("/pay/{order_id}/verify-utr")
def checkout_verify_utr(request: Request, order_id: str, utr: str = Form(...)):
    order = db.get_order(order_id)
    if not order:
        return flash_redirect(f"/pay/{order_id}", err="Order not found.")
    if order["status"] != "PENDING":
        return flash_redirect(f"/pay/{order_id}", err="This payment is no longer pending.")
    if pg.is_pg_provider(order["provider"]):
        verifiers.verify_on_demand(order["merchant_id"], order["provider"])
        order = db.get_order(order_id)
        if order["status"] == "PAID":
            return flash_redirect(f"/pay/{order_id}", ok="Payment verified. Thank you!")
        return flash_redirect(f"/pay/{order_id}", err="Your payment is being confirmed by the provider — this usually takes a few seconds.")
    raw = security.clean_utr(utr)
    if len(raw) < 8:
        return flash_redirect(f"/pay/{order_id}", err="Enter the full UTR / bank reference (8+ characters).")
    if db.is_utr_used(raw):
        return flash_redirect(f"/pay/{order_id}", err="That UTR was already claimed for another order.")
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM merchant_settings WHERE merchant_id=?", (order["merchant_id"],)).fetchone()
    try:
        if order["provider"] == "bharatpe" and row and row["bharatpe_enabled"]:
            verifiers.fetch_bharatpe_transactions(row["bharatpe_mid"].strip(),
                                                  security.decrypt_secret(row["bharatpe_token_enc"]), force=True)
        elif order["provider"] == "fampay" and row and row["fampay_enabled"]:
            verifiers.check_fampay_imap(row)
    except Exception:
        pass
    order = db.get_order(order_id)
    if order["status"] == "PAID":
        return flash_redirect(f"/pay/{order_id}", ok="Payment verified. Thank you!")
    return flash_redirect(f"/pay/{order_id}", err="Still not found. UPI can take 10–60s — try again.")


# ---------------------------------------------------------------- misc

@app.get("/favicon.ico")
def favicon():
    svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#111"/><path d="M36 6 L18 36 H30 L26 58 L46 26 H33 Z" fill="#FFE500" stroke="#FFE500" stroke-width="2" stroke-linejoin="round"/></svg>"""
    return Response(svg, media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=86400"})


@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"success": False, "error": "Not found"}, status_code=404)
    return render(request, "error.html", status_code=404, code=404, message="That page doesn't exist.")


@app.exception_handler(500)
async def server_error(request: Request, exc):
    return render(request, "error.html", status_code=500, code=500, message="Something broke on our side. Try again in a moment.")


# =================================================================
#  ADMIN CONSOLE
#  Enabled per-operator: FAMGATE_ADMIN_EMAILS="you@example.com,ops@example.com"
#  Non-admins get a 404 — the console's existence is not advertised.
# =================================================================

def require_admin(request: Request):
    m = current_merchant(request)
    return m if is_admin_merchant(m) else None


def _admin_missing(request: Request):
    return render(request, "error.html", status_code=404, code=404, message="That page doesn't exist.")


@app.get("/admin", response_class=HTMLResponse)
def admin_home(request: Request):
    m = require_admin(request)
    if not m:
        return _admin_missing(request)
    stats = db.admin_stats()
    return render(request, "admin.html", merchant=m, stats=stats,
                  recent_orders=db.admin_recent_orders(8), recent_users=db.admin_recent_users(6))


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, q: str = "", page: int = 1):
    m = require_admin(request)
    if not m:
        return _admin_missing(request)
    page = max(1, page)
    per = 25
    rows, total = db.admin_list_users(q, per, (page - 1) * per)
    pages = max(1, (total + per - 1) // per)
    return render(request, "admin_users.html", merchant=m, users=rows, q=q,
                  page=page, pages=pages, total=total)


@app.get("/admin/users/{mid}", response_class=HTMLResponse)
def admin_user_detail(request: Request, mid: int):
    m = require_admin(request)
    if not m:
        return _admin_missing(request)
    detail = db.admin_user_detail(mid)
    if not detail:
        return _admin_missing(request)
    target = detail.pop("merchant")
    return render(request, "admin_user.html", target=target, **detail, is_self=(int(target["id"]) == int(m["id"])))


@app.post("/admin/users/{mid}/ban")
def admin_ban_user(request: Request, mid: int, reason: str = Form("")):
    m = require_admin(request)
    if not m:
        return _admin_missing(request)
    target = db.get_merchant_by_id(mid)
    if not target:
        return _admin_missing(request)
    t_email = (target["email"] or "").lower()
    if t_email == (m["email"] or "").lower():
        return flash_redirect(f"/admin/users/{mid}", err="You cannot ban yourself.")
    if t_email in _admin_emails():
        return flash_redirect(f"/admin/users/{mid}", err="Admin accounts cannot be banned from this console.")
    db.set_merchant_banned(mid, True, reason)
    print(f"[admin] {m['email']} BANNED merchant #{mid} ({target['email']}) reason={reason!r}", flush=True)
    return flash_redirect(f"/admin/users/{mid}", ok=f"Banned {target['email']}. Their sessions and API access are revoked.")


@app.post("/admin/users/{mid}/unban")
def admin_unban_user(request: Request, mid: int):
    m = require_admin(request)
    if not m:
        return _admin_missing(request)
    target = db.get_merchant_by_id(mid)
    if not target:
        return _admin_missing(request)
    db.set_merchant_banned(mid, False)
    print(f"[admin] {m['email']} UNBANNED merchant #{mid} ({target['email']})", flush=True)
    return flash_redirect(f"/admin/users/{mid}", ok=f"{target['email']} is reinstated.")


@app.get("/admin/orders", response_class=HTMLResponse)
def admin_orders(request: Request, status: str = "", provider: str = "", q: str = "", page: int = 1):
    m = require_admin(request)
    if not m:
        return _admin_missing(request)
    page = max(1, page)
    per = 40
    rows, total = db.admin_list_orders(status, provider, q, per, (page - 1) * per)
    counts = db.admin_order_status_counts()
    pages = max(1, (total + per - 1) // per)
    return render(request, "admin_orders.html", merchant=m, orders=rows, counts=counts,
                  status=status.upper(), provider=provider.lower(), q=q, page=page, pages=pages, total=total)


@app.post("/admin/orders/{order_id}/expire")
def admin_expire_order(request: Request, order_id: str):
    m = require_admin(request)
    if not m:
        return _admin_missing(request)
    o = db.get_order(order_id)
    if not o:
        return _admin_missing(request)
    if o["status"] != "PENDING":
        return flash_redirect("/admin/orders?status=PENDING", err="Only PENDING orders can be expired.")
    with db.connect() as conn:
        conn.execute("UPDATE orders SET status='EXPIRED' WHERE id=? AND status='PENDING'", (order_id,))
    print(f"[admin] {m['email']} EXPIRED order {order_id}", flush=True)
    return flash_redirect("/admin/orders?status=PENDING", ok=f"Order {order_id} marked EXPIRED.")


from manual_features import register as register_manual_features
register_manual_features(globals())

# Separate simulated orders: no live providers, settlement or webhooks.
from demo_sandbox import register_sandbox
register_sandbox(app, render=render, current_merchant=current_merchant, api_auth=api_auth,
                 rate_ok=rate_ok, client_ip=client_ip, data_dir=db.DATA_DIR)
