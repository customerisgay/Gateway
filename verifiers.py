# -*- coding: utf-8 -*-
"""
Background verification engine.

FamPay  — FamPay exposes no official merchant API. Payment is auto-verified by reading the
          merchant's FamPay/UPI payment-confirmation emails over Gmail IMAP, extracting the
          amount + 12-digit bank reference (UTR/RRN) and matching it against pending orders
          using the unique decimal-offset amount.

BharatPe — polls the enterprise dashboard transaction feed
          (https://payments-tesseract.bharatpe.in/api/v1/merchant/transactions) with the
          merchant's Merchant ID + API token and matches SUCCESS transactions by exact amount.

Both paths: UTR de-duplication (global anti-replay), expiry sweeping, signed webhooks.
"""
import email
import imaplib
import json
import re
import threading
import time
from email.header import decode_header
from email.utils import parsedate_to_datetime, getaddresses
from typing import Any, Dict, List, Optional

import requests

import db
import mailer
import security

BHARATPE_FEED = "https://payments-tesseract.bharatpe.in/api/v1/merchant/transactions"
HTTP_TIMEOUT = 10
_cache: Dict[int, Dict[str, Any]] = {}  # per-merchant BharatPe response cache
_cache_lock = threading.Lock()
CACHE_TTL = 5  # seconds

FAMPAY_KEYWORDS = (
    "fampay", "famapp", "upi", "phonepe", "gpay", "google pay", "paytm",
    "received", "credited", "payment", "utr", "rrn",
)


# ------------------------------------------------------------------ helpers

def clean_utr(raw: str) -> str:
    return security.clean_utr(raw)


def _decode_mime(s: str) -> str:
    try:
        parts = decode_header(s or "")
        out = []
        for text, enc in parts:
            out.append(text.decode(enc or "utf-8", errors="replace") if isinstance(text, bytes) else str(text))
        return "".join(out)
    except Exception:
        return str(s or "")


def _extract_amounts(text: str) -> List[float]:
    found = []
    for m in re.finditer(r"(?:₹|Rs\.?|INR)\s*:?\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)", text, re.IGNORECASE):
        try:
            found.append(float(m.group(1).replace(",", "")))
        except ValueError:
            pass
    # Number followed by "INR" or "Rupees"
    for m in re.finditer(r"([0-9][0-9,]*(?:\.[0-9]{1,2})?)\s*(?:INR|rupees)", text, re.IGNORECASE):
        try:
            found.append(float(m.group(1).replace(",", "")))
        except ValueError:
            pass
    return found


def _extract_utr(text: str) -> str:
    labelled = re.findall(
        r"(?:UTR|U\.T\.R|RRN|Ref(?:erence)?(?:\.?\s*(?:No|Number|ID|Txn))?|Bank\s*Ref|Txn\.?\s*(?:ID|Ref)?|Reference\s*Number)\s*[:\-#]?\s*([0-9A-Za-z]{8,22})",
        text, re.IGNORECASE,
    )
    for cand in labelled:
        digits = security.clean_utr(cand)
        if len(digits) >= 8 and any(ch.isdigit() for ch in digits):
            return digits
    plain = re.findall(r"\b\d{12}\b", text)
    if plain:
        return plain[0]
    return ""


def _email_text(msg: email.message.Message) -> str:
    chunks: List[str] = []
    try:
        subject = _decode_mime(msg.get("Subject", ""))
        sender = _decode_mime(msg.get("From", ""))
        chunks.append(subject)
        chunks.append(sender)
    except Exception:
        pass
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ctype = (part.get_content_type() or "").lower()
                if ctype in ("text/plain", "text/html"):
                    payload = part.get_payload(decode=True)
                    if payload:
                        chunks.append(payload.decode(part.get_content_charset() or "utf-8", errors="ignore"))
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                chunks.append(payload.decode(msg.get_content_charset() or "utf-8", errors="ignore"))
    except Exception:
        pass
    text = " ".join(chunks)
    # strip tags for html bodies
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text)


def _match_and_settle(merchant_id: int, provider: str, amount: float, utr: str, payer_name: str, since_ts: int, received_at: Optional[int] = None) -> Optional[str]:
    """Try to settle a pending order for this merchant. Returns order_id if settled."""
    utr = clean_utr(utr)
    if utr and db.is_utr_used(utr):
        return None
    order = db.find_pending_match(merchant_id, amount, since_ts)
    if not order:
        return None
    if received_at is not None and (int(order['created_at']) > received_at or int(order['expires_at']) < received_at):
        return None
    order_id = order["id"]
    if db.mark_order_paid(order_id, utr, payer_name):
        if utr:
            db.mark_utr_used(utr, order_id, merchant_id, float(order["exact_amount"]), payer_name)
        settle_post_actions(merchant_id, order_id, provider, float(order["exact_amount"]), utr, payer_name,
                            order["customer_email"] or "", order["customer_name"] or "")
        return order_id
    return None


def settle_post_actions(merchant_id: int, order_id: str, provider: str, amount: float, utr: str,
                        payer_name: str, customer_email: str, customer_name: str) -> None:
    order = db.get_order(order_id)
    business = ""
    with db.connect() as conn:
        r = conn.execute("SELECT business_name FROM merchants WHERE id=?", (merchant_id,)).fetchone()
        business = r["business_name"] if r else ""
    payload = {
        "event": "payment.verified",
        "order_id": order_id,
        "merchant_id": merchant_id,
        "provider": provider,
        "amount": round(amount, 2),
        "currency": "INR",
        "utr": utr,
        "payer_name": payer_name,
        "client_ref": order["client_ref"] if order else "",
        "note": order["note"] if order else "",
        "customer_name": customer_name,
        "customer_email": customer_email,
        "paid_at": int(time.time()),
    }
    fire_webhook(merchant_id, order_id, payload)
    if customer_email:
        mailer.send_payment_receipt(customer_email, business or "FamGate merchant", amount, order_id, utr)


def fire_webhook(merchant_id: int, order_id: str, payload: Dict[str, Any], event: str = "payment.verified") -> Dict[str, Any]:
    wh = db.get_webhook(merchant_id)
    url = (wh["url"] if wh else "") or ""
    if not url:
        return {"sent": False, "detail": "No webhook URL configured"}
    ok, reason = security.webhook_url_allowed(url)
    if not ok:
        db.log_webhook_delivery(merchant_id, order_id, url, event, 0, False, f"blocked: {reason}")
        return {"sent": False, "detail": f"blocked: {reason}"}
    secret = security.decrypt_secret(wh["secret_enc"]) if wh and wh["secret_enc"] else ""
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "FamGate-Webhooks/1.0",
        "X-FamGate-Event": event,
    }
    if secret:
        headers["X-FamGate-Signature"] = "sha256=" + security.hmac_sha256_hex(secret, body)
    try:
        resp = requests.post(url, data=body, headers=headers, timeout=HTTP_TIMEOUT, allow_redirects=False)
        snippet = (resp.text or "")[:300]
        success = 200 <= resp.status_code < 300
        db.log_webhook_delivery(merchant_id, order_id, url, event, resp.status_code, success, snippet)
        return {"sent": success, "status_code": resp.status_code, "detail": snippet[:120]}
    except Exception as e:
        db.log_webhook_delivery(merchant_id, order_id, url, event, 0, False, f"error: {e}"[:300])
        return {"sent": False, "detail": str(e)[:200]}


# ------------------------------------------------------------------ FamPay IMAP

def check_fampay_imap(settings) -> Dict[str, Any]:
    """Poll one merchant's Gmail for FamPay payment confirmations. Returns a small report."""
    report = {"provider": "fampay", "merchant_id": settings["merchant_id"], "settled": [], "errors": []}
    app_pw = security.decrypt_secret(settings["fampay_app_password_enc"])
    email_addr = (settings["fampay_email"] or "").strip()
    if not email_addr or not app_pw:
        report["errors"].append("FamPay IMAP not fully configured")
        return report
    host = (settings["imap_host"] or "imap.gmail.com").strip()
    port = int(settings["imap_port"] or 993)
    folder = (settings["imap_folder"] or "INBOX").strip()
    since_ts = int(time.time()) - 2 * 3600  # only match recent orders

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(host, port, timeout=15)
        imap.login(email_addr, app_pw)
        typ, _ = imap.select(folder, readonly=True)
        if typ != 'OK':
            raise RuntimeError('Unable to open the configured mail folder')
        sender = 'no-reply@famapp.in'
        typ, data = imap.uid('search', None, 'FROM', '"'+sender+'"')
        if typ != 'OK':
            raise RuntimeError('Unable to search payment emails')
        ids = data[0].split() if data and data[0] else []
        accepted = 0
        for num in sorted(ids, key=int, reverse=True):
            if accepted >= 5:
                break
            try:
                # Inspect sender headers before downloading any message body.
                typ, headers = imap.uid('fetch', num, '(BODY.PEEK[HEADER.FIELDS (FROM)])')
                if typ != 'OK' or not headers:
                    continue
                raw_header = next((part[1] for part in headers if isinstance(part, tuple)), None)
                if not raw_header:
                    continue
                header_msg = email.message_from_bytes(raw_header)
                senders = [addr.lower().strip() for _, addr in getaddresses(header_msg.get_all('From', []))]
                if senders != [sender]:
                    continue
                accepted += 1
                typ, msg_data = imap.uid('fetch', num, '(INTERNALDATE BODY.PEEK[])')
                if typ != 'OK' or not msg_data:
                    continue
                item = next((part for part in msg_data if isinstance(part, tuple)), None)
                if not item or not item[1]:
                    continue
                received = imaplib.Internaldate2tuple(item[0])
                if received is None:
                    continue  # Never match an undated email to a new order.
                received_at = int(time.mktime(received))
                msg = email.message_from_bytes(item[1])
                if [a.lower().strip() for _, a in getaddresses(msg.get_all('From', []))] != [sender]:
                    continue
                text = _email_text(msg)
                if not any(k in text.lower() for k in FAMPAY_KEYWORDS):
                    continue
                amounts = _extract_amounts(text)
                utr = _extract_utr(text)
                if not utr:
                    continue
                for amount in amounts:
                    settled = _match_and_settle(settings['merchant_id'], 'fampay', amount, utr, '', since_ts, received_at=received_at)
                    if settled:
                        report['settled'].append(settled)
                        break
            except Exception as e:
                report['errors'].append(f'message parse error: {e}'[:120])
        try:
            imap.logout()
        except Exception:
            pass
    except imaplib.IMAP4.error as e:
        report["errors"].append(f"IMAP auth/connection failed: {e}"[:150])
    except Exception as e:
        report["errors"].append(f"IMAP error: {e}"[:150])
    finally:
        try:
            if imap is not None:
                imap.shutdown()
        except Exception:
            pass
    return report


def test_fampay_connection(settings) -> tuple:
    app_pw = security.decrypt_secret(settings["fampay_app_password_enc"])
    return test_imap_login(
        (settings["fampay_email"] or "").strip(),
        app_pw or "",
        (settings["imap_host"] or "imap.gmail.com").strip(),
        int(settings["imap_port"] or 993),
        (settings["imap_folder"] or "INBOX").strip(),
    )


def test_imap_login(email_addr: str, app_password: str, host: str = "imap.gmail.com",
                    port: int = 993, folder: str = "INBOX") -> tuple:
    """IMAP login probe with EXPLICIT credentials — tests what the user just typed."""
    if not email_addr or not app_password:
        return False, "Enter both the Gmail address and the 16-char app password."
    try:
        imap = imaplib.IMAP4_SSL(host, int(port), timeout=12)
        imap.login(email_addr, app_password)
        typ, data = imap.select(folder, readonly=True)
        if typ != "OK":
            imap.logout()
            return False, f"Connected to {host}, but could not open mailbox folder {folder}. Check the folder name."
        try:
            # imaplib returns byte strings, e.g. b'523'; str(bytes) is not numeric.
            count = int(data[0]) if data and data[0] is not None else None
            if count is not None and count < 0:
                count = None
        except (ValueError, TypeError):
            count = None
        imap.logout()
        if count is None:
            return False, f"Connected to {host}, but the message count for {folder} could not be read. Please retry."
        return True, f"Connected to {host} — {folder} has {count} messages (selected folder, not total Gmail storage)."
    except imaplib.IMAP4.error as e:
        return False, f"Gmail rejected the login: {e}. Use a 16-char App Password (not your normal password)."
    except Exception as e:
        return False, f"Could not connect: {e}"


# ------------------------------------------------------------------ BharatPe enterprise feed

def fetch_bharatpe_transactions(mid_value: str, token: str, force: bool = False) -> List[Dict[str, Any]]:
    now = time.time()
    cache_key = hash((mid_value, token[-12:] if token else ""))
    with _cache_lock:
        cached = _cache.get(cache_key)
        if cached and not force and (now - cached["at"] < CACHE_TTL):
            return cached["txns"]

    now_ms = int(now * 1000)
    s_date = now_ms - 48 * 3600 * 1000
    e_date = now_ms + 3600 * 1000
    url = (
        f"{BHARATPE_FEED}?module=PAYMENT_QR&merchantId={mid_value}"
        f"&sDate={s_date}&eDate={e_date}&pageSize=30&pageCount=0&isFromOtDashboard=1"
    )
    headers = {
        "token": token,
        "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X)",
        "origin": "https://enterprise.bharatpe.in",
        "referer": "https://enterprise.bharatpe.in/",
        "accept": "application/json, text/javascript, */*; q=0.01",
    }
    txns: List[Dict[str, Any]] = []
    try:
        r = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            payload = r.json()
            if payload.get("status"):
                txns = (payload.get("data") or {}).get("transactions") or []
            else:
                raise RuntimeError(payload.get("message") or "BharatPe rejected the request")
        else:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:160]}")
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"Network error talking to BharatPe: {e}")

    with _cache_lock:
        _cache[cache_key] = {"at": now, "txns": txns}
    return txns


def check_bharatpe(settings) -> Dict[str, Any]:
    report = {"provider": "bharatpe", "merchant_id": settings["merchant_id"], "settled": [], "errors": []}
    mid_value = (settings["bharatpe_mid"] or "").strip()
    token = security.decrypt_secret(settings["bharatpe_token_enc"])
    if not mid_value or not token:
        report["errors"].append("BharatPe Merchant ID / token not configured")
        return report
    since_ts = int(time.time()) - 2 * 3600
    try:
        txns = fetch_bharatpe_transactions(mid_value, token)
    except RuntimeError as e:
        report["errors"].append(str(e))
        return report
    for t in txns:
        try:
            status = str(t.get("status") or "").upper()
            if status != "SUCCESS":
                continue
            amount = float(t.get("amount") or 0)
            utr = security.clean_utr(t.get("bankReferenceNo") or t.get("internalUtr") or "")
            payer = str(t.get("payerName") or "").strip()
            settled = _match_and_settle(settings["merchant_id"], "bharatpe", amount, utr, payer, since_ts)
            if settled:
                report["settled"].append(settled)
        except Exception as e:
            report["errors"].append(f"txn parse error: {e}"[:120])
    return report


def test_bharatpe_connection(settings) -> tuple:
    mid_value = (settings["bharatpe_mid"] or "").strip()
    token = security.decrypt_secret(settings["bharatpe_token_enc"])
    return test_bharatpe_token(mid_value, token or "")


def test_bharatpe_token(mid_value: str, token: str) -> tuple:
    """BharatPe feed probe with EXPLICIT credentials — tests what the user just typed."""
    mid_value = (mid_value or "").strip()
    token = token or ""
    if not mid_value or not token:
        return False, "Enter both Merchant ID and API token."
    try:
        txns = fetch_bharatpe_transactions(mid_value, token, force=True)
        return True, f"BharatPe answered OK — {len(txns)} transaction(s) in the recent feed."
    except RuntimeError as e:
        return False, str(e)


def settle_via_callback(provider: str, provider_ref: str, utr: str, amount, event: str = "payment.verified",
                        order=None) -> Dict[str, Any]:
    """Called by /webhooks/<provider> after signature verification.

    The callback handler passes the order it already resolved; provider_ref resolution is a fallback."""
    if order is None:
        order = db.get_order_by_provider_ref(provider, provider_ref)
    merchant_id = order["merchant_id"]
    amount = float(order["exact_amount"])
    utr = security.clean_utr(utr) or f"{provider[:2].upper()}{order['id'][-10:]}"
    if db.is_utr_used(utr):
        return {"matched": True, "detail": "already settled", "order_id": order["id"], "duplicate": True}
    payer = ""
    if db.mark_order_paid(order["id"], utr, payer):
        db.mark_utr_used(utr, order["id"], merchant_id, amount, payer)
        settle_post_actions(merchant_id, order["id"], provider, amount, utr, payer,
                            order["customer_email"] or "", order["customer_name"] or "")
        db.log_webhook_delivery(merchant_id, order["id"], f"inbound:{provider}", event, 200, True, f"callback settled {order['id']}")
        return {"matched": True, "order_id": order["id"], "detail": "settled"}
    return {"matched": True, "order_id": order["id"], "detail": "already settled"}


# ------------------------------------------------------------------ official gateways (poll)

_pg_last: Dict[str, float] = {}


def check_pg_provider(merchant_id: int, provider_name: str) -> Dict[str, Any]:
    """Poll an official gateways's status API for pending orders of this merchant+provider."""
    report = {"provider": provider_name, "merchant_id": merchant_id, "settled": [], "errors": []}
    try:
        import providers as pg

        creds = db.get_provider_credentials(merchant_id)
        entry = creds.get(provider_name) or {}
        if not entry.get("enabled"):
            report["errors"].append("provider not enabled")
            return report
        adapter = pg.make(provider_name, entry.get("config") or {})
        if adapter is None:
            report["errors"].append("unknown provider")
            return report
        with db.connect() as conn:
            pending = conn.execute(
                "SELECT * FROM orders WHERE merchant_id=? AND provider=? AND status='PENDING' AND expires_at>? ORDER BY created_at ASC LIMIT 10",
                (merchant_id, provider_name, int(time.time()) - 3600),
            ).fetchall()
        for order in pending:
            try:
                state, utr, payer, detail = adapter.fetch_status(order)
                if state == "PAID":
                    utr = security.clean_utr(utr) or f"{provider_name[:2].upper()}{order['id'][-10:]}"
                    if db.is_utr_used(utr):
                        continue
                    if db.mark_order_paid(order["id"], utr, payer or f"{adapter.title} customer"):
                        db.mark_utr_used(utr, order["id"], merchant_id, float(order["exact_amount"]), payer or "")
                        settle_post_actions(merchant_id, order["id"], provider_name, float(order["exact_amount"]),
                                            utr, payer or "", order["customer_email"] or "", order["customer_name"] or "")
                        report["settled"].append(order["id"])
            except Exception as e:
                report["errors"].append(f"{order['id']}: {e}"[:150])
    except Exception as e:
        report["errors"].append(str(e)[:150])
    return report


def verify_pg_on_demand(merchant_id: int, provider_name: str, order_id: str = "") -> None:
    now = time.time()
    key = f"pg:{provider_name}:{merchant_id}"
    if now - _pg_last.get(key, 0.0) < 5:
        return
    _pg_last[key] = now
    check_pg_provider(merchant_id, provider_name)


# ------------------------------------------------------------------ on-demand (checkout poll)

_on_demand_last: Dict[str, float] = {}


def verify_on_demand(merchant_id: int, provider: str) -> None:
    """Throttle-friendly provider scan triggered by checkout status polls."""
    try:
        import providers as pg
        if pg.is_pg_provider(provider):
            verify_pg_on_demand(merchant_id, provider)
            return
    except Exception:
        pass
    now = time.time()
    throttle = 15 if provider == "fampay" else 5
    key = f"{provider}:{merchant_id}"
    last = _on_demand_last.get(key, 0.0)
    if now - last < throttle:
        return
    _on_demand_last[key] = now
    try:
        with db.connect() as conn:
            row = conn.execute("SELECT * FROM merchant_settings WHERE merchant_id=?", (merchant_id,)).fetchone()
        if not row:
            return
        if provider == "fampay" and row["fampay_enabled"]:
            check_fampay_imap(row)
        elif provider == "bharatpe" and row["bharatpe_enabled"]:
            check_bharatpe(row)
    except Exception:
        pass


# ------------------------------------------------------------------ background loop

_poll_thread: Optional[threading.Thread] = None
_stop = threading.Event()


def _loop(interval: int) -> None:
    while not _stop.is_set():
        try:
            db.expire_old_orders()
            for settings in db.all_provider_settings():
                try:
                    if settings["fampay_enabled"]:
                        check_fampay_imap(settings)
                except Exception:
                    pass
                try:
                    if settings["bharatpe_enabled"]:
                        check_bharatpe(settings)
                except Exception:
                    pass
            # official gateways: light background sweep every ~60s (they mostly rely on callbacks)
            now2 = time.time()
            if now2 - getattr(_loop, "_pg_last_sweep", 0) > 60:
                _loop._pg_last_sweep = now2
                try:
                    with db.connect() as conn:
                        rows = conn.execute("SELECT DISTINCT merchant_id, provider FROM provider_credentials WHERE enabled=1").fetchall()
                    for r in rows:
                        try:
                            check_pg_provider(r["merchant_id"], r["provider"])
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass
        _stop.wait(interval)


def start(interval: int = None) -> threading.Thread:
    global _poll_thread
    if interval is None:
        interval = int(__import__("os").environ.get("FAMGATE_POLL_SECONDS", "8"))
    if _poll_thread and _poll_thread.is_alive():
        return _poll_thread
    _stop.clear()
    _poll_thread = threading.Thread(target=_loop, args=(max(3, interval),), daemon=True, name="famgate-verifier")
    _poll_thread.start()
    return _poll_thread
