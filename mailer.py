# -*- coding: utf-8 -*-
"""SMTP mailer. If SMTP_* env vars are missing we fall back to a logged dev mode
so the app stays fully testable locally — set real SMTP credentials in .env to go live."""
import os
import smtplib
import ssl
import time
from email.message import EmailMessage

SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "").strip() or SMTP_USER
SMTP_TLS = os.environ.get("SMTP_TLS", "1").strip().lower() not in ("0", "false", "no")
MAIL_TIMEOUT = int(os.environ.get("SMTP_TIMEOUT", "12"))

DATA_DIR = os.environ.get(
    "FAMGATE_DATA_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"),
)
OUTBOX_LOG = os.path.join(DATA_DIR, "mail_outbox.log")


def smtp_configured() -> bool:
    return bool(SMTP_HOST and SMTP_FROM)


def _log_dev_mail(to: str, subject: str, body: str) -> None:
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(OUTBOX_LOG, "a", encoding="utf-8") as f:
            f.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')}  to={to}  subject={subject}\n{body}\n")
    except Exception:
        pass


def send_email(to: str, subject: str, text: str, html: str = "") -> tuple:
    """Returns (ok: bool, detail: str)."""
    to = to.strip()
    if not to:
        return False, "No recipient"
    if not smtp_configured():
        _log_dev_mail(to, subject, text)
        return False, "SMTP not configured — email logged to data/mail_outbox.log (dev mode)"
    msg = EmailMessage()
    msg["From"] = f"FamGate <{SMTP_FROM}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    try:
        ctx = ssl.create_default_context()
        if SMTP_TLS:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=MAIL_TIMEOUT) as s:
                s.ehlo()
                s.starttls(context=ctx)
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        else:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=MAIL_TIMEOUT, context=ctx) as s:
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        return True, "sent"
    except Exception as e:
        _log_dev_mail(to, subject + "  [FAILED: " + str(e)[:120] + "]", text)
        return False, f"SMTP error: {e}"


def send_otp_email(to: str, otp: str, purpose: str = "verify your account") -> tuple:
    subject = f"FamGate — your verification code: {otp}"
    text = (
        f"Your FamGate verification code is {otp}\n\n"
        f"Use it to {purpose}. It expires in 15 minutes.\n"
        f"If you didn't request this, ignore this email."
    )
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;border:3px solid #111;border-radius:16px;overflow:hidden">
      <div style="background:#FFE500;padding:18px 24px;border-bottom:3px solid #111">
        <b style="font-size:22px">FamGate</b><span style="color:#555"> · payment gateway</span>
      </div>
      <div style="padding:24px">
        <p style="margin:0 0 8px;color:#111">Use this code to {purpose}:</p>
        <div style="font-size:34px;letter-spacing:8px;font-weight:900;background:#111;color:#FFE500;border-radius:12px;padding:14px 20px;display:inline-block">{otp}</div>
        <p style="color:#555;font-size:13px;margin-top:16px">Expires in 15 minutes. Never share this code with anyone — FamGate staff will never ask for it.</p>
      </div>
    </div>"""
    return send_email(to, subject, text, html)


def send_payment_receipt(to: str, business_name: str, amount: float, order_id: str, utr: str) -> tuple:
    subject = f"Payment received ₹{amount:.2f} — {business_name}"
    text = (
        f"Thanks! Your payment of ₹{amount:.2f} to {business_name} was received.\n"
        f"Order: {order_id}\nUTR / bank reference: {utr}\n"
    )
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;border:3px solid #111;border-radius:16px;overflow:hidden">
      <div style="background:#111;padding:18px 24px;color:#FFE500;font-size:22px;font-weight:900">Payment received ✓</div>
      <div style="padding:24px;color:#111">
        <p style="font-size:30px;font-weight:900;margin:0">₹{amount:.2f}</p>
        <p style="margin:8px 0">paid to <b>{business_name}</b></p>
        <p style="color:#555;font-size:13px">Order {order_id}<br>UTR / bank ref: {utr or '—'}</p>
      </div>
    </div>"""
    return send_email(to, subject, text, html)
