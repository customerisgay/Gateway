# -*- coding: utf-8 -*-
"""Cashfree Payment Gateway — Payment Links API (server-to-server, redirect flow).

Sandbox : https://sandbox.cashfree.com/pg
Production: https://api.cashfree.com/pg
Webhook : x-webhook-signature = base64(HMAC-SHA256(x-webhook-timestamp + rawBody, webhook_secret))
"""
import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional

from providers.base import BaseProvider, PGResult

API_VERSION = "2023-08-01"


class CashfreeProvider(BaseProvider):
    name = "cashfree"
    title = "Cashfree"
    icon = "💸"
    required_fields = ("app_id", "secret_key")
    field_help = {
        "app_id": "Cashfree dashboard → Developers → API Keys → App ID (TEST_… / PROD_…)",
        "secret_key": "Same screen → Secret Key",
        "webhook_secret": "Cashfree dashboard → Developers → Webhooks → secret (defaults to Secret Key if blank)",
        "env": "sandbox = test mode · production = live money",
    }
    cta_note = "Accepts UPI (GPay, PhonePe, MobiKwik, BHIM…), cards, netbanking, Paytm UPI handles"

    def _base(self) -> str:
        if str(self.cfg.get("env") or "sandbox") == "production":
            return "https://api.cashfree.com/pg"
        return "https://sandbox.cashfree.com/pg"

    def _headers(self) -> Dict[str, str]:
        return {
            "x-client-id": self.cfg.get("app_id", "").strip(),
            "x-client-secret": self.cfg.get("secret_key", "").strip(),
            "x-api-version": API_VERSION,
        }

    def test_connection(self):
        if self.missing_fields():
            return False, "Fill in App ID and Secret Key."
        try:
            code, body = self._get_json(f"{self._base()}/links?limit=1", headers=self._headers())
        except Exception as e:
            return False, f"Network error: {e}"
        if code == 200:
            return True, f"Cashfree accepted the keys ({self.cfg.get('env', 'sandbox')}) — connection OK."
        if code in (401, 403):
            return False, "Cashfree rejected the keys. Use the App ID/Secret from API Keys (not client-side tokens)."
        return False, f"Unexpected response HTTP {code}: {str(body)[:160]}"

    def create_payment(self, order, base_url: str) -> PGResult:
        if self.missing_fields():
            return PGResult(False, error="Cashfree is not fully configured (app_id / secret_key missing).")
        link_id = "".join(ch for ch in order["id"] if ch.isalnum() or ch in "_-")[:40]
        phone = "9999999999"  # Cashfree mandates a customer phone on links
        payload = {
            "link_id": link_id,
            "link_amount": round(float(order["exact_amount"]), 2),
            "link_currency": "INR",
            "link_purpose": (order["note"] or f"Payment {order['id']}")[:250],
            "customer_details": {
                "customer_name": (order["customer_name"] or "Customer")[:90],
                "customer_email": order["customer_email"] or "customer@famgate.in",
                "customer_phone": phone,
            },
            "link_meta": {"return_url": f"{base_url}/pay/{order['id']}", "notify_url": f"{base_url}/webhooks/cashfree"},
            "link_expiry_time": time.strftime("%Y-%m-%dT%H:%M:%S+05:30", time.gmtime(int(order["expires_at"]) + 19800)),
            "link_notify": {"send_sms": False, "send_email": bool(order["customer_email"])},
        }
        try:
            code, body = self._post_json(f"{self._base()}/links", payload, headers=self._headers())
        except Exception as e:
            return PGResult(False, error=f"Cashfree network error: {e}")
        if code in (200, 201):
            url = body.get("link_url") or ""
            if url:
                return PGResult(True, payment_url=url, provider_ref=link_id, raw=body)
            return PGResult(False, error="Cashfree response missing link_url.", raw=body)
        msg = body.get("message") or body.get("error") or str(body)[:200]
        return PGResult(False, error=f"Cashfree error HTTP {code}: {msg}", raw=body)

    def fetch_status(self, order):
        ref = order["provider_ref"]
        if not ref:
            return "ERROR", "", "", "No Cashfree link id stored."
        try:
            code, body = self._get_json(f"{self._base()}/links/{ref}", headers=self._headers())
        except Exception as e:
            return "ERROR", "", "", f"Network error: {e}"
        if code != 200:
            return "ERROR", "", "", f"HTTP {code}: {str(body)[:160]}"
        status = str(body.get("link_status") or "").upper()
        if status == "PAID":
            utr = str(body.get("cf_link_id") or ref)
            try:  # fetch payments for the real bank reference
                pc, pays = self._get_json(f"{self._base()}/links/{ref}/payments", headers=self._headers())
                if pc == 200 and isinstance(pays, list) and pays:
                    p0 = pays[0]
                    utr = str(p0.get("bank_reference") or p0.get("cf_payment_id") or utr)
            except Exception:
                pass
            return "PAID", utr, "", "paid"
        return "PENDING", "", "", f"link_status={status or 'unknown'}"

    @staticmethod
    def peek_ref(headers: Dict[str, str], raw_body: bytes) -> str:
        try:
            data = json.loads(raw_body.decode("utf-8"))
        except Exception:
            return ""
        inner = data.get("data") or {}
        order_obj = inner.get("order") or inner.get("link") or {}
        return str(order_obj.get("order_id") or order_obj.get("link_id")
                   or inner.get("link_id") or inner.get("order_id") or "")

    @staticmethod
    def verify_callback(headers: Dict[str, str], raw_body: bytes, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        secret = (cfg.get("webhook_secret") or cfg.get("secret_key") or "").strip()
        ts = (headers.get("x-webhook-timestamp") or "").strip()
        sig = (headers.get("x-webhook-signature") or "").strip()
        if not secret or not ts or not sig:
            return None
        digest = base64.b64encode(hmac.new(secret.encode(), (ts + raw_body.decode("utf-8")).encode(), hashlib.sha256).digest()).decode()
        if not hmac.compare_digest(digest, sig):
            return None
        try:
            data = json.loads(raw_body.decode("utf-8"))
        except Exception:
            return None
        event = str(data.get("type") or data.get("event") or "").upper()
        inner = data.get("data") or {}
        order_obj = inner.get("order") or inner.get("link") or {}
        payment_obj = inner.get("payment") or {}
        ref = (
            order_obj.get("order_id") or order_obj.get("link_id")
            or inner.get("link_id") or inner.get("order_id")
            or payment_obj.get("cf_order_id") or ""
        )
        ok = ("SUCCESS" in event) or str(order_obj.get("order_status") or order_obj.get("link_status") or "").upper() in ("PAID", "SUCCESS")
        amount = None
        try:
            amount = float(order_obj.get("order_amount") or order_obj.get("link_amount") or payment_obj.get("payment_amount") or 0)
        except (TypeError, ValueError):
            amount = None
        return {"provider_ref": str(ref), "utr": str(payment_obj.get("bank_reference") or payment_obj.get("cf_payment_id") or ref), "amount": amount, "ok": ok}
