# -*- coding: utf-8 -*-
"""Razorpay — Payment Links API (perfect for server-side gateway flow).
Docs: POST https://api.razorpay.com/v1/payment_links (HTTP Basic auth key_id:key_secret)
Creates a hosted page URL (short_url) we can hand straight to the customer.
"""
import hashlib
import hmac
import json
from typing import Any, Dict, Optional

from providers.base import BaseProvider, PGResult

API = "https://api.razorpay.com/v1"


class RazorpayProvider(BaseProvider):
    name = "razorpay"
    title = "Razorpay"
    icon = "⚡"
    required_fields = ("key_id", "key_secret")
    field_help = {
        "key_id": "Dashboard → Settings → API Keys → Key ID (rzp_test_… / rzp_live_…)",
        "key_secret": "Same screen → Key Secret (shown once at generation)",
        "webhook_secret": "Dashboard → Webhooks → the secret you set on your webhook (for payment.verified callbacks)",
    }
    cta_note = "Accepts UPI (GPay, PhonePe, MobiKwik, BHIM…), cards, netbanking, wallets"

    def _auth(self):
        return (self.cfg.get("key_id", "").strip(), self.cfg.get("key_secret", "").strip())

    def test_connection(self):
        if self.missing_fields():
            return False, "Fill in Key ID and Key Secret."
        try:
            code, body = self._get_json(f"{API}/payments?count=1", auth=self._auth())
        except Exception as e:
            return False, f"Network error: {e}"
        if code == 200:
            return True, "Razorpay accepted the keys — connection OK."
        if code in (401, 403):
            return False, "Razorpay rejected the keys (401/403). Re-copy Key ID + Secret from the dashboard."
        return False, f"Unexpected response HTTP {code}: {str(body)[:160]}"

    def create_payment(self, order, base_url: str) -> PGResult:
        if self.missing_fields():
            return PGResult(False, error="Razorpay is not fully configured (key_id / key_secret missing).")
        payload = {
            "amount": self.amount_paise(order),
            "currency": "INR",
            "accept_partial": False,
            "reference_id": order["id"],
            "description": (order["note"] or f"Payment {order['id']}")[:255],
            "expire_by": int(order["expires_at"]),
            "callback_url": f"{base_url}/webhooks/razorpay",
            "callback_method": "get",
            "notify": {"sms": False, "email": bool(order["customer_email"])},
        }
        cust = {}
        if order["customer_name"]:
            cust["name"] = order["customer_name"]
        if order["customer_email"]:
            cust["email"] = order["customer_email"]
        if cust:
            payload["customer"] = cust
        try:
            code, body = self._post_json(f"{API}/payment_links", payload, auth=self._auth(), timeout=12)
        except Exception as e:
            return PGResult(False, error=f"Razorpay network error: {e}")
        if code in (200, 201):
            url = body.get("short_url") or ""
            if url:
                return PGResult(True, payment_url=url, provider_ref=body.get("id", ""), raw=body)
            return PGResult(False, error="Razorpay response missing short_url.", raw=body)
        desc = body.get("error", {}).get("description") if isinstance(body.get("error"), dict) else str(body)[:200]
        return PGResult(False, error=f"Razorpay error HTTP {code}: {desc}", raw=body)

    def fetch_status(self, order):
        ref = order["provider_ref"]
        if not ref:
            return "ERROR", "", "", "No Razorpay reference stored on this order."
        try:
            code, body = self._get_json(f"{API}/payment_links/{ref}", auth=self._auth())
        except Exception as e:
            return "ERROR", "", "", f"Network error: {e}"
        if code != 200:
            return "ERROR", "", "", f"HTTP {code}: {str(body)[:160]}"
        status = str(body.get("status") or "").lower()
        if status == "paid":
            payments = body.get("payments") or []
            utr = ""
            if isinstance(payments, list) and payments:
                first = payments[0]
                utr = (first.get("payment_id") if isinstance(first, dict) else "") or ""
            return "PAID", utr or ref, "", "paid"
        return "PENDING", "", "", f"payment_link status: {status}"

    @staticmethod
    def peek_ref(headers: Dict[str, str], raw_body: bytes) -> str:
        """Unverified extraction of the provider reference — used ONLY to locate the merchant
        whose credentials should verify the signature. Never settle on this alone."""
        try:
            data = json.loads(raw_body.decode("utf-8"))
        except Exception:
            return ""
        payload = data.get("payload") or {}
        link = (payload.get("payment_link") or {}).get("entity") or {}
        payment = (payload.get("payment") or {}).get("entity") or {}
        return str(link.get("id") or "")

    @staticmethod
    def verify_callback(headers: Dict[str, str], raw_body: bytes, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        secret = (cfg.get("webhook_secret") or cfg.get("key_secret") or "").strip()
        sig = (headers.get("x-razorpay-signature") or "").strip()
        if not secret or not sig:
            return None
        expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        try:
            data = json.loads(raw_body.decode("utf-8"))
        except Exception:
            return None
        event = str(data.get("event") or "")
        payload = data.get("payload") or {}
        link = (payload.get("payment_link") or {}).get("entity") or {}
        payment = (payload.get("payment") or {}).get("entity") or {}
        if event in ("payment_link.paid", "payment.captured"):
            return {
                "provider_ref": link.get("id") or payment.get("description") or "",
                "utr": payment.get("id") or link.get("id") or "",
                "amount": (payment.get("amount") or link.get("amount") or 0) / 100.0,
                "ok": True,
            }
        # Validly signed, but not a success event — acknowledge and ignore
        return {"provider_ref": link.get("id") or "", "utr": "", "amount": None, "ok": False}
