# -*- coding: utf-8 -*-
"""MobiKwik (Zaakpay) — Express Checkout / Webpay flow.

Staging : https://zaakstaging.zaakpay.com   (skip domain check, mode=0)
Live    : https://api.zaakpay.com           (mode=1)

Flow: our checkout page renders an auto-submitting hidden form → POST
/api/paymentTransact/V13 → Zaakpay hosts the payment page (UPI: GPay, PhonePe,
MobiKwik, BHIM + cards + netbanking). The result is POSTed (form) back to our
returnUrl = /webhooks/mobikwik, which we HMAC-verify and settle.

Checksum (both directions) = HMAC-SHA256 over non-empty params concatenated as
`key=value&` in ALPHABETICAL KEY ORDER, keyed with the merchant Secret Key.
Empty parameters are excluded.

Docs: https://developer.zaakpay.com/docs/redirect-flow , /docs/check-transaction-status-api
"""
import hashlib
import hmac
import json
import re
from typing import Any, Dict, Optional
from urllib.parse import parse_qs

from providers.base import BaseProvider, PGResult

SUCCESS_CODE = "100"


def _nvq(params: Dict[str, str]) -> str:
    """Alphabetical `key=value&` string, skipping empty values (Zaakpay checksum recipe)."""
    return "".join(f"{k}={params[k]}&" for k in sorted(params) if str(params[k]).strip() != "")


def _checksum(params: Dict[str, str], secret: str) -> str:
    return hmac.new(secret.encode(), _nvq(params).encode(), hashlib.sha256).hexdigest()


class MobikwikProvider(BaseProvider):
    name = "mobikwik"
    title = "MobiKwik (Zaakpay)"
    icon = "Ⓜ️"
    required_fields = ("merchant_identifier", "secret_key")
    field_help = {
        "merchant_identifier": "Zaakpay dashboard → Developers → Merchant Identifier",
        "secret_key": "Same screen → Secret Key (used for HMAC-SHA256 request/response checksums)",
        "env": "sandbox = staging (zaakstaging.zaakpay.com, domain check skipped) · production = live (api.zaakpay.com)",
    }
    cta_note = "Accepts MobiKwik, GPay, PhonePe, BHIM UPI, cards, netbanking (Zaakpay Express Checkout)"

    LIVE = "https://api.zaakpay.com"
    SANDBOX = "https://zaakstaging.zaakpay.com"

    def _base(self) -> str:
        return self.LIVE if str(self.cfg.get("env") or "sandbox") == "production" else self.SANDBOX

    def _mode(self) -> str:
        return "1" if str(self.cfg.get("env") or "sandbox") == "production" else "0"

    def test_connection(self):
        if self.missing_fields():
            return False, "Fill in Merchant Identifier and Secret Key."
        code, body = self._check_txn("FAMGATE_PING_TEST")
        if code == 0:
            return False, str(body.get("error"))
        low = str(body).lower()
        if code in (401, 403) or "invalid" in low and "checksum" in low:
            return False, f"Zaakpay rejected the checksum/credentials (HTTP {code}): {str(body)[:160]}"
        if isinstance(body, dict) and ("orders" in body or "merchantIdentifier" in body or "success" in body):
            return True, f"Zaakpay answered ({self.cfg.get('env', 'sandbox')}) — credentials accepted."
        return False, f"Unexpected response HTTP {code}: {str(body)[:160]}"

    def build_form(self, order, base_url: str) -> Dict[str, str]:
        """The exact parameters of the hidden Express-Checkout form (minus checksum)."""
        amount = self.amount_paise(order)
        desc = re.sub(r"[^A-Za-z0-9 ]+", " ", (order["note"] or f"Payment {order['id']}")).strip()[:100] or f"Order {order['id']}"
        first = re.sub(r"[^A-Za-z0-9 ]+", " ", order["customer_name"] or "Customer").strip()[:30] or "Customer"
        email = (order["customer_email"] or "").strip() or "customer@famgate.local"
        params = {
            "merchantIdentifier": self.cfg["merchant_identifier"].strip(),
            "orderId": order["id"][:40],
            "amount": str(amount),
            "currency": "INR",
            "buyerEmail": email,
            "buyerFirstName": first,
            "productDescription": desc,
            "returnUrl": f"{base_url}/webhooks/mobikwik",
            "txnType": "1",  # ALL payment tabs (cards, NB, wallets, UPI)
            "mode": self._mode(),
        }
        params["checksum"] = _checksum(params, self.cfg["secret_key"].strip())
        return params

    def create_payment(self, order, base_url: str) -> PGResult:
        if self.missing_fields():
            return PGResult(False, error="MobiKwik is not fully configured (merchant_identifier / secret_key missing).")
        form = self.build_form(order, base_url)
        return PGResult(True, payment_url=f"{base_url}/pay/{order['id']}",
                        provider_ref=order["id"], provider_token=json.dumps(form, separators=(",", ":")), raw=form)

    def _check_txn(self, order_id: str):
        url = f"{self._base()}/checkTxn?v=8"
        data = {"merchantIdentifier": self.cfg["merchant_identifier"].strip(),
                "mode": self._mode(),
                "orderDetail": {"orderId": order_id}}
        data_str = json.dumps(data, separators=(",", ":"))
        checksum = hmac.new(self.cfg["secret_key"].strip().encode(), data_str.encode(), hashlib.sha256).hexdigest()
        try:
            code, body = self._post_form(url, {"data": data_str, "checksum": checksum})
        except Exception as e:
            return 0, {"error": f"network error: {e}"}
        return code, body

    def _post_form(self, url: str, form: Dict[str, str]):
        import requests
        r = requests.post(url, data=form, headers={"Accept": "application/json"}, timeout=12)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"_raw": r.text[:400]}

    def fetch_status(self, order):
        if self.missing_fields():
            return "ERROR", "", "", "Not configured."
        ref = order["provider_ref"] or order["id"]
        code, body = self._check_txn(ref)
        if code == 0:
            return "ERROR", "", "", str(body.get("error", "network error"))
        if not isinstance(body, dict):
            return "ERROR", "", "", f"HTTP {code}: {str(body)[:160]}"
        orders = body.get("orders") or []
        if not orders:
            return "PENDING", "", "", "no transaction found for this order yet"
        txn = orders[0]
        inner = txn.get("orderDetail") or {}
        txn_status = str(txn.get("txnStatus") or "")
        if txn_status == "0":
            utr = str(txn.get("bankRefNum") or txn.get("authCode") or inner.get("txnId") or ref)
            mode = str((txn.get("paymentInstrument") or {}).get("paymentMode") or "")
            return "PAID", utr, mode, "success"
        if txn_status == "1":
            return "PENDING", "", "", f"failed (responseCode={txn.get('responseCode')})"
        return "PENDING", "", "", f"txnStatus={txn_status or 'unknown'}"

    @staticmethod
    def peek_ref(headers: Dict[str, str], raw_body: bytes) -> str:
        parsed = parse_qs(raw_body.decode("utf-8"))
        return str((parsed.get("orderId") or parsed.get("orderID") or parsed.get("ORDERID") or [""])[0])

    @staticmethod
    def verify_callback(headers: Dict[str, str], raw_body: bytes, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        secret = (cfg.get("secret_key") or "").strip()
        if not secret:
            return None
        parsed = parse_qs(raw_body.decode("utf-8"))
        params = {k: (v[0] if isinstance(v, list) and v else "") for k, v in parsed.items()}
        received = (params.get("checksum") or "").strip()
        if not received:
            return None
        signed = {k: v for k, v in params.items() if k != "checksum"}
        expected = _checksum(signed, secret)
        if not hmac.compare_digest(expected, received):
            return None
        code_ = str(params.get("responseCode") or "").strip()
        try:
            amount = float(params.get("amount") or 0) / 100.0
        except (TypeError, ValueError):
            amount = None
        return {
            "provider_ref": str(params.get("orderId") or ""),
            "utr": str(params.get("pgTransId") or params.get("bankRefNum") or params.get("orderId") or ""),
            "amount": amount,
            "ok": code_ == SUCCESS_CODE,
        }
