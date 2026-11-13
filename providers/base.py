# -*- coding: utf-8 -*-
"""Base contract for official-gateway adapters (Razorpay, PhonePe, Paytm, Cashfree).

Every adapter gets the merchant's decrypted credential dict and must implement:
  test_connection()   -> (ok: bool, message: str)
  create_payment()    -> PGResult
  fetch_status()      -> (state, utr, payer) where state in {PAID, PENDING, ERROR}
  verify_callback()   -> normalized dict or None   (called by /webhooks/<provider>)
"""
import json
from typing import Any, Dict, Optional

import requests

HTTP_TIMEOUT = 12


class PGResult:
    def __init__(self, ok: bool, payment_url: str = "", provider_ref: str = "",
                 provider_token: str = "", error: str = "", raw: Any = None):
        self.ok = ok
        self.payment_url = payment_url
        self.provider_ref = provider_ref
        self.provider_token = provider_token
        self.error = error
        self.raw = raw


class BaseProvider:
    name = "base"
    title = "Provider"
    icon = "💳"
    required_fields = ()
    field_help: Dict[str, str] = {}
    cta_note = ""

    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg or {}

    # -- helpers --
    def missing_fields(self):
        return [f for f in self.required_fields if not str(self.cfg.get(f) or "").strip()]

    def amount_paise(self, order) -> int:
        return int(round(float(order["exact_amount"]) * 100))

    @staticmethod
    def _post_json(url, payload, headers=None, timeout=HTTP_TIMEOUT, auth=None):
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if headers:
            h.update(headers)
        r = requests.post(url, data=json.dumps(payload, separators=(",", ":")), headers=h, timeout=timeout, auth=auth)
        try:
            body = r.json()
        except Exception:
            body = {"_raw": r.text[:400]}
        return r.status_code, body

    @staticmethod
    def _get_json(url, headers=None, timeout=HTTP_TIMEOUT, auth=None):
        h = {"Accept": "application/json"}
        if headers:
            h.update(headers)
        r = requests.get(url, headers=h, timeout=timeout, auth=auth)
        try:
            body = r.json()
        except Exception:
            body = {"_raw": r.text[:400]}
        return r.status_code, body

    # -- interface --
    def test_connection(self):
        raise NotImplementedError

    def create_payment(self, order, base_url: str) -> PGResult:
        raise NotImplementedError

    def fetch_status(self, order):
        """Returns ('PAID'|'PENDING'|'ERROR', utr: str, payer: str, detail: str)."""
        raise NotImplementedError

    @staticmethod
    def verify_callback(headers: Dict[str, str], raw_body: bytes, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return {'provider_ref': str, 'utr': str, 'amount': float|None, 'ok': bool} or None."""
        raise NotImplementedError
