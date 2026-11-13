# -*- coding: utf-8 -*-
"""PhonePe Payment Gateway (Standard Checkout) — redirect/Pay-Page flow.

Sandbox base : https://api-preprod.phonepe.com/apis/pg-sandbox
Production   : https://api.phonepe.com/apis/hermes

Public sandbox test credentials (from PhonePe docs):
  merchantId: PGTESTPAYUAT86   salt: 96434309-7796-489d-8924-ab56988a6076   saltIndex: 1
"""
import base64
import hashlib
import hmac
import json
from typing import Any, Dict, Optional

from providers.base import BaseProvider, PGResult


class PhonePeProvider(BaseProvider):
    name = "phonepe"
    title = "PhonePe PG"
    icon = "📲"
    required_fields = ("merchant_id", "salt_key", "salt_index")
    field_help = {
        "merchant_id": "PhonePe dashboard → Developer Settings → Merchant ID (current UAT: PGTESTPAYUAT86; older demos use PGTESTPAYUAT)",
        "salt_key": "Same screen → Salt Key (current UAT: 96434309-7796-489d-8924-ab56988a6076)",
        "salt_index": "Numeric salt index, usually 1",
        "env": "sandbox = UAT testing · production = live money (api.phonepe.com/apis/hermes)",
    }
    cta_note = "Accepts GPay, PhonePe, Paytm, MobiKwik, BHIM, cards, netbanking via one checkout"

    def _base(self) -> str:
        if str(self.cfg.get("env") or "sandbox") == "production":
            return "https://api.phonepe.com/apis/hermes"
        return "https://api-preprod.phonepe.com/apis/pg-sandbox"

    def _xverify(self, payload_b64: str, path: str) -> str:
        digest = hashlib.sha256((payload_b64 + path + self.cfg.get("salt_key", "").strip()).encode()).hexdigest()
        return f"{digest}###{str(self.cfg.get('salt_index') or '1').strip()}"

    def _xverify_path(self, path: str) -> str:
        digest = hashlib.sha256((path + self.cfg.get("salt_key", "").strip()).encode()).hexdigest()
        return f"{digest}###{str(self.cfg.get('salt_index') or '1').strip()}"

    def test_connection(self):
        if self.missing_fields():
            return False, "Fill in Merchant ID, Salt Key and Salt Index."
        # Status call for a non-existent txn — PhonePe returns a structured JSON answer
        path = f"/pg/v1/status/{self.cfg['merchant_id'].strip()}/FAMGATE_PING_0001"
        try:
            code, body = self._get_json(f"{self._base()}{path}", headers={"X-VERIFY": self._xverify_path(path)})
        except Exception as e:
            return False, f"Network error: {e}"
        raw = str(body)
        low = raw.lower()
        if code in (401, 403) or "checksum" in low or "invalid merchant" in low:
            return False, f"PhonePe rejected the checksum/credentials (HTTP {code}): {raw[:160]}"
        if code == 200 and isinstance(body, dict):
            return True, f"PhonePe answered (sandbox={self.cfg.get('env', 'sandbox')}) — credentials look valid. {body.get('message', '')}"
        return False, f"Unexpected response HTTP {code}: {raw[:160]}"

    def create_payment(self, order, base_url: str) -> PGResult:
        if self.missing_fields():
            return PGResult(False, error="PhonePe is not fully configured (merchant_id / salt_key / salt_index missing).")
        txn_id = order["id"][:38]
        payload = {
            "merchantId": self.cfg["merchant_id"].strip(),
            "merchantTransactionId": txn_id,
            "merchantUserId": f"U{order['merchant_id']}",
            "amount": self.amount_paise(order),
            "redirectUrl": f"{base_url}/pay/{order['id']}",
            "redirectMode": "REDIRECT",
            "callbackUrl": f"{base_url}/webhooks/phonepe",
            "paymentInstrument": {"type": "PAY_PAGE"},
        }
        if order["customer_name"]:
            payload["name"] = order["customer_name"][:100]
        if order["customer_email"]:
            payload["customerId"] = order["customer_email"][:64]
        b64 = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
        try:
            code, body = self._post_json(
                f"{self._base()}/pg/v1/pay",
                {"request": b64},
                headers={"X-VERIFY": self._xverify(b64, "/pg/v1/pay")},
            )
        except Exception as e:
            return PGResult(False, error=f"PhonePe network error: {e}")
        if code == 200 and body.get("success"):
            try:
                url = body["data"]["instrumentResponse"]["redirectInfo"]["url"]
                return PGResult(True, payment_url=url, provider_ref=txn_id, raw=body)
            except (KeyError, TypeError):
                return PGResult(False, error="PhonePe response missing redirect URL.", raw=body)
        msg = body.get("message") if isinstance(body, dict) else str(body)[:200]
        return PGResult(False, error=f"PhonePe error HTTP {code}: {msg}", raw=body)

    def fetch_status(self, order):
        if self.missing_fields():
            return "ERROR", "", "", "Not configured."
        ref = order["provider_ref"] or order["id"][:38]
        path = f"/pg/v1/status/{self.cfg['merchant_id'].strip()}/{ref}"
        try:
            code, body = self._get_json(f"{self._base()}{path}", headers={"X-VERIFY": self._xverify_path(path)})
        except Exception as e:
            return "ERROR", "", "", f"Network error: {e}"
        if code != 200:
            return "ERROR", "", "", f"HTTP {code}: {str(body)[:160]}"
        data = body.get("data") or {}
        envelope_code = str(body.get("code") or "").upper()
        state = str((data or {}).get("state") or "").upper()
        if state == "COMPLETED" or envelope_code == "PAYMENT_SUCCESS":
            return "PAID", str(data.get("transactionId") or ref), "", "completed"
        if state in ("FAILED", "TIMED_OUT"):
            return "PENDING", "", "", f"state={state}"
        return "PENDING", "", "", f"state={state or 'unknown'}"

    @staticmethod
    def peek_ref(headers: Dict[str, str], raw_body: bytes) -> str:
        try:
            parsed = json.loads(raw_body.decode("utf-8"))
            b64 = parsed.get("response", "")
        except Exception:
            from urllib.parse import parse_qs
            qs = parse_qs(raw_body.decode("utf-8"))
            b64 = (qs.get("response") or [""])[0]
        if not b64:
            return ""
        try:
            data = json.loads(base64.b64decode(b64).decode("utf-8"))
            return str((data.get("data") or {}).get("merchantTransactionId") or "")
        except Exception:
            return ""

    @staticmethod
    def verify_callback(headers: Dict[str, str], raw_body: bytes, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        salt = (cfg.get("salt_key") or "").strip()
        index = str(cfg.get("salt_index") or "1").strip()
        xv = (headers.get("x-verify") or "").strip()
        if not salt or not xv:
            return None
        # PhonePe posts {"response": "<base64>"} possibly form-encoded
        b64 = ""
        try:
            parsed = json.loads(raw_body.decode("utf-8"))
            b64 = parsed.get("response", "")
        except Exception:
            from urllib.parse import parse_qs
            qs = parse_qs(raw_body.decode("utf-8"))
            b64 = (qs.get("response") or [""])[0]
        if not b64:
            return None
        expected = hashlib.sha256((b64 + salt).encode()).hexdigest() + "###" + index
        if not hmac.compare_digest(expected, xv):
            return None
        try:
            data = json.loads(base64.b64decode(b64).decode("utf-8"))
        except Exception:
            return None
        inner = data.get("data") or {}
        state = str(inner.get("state") or data.get("code") or "").upper()
        ok = state == "COMPLETED" or str(data.get("code") or "").upper() == "PAYMENT_SUCCESS"
        return {
            "provider_ref": inner.get("merchantTransactionId") or "",
            "utr": str(inner.get("transactionId") or ""),
            "amount": (float(inner.get("amount") or 0)) / 100.0,
            "ok": ok,
        }
