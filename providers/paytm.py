# -*- coding: utf-8 -*-
"""Paytm Payment Gateway — All-in-One SDK (initiateTransaction → txnToken → JS checkout).

Staging host : https://securegw-stg.paytm.in   (website WEBSTAGING)
Production   : https://securegw.paytm.in        (website DEFAULT)

Flow: server → initiateTransaction (signed with merchant key) → txnToken → the hosted
checkout page /pay/<order_id> renders Paytm's JS with the token. Paytm calls back to
/webhooks/paytm (application/x-www-form-urlencoded) — we checksum-verify, settle, redirect.
"""
import json
import re
from typing import Any, Dict, Optional

from paytmchecksum import PaytmChecksum

from providers.base import BaseProvider, PGResult


class PaytmProvider(BaseProvider):
    name = "paytm"
    title = "Paytm PG"
    icon = "💠"
    required_fields = ("mid", "merchant_key")
    field_help = {
        "mid": "Paytm dashboard → Developer Settings → Merchant ID",
        "merchant_key": "Same screen → Merchant Key (16 chars) — keep it secret",
        "website": "WEBSTAGING for testing, DEFAULT for production",
        "channel_id": "Usually WEB",
        "industry_type_id": "Usually Retail",
        "env": "staging = test · production = live money",
    }
    cta_note = "Accepts Paytm app, GPay, PhonePe, MobiKwik, BHIM, cards, netbanking, UPI"

    def _host(self) -> str:
        return "https://securegw-stg.paytm.in" if str(self.cfg.get("env") or "staging") != "production" else "https://securegw.paytm.in"

    def js_url(self) -> str:
        return f"{self._host()}/merchantpgpui/checkoutjs/merchants/{self.cfg.get('mid', '').strip()}.js"

    def _website(self) -> str:
        return (self.cfg.get("website") or ("WEBSTAGING" if str(self.cfg.get("env") or "staging") != "production" else "DEFAULT")).strip()

    def _call(self, path: str, body: Dict[str, Any]):
        body_str = json.dumps(body, separators=(",", ":"))
        try:
            sig = PaytmChecksum.generateSignatureByString(body_str, self.cfg.get("merchant_key", "").strip())
        except Exception as e:
            return 0, {"error": f"checksum error (is the merchant key 16 chars?): {e}"}
        payload = {"body": body, "head": {"signature": sig}}
        url = f"{self._host()}{path}?mid={self.cfg.get('mid', '').strip()}"
        try:
            code, resp = self._post_json(url, payload)
        except Exception as e:
            return 0, {"error": f"network error: {e}"}
        return code, resp

    def test_connection(self):
        if self.missing_fields():
            return False, "Fill in Merchant ID and Merchant Key."
        # status call with a dummy order — any structured Paytm JSON means connectivity + key accepted
        code, body = self._call("/v3/order/status", {"mid": self.cfg["mid"].strip(), "orderId": "FAMGATE_PING"})
        if code == 0:
            return False, str(body)
        head = (body or {}).get("head") or {}
        body2 = (body or {}).get("body") or {}
        rc = str(head.get("responseCode") or "")
        if code == 200 and rc:
            if rc == "01":
                return True, "Paytm accepted the merchant key — connection OK."
            msg = head.get("responseMessage") or (body2.get("resultInfo") or {}).get("resultMsg") or str(body)[:120]
            # 2006/227 = invalid MID / order not found — both prove the pipe works when MID is valid
            return True, f"Paytm answered ({rc}: {msg}) — connectivity OK. For a true credential check, create a ₹1 order."
        return False, f"Unexpected response HTTP {code}: {str(body)[:200]}"

    def create_payment(self, order, base_url: str) -> PGResult:
        if self.missing_fields():
            return PGResult(False, error="Paytm is not fully configured (mid / merchant_key missing).")
        body = {
            "requestType": "Payment",
            "mid": self.cfg["mid"].strip(),
            "websiteName": self._website(),
            "orderId": order["id"],
            "callbackUrl": f"{base_url}/webhooks/paytm",
            "channelId": (self.cfg.get("channel_id") or "WEB").strip(),
            "txnAmount": {"value": f"{float(order['exact_amount']):.2f}", "currency": "INR"},
            "industryTypeId": (self.cfg.get("industry_type_id") or "Retail").strip(),
        }
        if order["customer_email"]:
            body["email"] = order["customer_email"]
        if order["customer_name"]:
            body["custId"] = re.sub(r"[^A-Za-z0-9_@.-]", "", order["customer_email"] or f"cust_{order['merchant_id']}")[:64]
        code, resp = self._call("/theia/api/v1/initiateTransaction", body)
        if code == 0:
            return PGResult(False, error=str(resp))
        rbody = (resp or {}).get("body") or {}
        info = rbody.get("resultInfo") or {}
        token = rbody.get("txnToken") or ""
        if code == 200 and str(info.get("resultStatus", "")).upper() == "S" and token:
            # payment_url = our hosted page, which boots the Paytm JS SDK with this token
            return PGResult(True, payment_url=f"{base_url}/pay/{order['id']}", provider_ref=order["id"], provider_token=token, raw=resp)
        msg = info.get("resultMsg") or (resp or {}).get("head", {}).get("responseMessage") or str(resp)[:200]
        return PGResult(False, error=f"Paytm initiate failed ({info.get('resultCode')}): {msg}", raw=resp)

    def fetch_status(self, order):
        if self.missing_fields():
            return "ERROR", "", "", "Not configured."
        code, resp = self._call("/v3/order/status", {"mid": self.cfg["mid"].strip(), "orderId": order["provider_ref"] or order["id"]})
        if code == 0:
            return "ERROR", "", "", str(resp)
        body = (resp or {}).get("body") or {}
        info = body.get("resultInfo") or {}
        status = str(info.get("resultStatus") or "").upper()
        if status == "TXN_SUCCESS" or str(body.get("resultStatus") or "").upper() == "SUCCESS":
            utr = str(body.get("bankTxnId") or body.get("txnId") or body.get("orderId") or "")
            payer = str(body.get("paymentMode") or "")
            return "PAID", utr, payer, "success"
        return "PENDING", "", "", f"resultStatus={status or (info.get('resultMsg') or 'unknown')}"

    @staticmethod
    def peek_ref(headers: Dict[str, str], raw_body: bytes) -> str:
        from urllib.parse import parse_qs

        parsed = parse_qs(raw_body.decode("utf-8"))
        return str((parsed.get("ORDERID") or parsed.get("orderId") or [""])[0])

    @staticmethod
    def verify_callback(headers: Dict[str, str], raw_body: bytes, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        key = (cfg.get("merchant_key") or "").strip()
        if not key:
            return None
        from urllib.parse import parse_qs

        parsed = parse_qs(raw_body.decode("utf-8"))
        params = {k: (v[0] if isinstance(v, list) and v else "") for k, v in parsed.items()}
        checksum = params.get("CHECKSUMHASH") or ""
        if not checksum:
            return None
        try:
            ok = PaytmChecksum.verifySignature(dict(params), key, checksum)
        except Exception:
            return None
        if not ok:
            return None
        status = str(params.get("STATUS") or params.get("resultStatus") or "").upper()
        return {
            "provider_ref": str(params.get("ORDERID") or ""),
            "utr": str(params.get("BANKTXNID") or params.get("TXNID") or ""),
            "amount": float(params.get("TXNAMOUNT") or params.get("TXN_AMOUNT") or 0),
            "ok": status == "TXN_SUCCESS",
        }

