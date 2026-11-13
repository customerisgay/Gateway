# -*- coding: utf-8 -*-
"""Provider registry. Direct UPI rails: fampay (email IMAP) + bharatpe (enterprise feed).
Official merchant gateways: razorpay, phonepe, paytm, cashfree, mobikwik (Zaakpay) — KYC + sandbox/prod keys.
Every UPI app (Google Pay, PhonePe, MobiKwik, BHIM, Paytm, WhatsApp Pay, Amazon Pay) can pay
ANY rail — these are the verification engines behind them."""
from providers.base import PGResult
from providers.base import BaseProvider
import providers.base as base
from providers.mobikwik import MobikwikProvider
from providers.razorpay import RazorpayProvider
from providers.phonepe import PhonePeProvider
from providers.paytm import PaytmProvider
from providers.cashfree import CashfreeProvider

PG_PROVIDERS = {
    "razorpay": RazorpayProvider,
    "phonepe": PhonePeProvider,
    "paytm": PaytmProvider,
    "cashfree": CashfreeProvider,
    "mobikwik": MobikwikProvider,
}
DIRECT_PROVIDERS = ("fampay", "bharatpe")
ALL_PROVIDERS = DIRECT_PROVIDERS + tuple(PG_PROVIDERS)

_TITLES = {"fampay": "FamPay (QR · email verification)", "bharatpe": "BharatPe (QR · MID+token)"}
for _name, _cls in PG_PROVIDERS.items():
    _TITLES[_name] = _cls.title


def is_pg_provider(name: str) -> bool:
    return name in PG_PROVIDERS


def peek_ref(name: str, headers, raw_body: bytes) -> str:
    cls = PG_PROVIDERS.get(name)
    if not cls:
        return ""
    try:
        return cls.peek_ref(headers, raw_body)
    except Exception:
        return ""


def title_of(name: str) -> str:
    return _TITLES.get(name, name)


def make(name: str, cfg: dict):
    cls = PG_PROVIDERS.get(name)
    return cls(cfg) if cls else None


def field_specs(name: str):
    """Ordered (field_key, label, secret?, help) tuples for rendering settings forms."""
    specs = {
        "razorpay": [("key_id", "Key ID", False), ("key_secret", "Key Secret", True), ("webhook_secret", "Webhook Secret (optional)", True)],
        "phonepe": [("merchant_id", "Merchant ID", False), ("salt_key", "Salt Key", True), ("salt_index", "Salt Index", False), ("env", "Environment", False)],
        "paytm": [("mid", "Merchant ID (MID)", False), ("merchant_key", "Merchant Key (16 chars)", True), ("website", "Website (WEBSTAGING / DEFAULT)", False),
                  ("channel_id", "Channel ID (WEB)", False), ("industry_type_id", "Industry Type (Retail)", False), ("env", "Environment", False)],
        "cashfree": [("app_id", "App ID", False), ("secret_key", "Secret Key", True), ("webhook_secret", "Webhook Secret (optional)", True), ("env", "Environment", False)],
        "mobikwik": [("merchant_identifier", "Merchant Identifier", False), ("secret_key", "Secret Key", True), ("env", "Environment", False)],
    }
    return specs.get(name, [])
