# -*- coding: utf-8 -*-
"""UPI intent links + collision-free decimal-offset engine + QR rendering."""
import io
import random
import urllib.parse


def build_upi_uri(vpa: str, payee_name: str, amount: float, note: str) -> str:
    params = urllib.parse.urlencode(
        {
            "pa": vpa,
            "pn": payee_name,
            "am": f"{amount:.2f}",
            "cu": "INR",
            "tn": note,
            "mode": "02",
        }
    )
    return f"upi://pay?{params}"


def app_deep_links(upi_uri: str) -> dict:
    body = upi_uri.split("?", 1)[1]
    return {
        "phonepe": f"phonepe://pay?{body}",
        "gpay": f"tez://upi/pay?{body}",
        "paytm": f"paytmmp://pay?{body}",
        "bhim": f"bhim://pay?{body}",
    }


def pick_exact_amount(base_amount: float, active_amounts: set) -> float:
    """
    Assigns unique decimal paise (0.01–0.99) to the integer rupee base so concurrent
    orders never collide during auto-verification, e.g. ₹100 -> ₹100.14.
    If decimal offsets are exhausted, falls back to a random paise in 1.01–1.99 above base.
    """
    base = max(float(base_amount), 1.0)
    base_whole = int(base)
    offsets = list(range(1, 100))
    random.shuffle(offsets)
    for off in offsets:
        candidate = round(base_whole + off / 100.0, 2)
        if candidate not in active_amounts:
            return candidate
    for extra in (random.randint(101, 199) for _ in range(50)):
        candidate = round(base_whole + extra / 100.0, 2)
        if candidate not in active_amounts:
            return candidate
    return round(base + 0.01, 2)


def qr_png_bytes(data: str, box_size: int = 9, border: int = 2) -> bytes:
    import qrcode
    from qrcode.constants import ERROR_CORRECT_M

    qr = qrcode.QRCode(error_correction=ERROR_CORRECT_M, box_size=box_size, border=border)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#111111", back_color="#FFFFFF")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
