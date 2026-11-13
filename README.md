# ⚡ FamGate — FamPay & BharatPe Payment Gateway (+ Official PG Adapters)

Self-hosted, 0%-fee UPI payment gateway for **FamPay** and **BharatPe** merchant accounts — with a merchant REST API, hosted checkout pages, HMAC-signed webhooks and full auto-verification. Your customers pay you directly; FamGate tells you when money lands. Since v2, it also orchestrates official payment gateways for merchants who prefer hosted, full-service checkouts — **Razorpay, PhonePe, Paytm, Cashfree and MobiKwik (Zaakpay)** — through the same orders pipeline.

> **Why this exists:** FamPay has **no official merchant API**, so FamGate verifies FamPay payments by reading your FamPay payment-confirmation emails over Gmail IMAP (the "email verification" flow). **BharatPe**'s enterprise dashboard exposes a transaction feed; FamGate polls it with your **Merchant ID + API token** and matches SUCCESS transactions by exact amount + bank reference (UTR). Neither flow routes or holds your money.
>
> **Official gateways:** with your own merchant account + API keys you can let Razorpay/PhonePe/Paytm/Cashfree/MobiKwik-Zaakpay collect for you. FamGate creates the payment on the gateway, verifies its **signed webhook** (or server-to-server status poll as fallback), marks the order PAID, fires your webhook and receipt — funds settle in *your* gateway account.
>
> **GPay (Google Pay):** Google publishes **no merchant collection API**. GPay is a *payer* app — it works here through any UPI rail (FamPay/BharatPe QR & deep links) or inside any gateway checkout. Anything claiming a "GPay merchant API" is mis-marketing.

---

## Features

- 🔒 **Email verification** — merchant signup/login with 6-digit OTP sent over SMTP
- ⚡ **FamPay auto-verification** via Gmail IMAP (App Password) — parses amount + UTR from payment emails
- 🇮🇳 **BharatPe auto-verification** via Merchant ID + API token (`payments-tesseract.bharatpe.in`)
- 🎯 **Collision-free decimal-offset matching** (₹100 → ₹100.42) — no UTR typing for customers
- 🔗 **Hosted checkout page** per order — QR, GPay/PhonePe/Paytm/BHIM deep links, countdown, live status
- 🪝 **HMAC-SHA256 webhooks** (`payment.verified`) with delivery logs + test button
- 🔑 **Merchant REST API** — create orders, poll status, verify UTR, list orders (`X-Api-Key`)
- 🛡️ **Anti-fraud**: global UTR de-duplication, SSRF-guarded webhooks, encrypted credential vault (Fernet — AES-128-CBC + HMAC), per-key + per-IP rate limits
- 🧾 **Customer receipt emails** (SMTP) + merchant dashboard with orders, stats, provider health
- 🚪 **Official gateway adapters** (bring your own merchant account): Razorpay (Payment Links API), PhonePe (Standard Checkout), Paytm (All-in-One JS checkout), Cashfree (Payment Links API), MobiKwik/Zaakpay (Express Checkout V13, HMAC-SHA256) — hosted checkout with UPI + cards + netbanking; verified via each provider's signed callback; server-side status poll as fallback; encrypted key storage; one-click "Test connection"

## Quick start

```bash
cd famgate
python3 -m venv .venv && source .venv/bin/activate   # optional
pip install -r requirements.txt
cp .env.example .env     # <- fill in SMTP credentials for real emails
python3 run.py           # serves on 0.0.0.0:8000
```

Open http://localhost:8000 — sign up, verify your email, then:

1. **Dashboard → Payments** — connect FamPay (Gmail App Password + your `@fam` VPA) and/or BharatPe (Merchant ID + token + `@unitype`/`@yesbank` VPA)
2. **Dashboard → API Keys** — generate `fp_live_…` key + secret
3. **Dashboard → Webhooks** — set your `https://yoursite.com/webhooks/famgate` endpoint
4. Call the API:

```bash
curl -X POST http://localhost:8000/api/v1/order/create \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: fp_live_your_key_here" \
  -d '{"amount": 250, "order_id": "INV-2026-991", "customer_email": "rohan@example.com"}'
```

Open the returned `payment_url` — scan, pay, watch the dashboard flip to **PAID** and your webhook fire.

> **No SMTP configured?** Signup OTPs are shown on the verification screen and logged to `data/mail_outbox.log` (dev mode) — the app stays fully usable offline. Configure SMTP to send real mail.

## Getting your credentials

### FamPay (via Gmail IMAP — payment email verification)
1. Use the Gmail inbox that receives your FamPay UPI payment confirmations.
2. Google Account → **Security → 2-Step Verification → App passwords** → create one (16 chars).
3. Gmail → **Settings → Forwarding and POP/IMAP → Enable IMAP**.
4. Dashboard → Payments → FamPay: paste the Gmail address, the 16-char App Password and your FamPay UPI ID (e.g. `yourname@fam`). Hit **Test IMAP connection**.

### BharatPe (Merchant ID + token)
1. Log in at **enterprise.bharatpe.in**.
2. Open browser DevTools → **Network** → open any request to `payments-tesseract.bharatpe.in/api/v1/merchant/transactions`.
   - `merchantId=…` in the query string → your **Merchant ID**
   - `token: …` in the request headers → your **API token**
   - Your QR's UPI ID (printed on the standee / profile) → **VPA**, usually `@unitype` or `@yesbank`
3. Dashboard → Payments → BharatPe → paste all three, enable, **Test BharatPe API**.

### SMTP (for OTPs & receipts)
Gmail: `smtp.gmail.com:587` + the same App Password, `SMTP_FROM` = your Gmail. See `.env.example`. Any SMTP provider works (Mailgun, SES, Zoho…).

### Official gateways (Razorpay, PhonePe, Paytm, Cashfree, MobiKwik–Zaakpay)

1. Create a merchant account with the gateway (KYC as required by them — free to test in sandboxes).
2. Copy the keys from its dashboard into **Dashboard → Payments → Official gateways**:

| Gateway | What you paste | Where to find it | Checkout on the pay page |
|---|---|---|---|
| **Razorpay** | Key ID + Key Secret (+ optional Webhook Secret) | Dashboard → Settings → API Keys; webhooks under Dashboard → Webhooks (set URL `{host}/webhooks/razorpay`) | Hosted payment-link page (UPI, cards, netbanking, wallets) |
| **PhonePe** | Merchant ID + Salt Key + Salt Index | PhonePe Business dashboard → Developer Settings (current UAT pair: `PGTESTPAYUAT86` / salt `96434309-77…`, index `1`; older demos use `PGTESTPAYUAT`) | Redirect to PhonePe's pay page (UPI: GPay, PhonePe, Paytm, MobiKwik, BHIM) |
| **Paytm** | MID + Merchant Key (16 chars) | Paytm dashboard → Developer Settings | Paytm All-in-One JS checkout opens with amount pre-filled |
| **Cashfree** | App ID + Secret Key (+ optional Webhook Secret) | Cashfree Dashboard → Developers → API Keys | Payment-link page (UPI, cards, netbanking) |
| **MobiKwik (Zaakpay)** | Merchant Identifier + Secret Key | Zaakpay dashboard → Developer/Integration URLs & Keys | Zaakpay Express Checkout (auto-submitting form; UPI, cards, netbanking, wallets) |

3. Enable the gateway. The pay page and API both gain it automatically:

```bash
curl -X POST http://localhost:8000/api/v1/order/create \
  -H "Content-Type: application/json" -H "X-Api-Key: fp_live_…" \
  -d '{"amount": 250, "provider": "razorpay"}'
```

`provider` also accepts `phonepe | paytm | cashfree | mobikwik`, and webhooks arrive at `{host}/webhooks/<provider>` — FamGate verifies each provider's signature scheme (Razorpay HMAC-SHA256 hex; PhonePe `SHA256(base64+salt)###index`; Paytm `PaytmChecksum`; Cashfree `base64(HMAC-SHA256(ts+body))`; Zaakpay alphabetical `key=value&` HMAC-SHA256) **before** settling anything. Gateways can additionally re-check pending orders via `/order/status` and an internal ~60s sweep, so a missed callback never strands an order. FamGate never receives or stores card data.

## Merchant API (v1)

Base: `{your-host}/api/v1` · Auth: header `X-Api-Key: fp_live_…` (or `Authorization: Bearer …`)

| Endpoint | Purpose |
|---|---|
| `POST /order/create` | Create order → `payment_url`, `upi_link`, `qr_base64`, `exact_amount`. `provider` accepts `fampay` / `bharatpe` / `razorpay` / `phonepe` / `paytm` / `cashfree` / `mobikwik` / `auto` |
| `GET /order/status?order_id=…` | Poll: `PENDING` / `PAID` / `EXPIRED` (+ `utr`, `payer_name`) |
| `POST /order/verify-utr` | Manual UTR fallback — de-duplicated globally |
| `GET /orders?status=PAID&limit=25` | List orders |
| `GET /health` | Liveness probe |

**Webhook** (`payment.verified`): raw JSON body + headers `X-FamGate-Event` and `X-FamGate-Signature: sha256=<hmac-sha256 hex of body, key = your webhook secret>`. Verify it like this:

```python
expected = "sha256=" + hmac.new(SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
assert hmac.compare_digest(expected, request.headers["X-FamGate-Signature"])
```

Full reference (with Node.js example): open **/docs** on your instance. Rate limits: create 60/min, status 600/min, verify-utr 60/min per key; 300/min per IP. Errors: `400` validation · `401` bad/revoked key · `404` unknown order · `409` UTR already claimed · `429` rate-limited · `502` upstream provider error.

## Testing without real money

- **Dashboard → Webhooks → Send test webhook** — delivers a `payment.test` event to your endpoint.
- Or pay a ₹1 live order from a UPI app and watch it verify in ~3–10s.
- **Developer smoke suite**: `python3 e2e_test.py` (server must be running) — 30 checks covering signup→OTP→settings→API→order creation with dummy gateways (expect graceful failures), and HMAC-verified inbound callbacks for every gateway (Razorpay, PhonePe, Paytm, Cashfree, MobiKwik), replay/idempotency, and bad-signature rejection.

## Environment variables

See `.env.example`. Highlights:

| Var | Default | Purpose |
|---|---|---|
| `SMTP_HOST/PORT/USER/PASS/FROM/TLS` | — | Outbound mail (OTPs, receipts). Unset ⇒ dev mode (logged, not sent) |
| `FAMGATE_POLL_SECONDS` | `8` | Background verification interval |
| `FAMGATE_VAULT_KEY` | auto at `data/vault.key` | Fernet key encrypting saved Gmail/BharatPe secrets |
| `FAMGATE_WEBHOOK_ALLOW_PRIVATE` | `0` | `1` = allow webhook URLs on localhost/LAN (dev only — SSRF guard is strict by default) |
| `FAMGATE_DATA_DIR` / `FAMGATE_DB` | `./data` | SQLite + vault location |

## Security notes (please read)

- FamPay verification = **reading your own email** via revocable App Password; we never see your Gmail password. Enable 2FA and revoke the App Password anytime.
- The BharatPe token is the one shown in the enterprise dashboard's own requests; treat it like a password. It is encrypted at rest.
- Webhook URLs must be public http(s); private/loopback targets are rejected (`FAMGATE_WEBHOOK_ALLOW_PRIVATE=1` disables for local dev).
- UTRs are globally de-duplicated to prevent replay attacks. Receipts/OTPs go out only if SMTP is set — otherwise they're logged locally.
- FamGate is verification infrastructure, **not** a payment aggregator: funds settle directly to your FamPay/BharatPe-linked bank account. Using it for third-party collections, or against FamPay/BharatPe terms of service, is your responsibility.

## Project layout

```
famgate/
├── app.py          # FastAPI routes: website, dashboard, merchant API, hosted checkout, inbound gateway webhooks
├── db.py           # SQLite layer (orders, merchants, keys, UTR ledger, webhooks, provider_credentials vault)
├── verifiers.py    # FamPay IMAP poller + BharatPe feed poller + PG status poller + webhook dispatcher
├── providers/      # Official gateway adapters (razorpay, phonepe, paytm, cashfree, mobikwik) — one PGResult contract
├── upi.py          # UPI intent URIs, decimal-offset engine, QR rendering
├── mailer.py       # SMTP (OTP + customer receipts) with dev-mode fallback
├── security.py     # PBKDF2 hashing, Fernet vault, SSRF guard, HMAC helpers
├── templates/      # Jinja2 UI (landing, auth, dashboard, checkout, docs)
├── static/         # Neo-brutalist stylesheet + assets
└── run.py          # uvicorn launcher
```

## Honest limitations

- FamPay has no official collection API — verification latency depends on how fast the payment email arrives (usually seconds, up to ~1 min) and on the merchant Gmail staying connected.
- The BharatPe endpoint (`payments-tesseract.bharatpe.in`) is the internal feed used by the enterprise dashboard; it is undocumented and can change without notice. If `Test BharatPe API` fails with 401, re-copy the token from DevTools.
- Exact-amount matching means the customer must pay the paise shown. The hosted checkout makes this one tap; if your customers pay a round amount, disable decimal offset and verify by UTR instead.
- Official gateways require your **own** merchant account (KYC as per their rules). The adapters implement each provider's *documented* API surface and degrade gracefully when credentials are wrong or unreachable (HTTP 502, order marked EXPIRED, nothing silently charged). Dummy/test keys never move real money. **GPay has no merchant collection API** — it works only as a payer app through a rail.
- **PhonePe adapter implements Standard Checkout *V1* (salt-key checksum, `/pg/v1/*`) — the API used by all reference integrations and still offered by PhonePe.** PhonePe also operates a newer, separate **PG V2** (OAuth `client_id`/`client_version`/`client_secret`, host `https://api.phonepe.com/apis/hermes`, Java/PHP SDK models — see `fayyaztech/phonepe-gateway-pg-v2`); it is **not** implemented yet and is not interchangeable with V1 credentials.
- Reference implementations reviewed against the adapters: `VivekNThakkar/phonepe-express`, `fayyaztech/phonepe-gateway-pg-v2`, `allenkiakshay/Phonepe-payment-gateway-nextjs`, `Tibinsunny/phonepe-kit`, `Revanray1/phonepe_paymentIntegration`, `ShivamAnand26/essentiora-phonepe-backend`, plus the referenced Paytm/Laravel/PHP/Dart samples and `knit-pay/upi-qr-code-payment-for-woocommerce` (which itself documents that UPI QR payments cannot be auto-verified without a merchant-feed API — the approach FamGate takes for FamPay/BharatPe). Their checksum recipes, status-poll checksums and callback handling match this codebase.
- Paytm's checkout needs the customer's browser to load Paytm's JS; in pure-server-to-server flows prefer the status poll. MobiKwik (Zaakpay) settlement arrives via the `returnUrl` form POST; a background sweep re-checks pending orders server-side.
