# Godpay — current source export

This archive contains the current application source exported from the running Godpay gateway. It is a source-only copy, not a database backup or a complete server image. No changes were made to the running application for this export.

## Run locally

Requires Python 3.10 or later.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 run.py
```

Open http://localhost:8000. Create an account, configure your own payment provider under Payments, and create an API key. SQLite storage is created under `data/` by default. Never commit `.env` or `data/` to source control.

For production, use HTTPS and a trusted reverse proxy. Review proxy-header trust in `run.py`; it currently trusts forwarded headers from all peers and should not be exposed directly to untrusted clients. Keep the vault encryption key stable and back it up securely. Existing encrypted credentials cannot be restored without their original vault key.

## Current payment flow

1. Create an order through `/api/v1/order/create`, or use the saved-key selector in API Playground to create a manual payment link.
2. The checkout displays the exact payable amount, QR code, and available payment-app actions.
3. Verification uses the configured provider. FamPay checks only the five newest exact-sender matches from `no-reply@famapp.in`, using read-only IMAP and received timestamps. Sender matching alone is not cryptographic proof of email authenticity.
4. Successful verification marks the order paid and triggers the existing receipt/webhook flow.
5. Verified receipts can be shared as PNG files, with an image-download fallback. Print/PDF controls are removed.
6. Customers and merchants can cancel pending orders. Cancellation closes the hosted checkout; it cannot reverse transfers or invalidate a QR/payment-app link already saved by the payer.

## Main files

- `app.py`: website, checkout, payment API and provider callback routes.
- `db.py`: SQLite schema and queries.
- `verifiers.py`: verification workers and settlement hooks.
- `manual_features.py`: saved-key manual links, profile names and cancellation.
- `upi.py`: UPI links, exact amounts and QR generation.
- `providers/`: payment-provider adapters.
- `templates/`, `static/`: current UI and component attribution.
- `demo_sandbox.py`: retained isolated demo API; its generator is no longer shown in Playground.

`README.md` contains older project documentation. Where it differs from current behavior—particularly signup OTP requirements and sandbox UI—use this file and the implementation as the reference. Signup email verification was removed from the current flow.

## Excluded

Live environment files, vault keys, API credentials, databases, merchant/customer records, sessions, payment records, logs, SSH keys, backups, installed dependencies, and Python bytecode are not included. `.env.example` contains placeholders only. Hosting proxy configuration and deployment secrets must be supplied separately.

Original UI references are listed in `UI-SOURCES.md` and `static/component-sources.json`; some referenced components are no longer active. Preserve applicable third-party attribution and licences.
