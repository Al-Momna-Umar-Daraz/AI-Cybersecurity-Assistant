# AI Cybersecurity Assistant Deployment

## Run locally (production-style)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
gunicorn -c gunicorn.conf.py wsgi:app
```

## Reverse proxy
Use `deploy/nginx.ai-cybersecurity-assistant.conf` as reference.

## Service
Use `deploy/ai-cybersecurity-assistant.service` with systemd.

## Required environment variables
- `FLASK_SECRET_KEY`
- `OPENAI_API_KEY`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI`
- `SESSION_COOKIE_SECURE=1`
- `ENFORCE_HTTPS=1`

## Optional
- `HIBP_API_KEY`
- `DEFAULT_ADMIN_PASSWORD`
- `STRIPE_SECRET_KEY`
- `STRIPE_PUBLISHABLE_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `ADSENSE_CLIENT` (for Google ads monetization)
- `FACECHECK_API_TOKEN`
- `FACECHECK_DEMO=1` (use demo mode until your paid API is active)
- `PK_BANK_NAME`
- `PK_ACCOUNT_TITLE`
- `PK_ACCOUNT_NUMBER`
- `PK_IBAN`
- `BANK_TRANSFER_AUTO_APPROVE=0` (keep `0` in production)
