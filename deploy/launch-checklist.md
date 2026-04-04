# Production Launch Checklist

1. Server Prep
- Ubuntu 22.04+, create app user, install python3, nginx.
- Clone project to `/opt/ai-cybersecurity-assistant`.

2. Python Environment
- `python3 -m venv .venv`
- `source .venv/bin/activate`
- `pip install -U pip`
- `pip install -r requirements.txt`

3. Environment
- Copy `deploy/.env.production.template` to `.env` (or `.env.example` as fallback)
- Set strong `FLASK_SECRET_KEY`
- Set `SESSION_COOKIE_SECURE=1`, `ENFORCE_HTTPS=1`
- Add `OPENAI_API_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, `HIBP_API_KEY`
- Add `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY`, `STRIPE_WEBHOOK_SECRET` for real one-time payments
- Add `ADSENSE_CLIENT` for ad-based earning model
- Add `FACECHECK_API_TOKEN` for in-app face recognition search
- Add Pakistan bank receiving details: `PK_BANK_NAME`, `PK_ACCOUNT_TITLE`, `PK_ACCOUNT_NUMBER`/`PK_IBAN`
- Keep `BANK_TRANSFER_AUTO_APPROVE=0` for production safety
- Run `python deploy/check_env_ready.py` before go-live

4. Gunicorn Service
- Copy `deploy/ai-cybersecurity-assistant.service` to `/etc/systemd/system/`
- `sudo systemctl daemon-reload`
- `sudo systemctl enable --now ai-cybersecurity-assistant`

5. Nginx
- Copy `deploy/nginx.ai-cybersecurity-assistant.conf` to `/etc/nginx/sites-available/`
- Enable site and reload nginx
- Obtain TLS via certbot and update cert paths

6. Google OAuth Setup
- In Google Cloud Console, add OAuth redirect URI:
  `https://your-domain.com/auth/google/callback`
- Set authorized domains.

7. Security Validation
- Check CSRF on all POST forms/APIs
- Confirm security headers present
- Verify rate limiting/lockout behavior

8. PWA Validation
- Open in Chrome, check install prompt
- Verify `manifest.webmanifest` and `sw.js` load over HTTPS

9. Monitoring
- Enable systemd journald retention
- Add error monitoring (Sentry or equivalent)

10. Backup
- Backup `cybersecurity.db`
- Backup `.env`
- Backup `static/uploads/`
