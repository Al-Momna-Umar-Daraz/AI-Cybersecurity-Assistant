# ENV Go-Live Checklist

## 1. Create .env
1. Copy `deploy/.env.production.template` to `.env` in project root.
2. Fill all `replace_with_...` values with real keys.

## 2. Minimum Required For Full Features
1. `FLASK_SECRET_KEY`
2. `OPENAI_API_KEY`
3. `HIBP_API_KEY`
4. `FACECHECK_API_TOKEN`
5. `GOOGLE_CLIENT_ID`
6. `GOOGLE_CLIENT_SECRET`
7. `GOOGLE_REDIRECT_URI`
8. `PK_ACCOUNT_TITLE` + (`PK_ACCOUNT_NUMBER` or `PK_IBAN`)

## 3. Earning Setup
1. Ad earnings: set `ADSENSE_CLIENT` in `.env`.
2. App credit purchase via local bank: set `PK_BANK_*` fields.
3. Optional Stripe checkout: set all `STRIPE_*` fields.

## 4. Security Required In Production
1. `SESSION_COOKIE_SECURE=1`
2. `ENFORCE_HTTPS=1`
3. `BANK_TRANSFER_AUTO_APPROVE=0`
4. `FACECHECK_DEMO=0`

## 5. Quick Verify Commands
```powershell
python -m py_compile app.py
python deploy/check_env_ready.py
```

## 6. Final Runtime Test
1. Login and open each feature page.
2. Test:
   - Breach checker
   - Face intel
   - Assistant chat
   - Bank transfer flow
   - Analysis charts
3. Confirm no 4xx/5xx errors in server logs.
