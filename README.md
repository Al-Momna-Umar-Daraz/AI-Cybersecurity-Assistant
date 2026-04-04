# AI Cybersecurity Assistant

Professional Flask-based cybersecurity web app with:

- Command Analyzer
- Password Checker
- URL Scanner
- Email Breach Checker (HIBP redirect flow)
- Port Scanner
- Network Scan AI Malware Detection
- Encryption Tools
- Linux Command Safety Lab
- Face Intelligence module
- Analysis / Reports / Monetization / Settings

## Tech Stack

- Python (Flask)
- SQLite
- Vanilla JavaScript + HTML/CSS
- PWA support (manifest + service worker)

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```

Open:

- `http://127.0.0.1:5000`

## Environment

Use `.env.example` as a base and create `.env`.

Important keys:

- `FLASK_SECRET_KEY`
- `OPENAI_API_KEY`
- `HIBP_API_KEY` (optional, for live HIBP API mode)
- `FACECHECK_API_TOKEN` (optional)
- Stripe/Ads keys (optional monetization)

## Production

Deployment helpers are in:

- `deploy/DEPLOYMENT.md`
- `deploy/launch-checklist.md`
- `deploy/.env.production.template`

## CI (Auto Checks on Every Push)

This repo includes GitHub Actions workflow:

- `.github/workflows/ci.yml`

It runs basic Python syntax checks on pushes and pull requests.

## Author

Developed by **Al Momna Umar Daraz**
