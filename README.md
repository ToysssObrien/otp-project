# OTP Service

FastAPI OTP service with:

- OTP request and verification endpoints
- Redis-backed OTP state
- Admin accounts are also stored in Redis. The env credentials seed the `Super Admin` account on startup, and staff users can be created from the admin UI.
- SMS provider integrations
- Operations monitor for OTP traffic and provider health

## Main Routes

- `POST /request-otp`
- `POST /verify-otp`
- `GET /health`
- `POST /admin/login`
- `POST /admin/logout`
- `GET /ops.html`
- `GET /admin/metrics`

## Admin Monitor Security

The admin console is a single-page flow at `/ops.html`.
If the dashboard is enabled but credentials are missing, `/admin/metrics` returns `503` and the admin console stays on the login view with an error state.

Required production environment variables:

- `ADMIN_DASHBOARD_USERNAME`
- `ADMIN_DASHBOARD_PASSWORD`

Recommended related variables:

- `ADMIN_DASHBOARD_REALM`
- `ADMIN_SESSION_DURATION_SECONDS`
- `ADMIN_SESSION_COOKIE_SECURE`
- `REDIS_URL`
- `OTP_PROVIDER`

## Metrics Captured

- Total OTP requests
- Blocked requests from cooldown or rate limit
- Verify success and failure totals
- Top phone numbers by request volume
- Top phone numbers by verify failures
- Provider send and verify latency
- Provider failure and recent activity timeline

## Local Run

```bash
pip install -r requirements.txt
npm install
npm run build
uvicorn main:app --reload
```

Open:

- `http://127.0.0.1:8000/otp.html`
- `http://127.0.0.1:8000/ops.html`

Frontend source lives in `frontend/` and builds into `static/`.

## Production Notes

- Set `USE_FAKE_REDIS=false`
- Set a real `REDIS_URL`
- Customer records and dashboard metrics are both stored in Redis, so they survive deploys as long as the Redis service remains attached.
- Super Admin and staff user accounts also live in Redis, so they survive deploys as long as the Redis service remains attached.
- Turn on `GOOGLE_SHEETS_BACKUP_ENABLED=true` and provide `GOOGLE_SHEETS_BACKUP_SPREADSHEET_ID` plus a Google service account to keep a second copy in Google Sheets.
- The app also writes a local snapshot export to `data/backups/latest-backup.json` on each backup cycle.
- Rotate SMS credentials if they were ever exposed
- Keep `/ops.html` behind admin auth only

## Deploy To Render

This repository includes a `render.yaml` Blueprint that provisions:

- 1 Python web service for the FastAPI app
- 1 Render Key Value instance for Redis-compatible storage

Recommended setup:

1. Push this repo to GitHub.
2. In Render, create a new Blueprint from the repository root `render.yaml`.
3. Keep the web service on a paid instance type for production use.
4. Set these secret values when Render prompts for them:
   - `ADMIN_DASHBOARD_USERNAME`
   - `ADMIN_DASHBOARD_PASSWORD`
   - `PLASGATE_SECRET_KEY`
   - `PLASGATE_PRIVATE_KEY`
   - `PLASGATE_SENDER` if your Plasgate sender is different from `PlasGateUAT`
5. After the first deploy, open:
   - `/health`
   - `/otp.html`
   - `/ops.html`

Notes:

- `REDIS_URL` is wired from the Render Key Value service automatically.
- `OTP_PROVIDER` is set to `plasgate` in `render.yaml`.
- The app is configured for the Singapore region in `render.yaml` to keep latency low for Southeast Asia.
- Do not use the free instance types for production OTP traffic.

## Optional Google Sheets Backup

Customer records and dashboard snapshots can auto-backup to Google Sheets on save and on a periodic timer.

Required environment variables:

- `GOOGLE_SHEETS_BACKUP_ENABLED=true`
- `GOOGLE_SHEETS_BACKUP_SPREADSHEET_ID`
- `GOOGLE_SHEETS_BACKUP_SHEET_NAME`
- `GOOGLE_SHEETS_BACKUP_DASHBOARD_SHEET_NAME`
- `GOOGLE_SHEETS_SERVICE_ACCOUNT_FILE` or `GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON`

Optional related variables:

- `GOOGLE_SHEETS_BACKUP_STRICT=false`
- `GOOGLE_SHEETS_BACKUP_INTERVAL_SECONDS=300`
- `GOOGLE_SHEETS_BACKUP_TIMEOUT_SECONDS=15`

Setup notes:

- Share the target spreadsheet with the service account email from your Google service account
- The customer backup rewrites columns `A:E` on the configured customer sheet using headers `ID`, `Name`, `PhoneNumber`, `OTP`, `Timestamp`
- The dashboard backup rewrites a separate sheet using rows for summary, provider health, recent events, and top phone metrics
- With `GOOGLE_SHEETS_BACKUP_STRICT=false`, local save still succeeds even if Google Sheets sync fails
