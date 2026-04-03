# Investment Dashboard Backend

## 1) Prepare env

Copy `.env.example` to `.env`, then fill in values:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI` (default: `http://localhost:3000/oauth2/callback`)
- `SESSION_SECRET`
- `GOOGLE_SPREADSHEET_ID`

## 2) Install dependencies

```bash
npm install
```

## 3) Start server

```bash
npm start
```

## 4) OAuth login

Open:

- `http://localhost:3000/auth/google`

## 5) Read sheets

Open:

- `http://localhost:3000/api/portfolio`

Optional custom ranges:

- `http://localhost:3000/api/portfolio?ranges=01_股票_基金!A1:Z300,02_配息!A1:Z300`

## Dual Mode (Local + GitHub Pages)

Frontend file: `index.html`

- Local mode:
  - Open `http://localhost:3000`
  - Frontend calls `http://localhost:3000/api/portfolio`

- GitHub Pages mode:
  - Frontend auto-calls `https://your-backend-domain.com/api/portfolio`
  - Update `PROD_API_BASE` in `index.html` to your real backend domain
  - Backend CORS allowlist already includes `https://stanleylutw.github.io`
  - Set backend env: `NODE_ENV=production` (for cross-site secure cookie)
  - Login on backend once: `https://your-backend-domain.com/auth/google`
