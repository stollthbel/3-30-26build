# Legacy Edge

Trade journal SaaS. Rust + SQLite. One binary, zero npm.

## Deploy to Railway

1. Push this repo to GitHub
2. Go to railway.com/new → **Deploy from GitHub repo** → pick this repo
3. Add two variables in the **Variables** tab:
   - `PORT` = `8080`
   - `JWT_SECRET` = any random string (mash your keyboard, 30+ characters)
4. Go to **Settings** → **Networking** → **Generate Domain**
5. Done. Your app is live.

## Run locally

```
cargo run --release
# → http://localhost:3000
```

## What it does

- Multi-tenant auth (signup/login, JWT sessions)
- Log trades with discipline scoring, emotional state, reflection
- Dashboard: P&L, win rate, equity curve, streaks, max drawdown
- Filterable trade history with detail modals
- Custom trading rules that become a pre-trade checklist
- CSV export

## Env vars

| Var | Value | Why |
|-----|-------|-----|
| PORT | 8080 | Railway needs this |
| JWT_SECRET | random string | Keeps logins secure |
