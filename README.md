# Bulk Find Replace

## Deployment + Dev Runbook (Scaffold)

### Local development
- Client: `cd client && npm install && npm run dev`
- Server: `cd server && npm install && npm start`

### Environment variables
- Client: `client/.env` (example in `client/.env.example`)
- Server: `server/.env` (example in `server/.env.example`)
- Do not commit `.env` files or secrets.

### Deploy overview
- Client: Vercel (Vite)
- Server: Render (Node/Express)
- Token storage: SQLite (Render persistent disk) + SQLite `server/tokens.db` (local dev)

### OAuth / Monday
- Feature URL: Vercel client URL
- OAuth Redirect URL: `https://<render-server-url>/auth/callback`

### Security checklist
- Confirm `.env` files are gitignored.
- Confirm no secrets are committed.
- Use Supabase service role key only on the server.

### Render persistent disk (tokens)
Render instances are ephemeral. To persist OAuth tokens:
- Create a Render Disk mounted at `/var/data`.
- Set `TOKENS_DB_PATH=/var/data/tokens.db` in Render env vars.
- Restart the Render service.

### Rotating Monday client secret
- Update `MONDAY_CLIENT_SECRET` in Render environment variables.
- Restart the Render service.
- Re-run OAuth flow.
