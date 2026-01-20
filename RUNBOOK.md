# Bulk Find & Replace Runbook

Recommended Node version: 20.x

Setup
```sh
cd server
npm install
cd ../client
npm install
```

Start server (3001)
```sh
cd server
npm start
```

Start client (5173)
```sh
cd client
npm run dev -- --host 0.0.0.0 --port 5173
```

Start tunnels (two terminals)
```sh
cloudflared tunnel --url http://localhost:3001
cloudflared tunnel --url http://localhost:5173
```

DEV QUICKSTART (exact terminal layout)
Terminal 1 (server)
```sh
cd server
npm start
```

Terminal 2 (client)
```sh
cd client
npm run dev -- --host 0.0.0.0 --port 5173
```

Terminal 3 (server tunnel)
```sh
cloudflared tunnel --url http://localhost:3001
```

Terminal 4 (client tunnel)
```sh
cloudflared tunnel --url http://localhost:5173
```

Paste URLs
- Monday Board View URL = `https://<public-client-url>`
- Monday OAuth Redirect URL = `https://<public-server-url>/auth/callback`
- `server/.env` SERVER_BASE_URL = `https://<public-server-url>`
- `server/.env` ALLOWED_ORIGINS includes `https://<public-client-url>,https://*.monday.com,https://*.monday.work`
- `client/.env` VITE_API_BASE_URL = `https://<public-server-url>`

Monday app settings
- Board View URL: `https://<public-client-url>`
- OAuth Redirect URL: `https://<public-server-url>/auth/callback`

Common errors and fixes
- `invalid_redirect_uri`: update `SERVER_BASE_URL` and Monday OAuth Redirect URL to match.
- `401 Not authorized`: open `https://<public-server-url>/auth/authorize` to connect.
- `CORS blocked`: ensure `ALLOWED_ORIGINS` includes the client tunnel URL and Monday domains.
