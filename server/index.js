
import express from 'express';
import cors from 'cors';
import axios from 'axios';
import Database from 'better-sqlite3';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, '.env') });
const app = express();

const requiredEnv = ['SERVER_BASE_URL', 'ALLOWED_ORIGINS', 'MONDAY_CLIENT_ID', 'MONDAY_CLIENT_SECRET'];
const missingEnv = requiredEnv.filter(k => !process.env[k]);
if (missingEnv.length) {
  throw new Error(`Missing required env: ${missingEnv.join(', ')}`);
}

const port = process.env.PORT || 3001;
const serverBaseUrl = process.env.SERVER_BASE_URL;
const redirectUri = `${serverBaseUrl}/auth/callback`;
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const isAllowedOrigin = origin => {
  if (!origin) return true;
  if (allowedOrigins.length === 0) return false;
  let originUrl;
  try {
    originUrl = new URL(origin);
  } catch {
    return false;
  }
  for (const entry of allowedOrigins) {
    if (entry.includes('*')) {
      try {
        const entryUrl = new URL(entry.replace('*.', ''));
        const allowedHost = entryUrl.hostname;
        if (originUrl.protocol === entryUrl.protocol &&
            originUrl.hostname.endsWith(allowedHost)) {
          return true;
        }
      } catch {
        continue;
      }
    } else if (origin === entry) {
      return true;
    }
  }
  return false;
};

app.use(cors({
  origin: (origin, cb) => {
    if (isAllowedOrigin(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  }
}));
app.use(express.json({ limit: '1mb' }));

const dbPath = process.env.TOKENS_DB_PATH || './tokens.db';
const db = new Database(dbPath);
db.prepare('CREATE TABLE IF NOT EXISTS tokens (account_id TEXT PRIMARY KEY, token TEXT)').run();

const saveToken = (id, token) =>
  db.prepare('INSERT OR REPLACE INTO tokens VALUES (?, ?)').run(id, token);

const getToken = id =>
  db.prepare('SELECT token FROM tokens WHERE account_id = ?').get(id)?.token;

const rateWindowMs = 60_000;
const rateMax = 120;
const rateBuckets = new Map();
const rateLimit = (req, res, next) => {
  const key = req.ip || 'unknown';
  const now = Date.now();
  const bucket = rateBuckets.get(key) || [];
  const recent = bucket.filter(ts => now - ts < rateWindowMs);
  recent.push(now);
  rateBuckets.set(key, recent);
  if (recent.length > rateMax) return res.status(429).send('Too many requests');
  next();
};

app.get('/health', (_, res) => {
  res.json({ ok: true, serverBaseUrl, redirectUri });
});

app.get('/auth/authorize', (_, res) => {
  const url = new URL('https://auth.monday.com/oauth2/authorize');
  url.searchParams.set('client_id', process.env.MONDAY_CLIENT_ID);
  url.searchParams.set('redirect_uri', redirectUri);
  res.redirect(url.toString());
});

app.get('/auth/callback', async (req, res) => {
  const { code, error, error_description } = req.query;
  const authCode = Array.isArray(code) ? code[0] : code;
  if (error) return res.status(400).send(String(error_description || error));
  if (!authCode) return res.status(400).send('Missing code');
  try {
    const r = await axios.post('https://auth.monday.com/oauth2/token', {
      client_id: process.env.MONDAY_CLIENT_ID,
      client_secret: process.env.MONDAY_CLIENT_SECRET,
      code: authCode,
      redirect_uri: redirectUri
    });
    saveToken(r.data.account_id, r.data.access_token);
    res.send('Authorized. Close window.');
  } catch (err) {
    console.error('OAuth token exchange failed', err.response?.status || err.message);
    res.status(500).send('OAuth exchange failed');
  }
});

app.post('/api/graphql', rateLimit, async (req, res) => {
  const { accountId, query, variables } = req.body || {};
  if (typeof accountId !== 'string') return res.status(400).send('Invalid accountId');
  if (!/^\d+$/.test(accountId)) return res.status(400).send('Invalid accountId');
  if (typeof query !== 'string') return res.status(400).send('Invalid query');
  if (variables !== undefined && (typeof variables !== 'object' || Array.isArray(variables))) {
    return res.status(400).send('Invalid variables');
  }
  const token = getToken(accountId);
  if (!token) return res.status(401).send('Not authorized');
  const r = await axios.post('https://api.monday.com/v2', { query, variables }, {
    headers: { Authorization: token }
  });
  res.json(r.data);
});

app.listen(port, () => console.log(`Server on ${port}`));
