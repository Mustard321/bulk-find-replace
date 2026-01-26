
import express from 'express';
import cors from 'cors';
import axios from 'axios';
import Database from 'better-sqlite3';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, '.env') });
const app = express();

app.use((req, _res, next) => {
  console.log(`[REQ] ${req.method} ${req.path}`);
  next();
});

app.get('/__debug/ping', (_req, res) => {
  console.log('[DBG] ping');
  res.json({ ok: true, ts: Date.now() });
});

app.get('/__debug/authorize-config', (_req, res) => {
  res.json({ ok: true, requiresAccountId: true, stateFormat: '<accountId>.<nonce>' });
});

app.get('/__debug/version', (_req, res) => {
  const sha = process.env.RENDER_GIT_COMMIT || process.env.COMMIT_SHA || 'unknown';
  const service = process.env.RENDER_SERVICE_ID || null;
  res.json({ ok: true, sha, service });
});

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
  },
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET', 'POST', 'OPTIONS']
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

const mondayAuth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const secret = (process.env.MONDAY_SIGNING_SECRET || '').trim();
    const secretLen = secret ? String(secret).length : 0;

    if (!token) {
      if (process.env.NODE_ENV !== 'production') {
        console.warn('[mondayAuth] missing token', { hasAuthHeader: !!authHeader, secretLen });
      }
      return res.status(401).json({ ok: false, error: 'UNAUTHORIZED', reason: 'MISSING_TOKEN' });
    }
    if (!secret) {
      if (process.env.NODE_ENV !== 'production') {
        console.warn('[mondayAuth] missing MONDAY_SIGNING_SECRET', { secretLen });
      }
      return res.status(401).json({ ok: false, error: 'UNAUTHORIZED', reason: 'MISSING_SECRET' });
    }

    const decoded = jwt.verify(token, secret);
    req.monday = decoded;
    return next();
  } catch (e) {
    const secretLen = (process.env.MONDAY_SIGNING_SECRET || '').trim().length;
    console.warn(`[mondayAuth] verify failed name=${e?.name || 'Error'} message=${e?.message || ''} secretLen=${secretLen}`);
    return res.status(401).json({
      ok: false,
      error: 'UNAUTHORIZED',
      reason: 'VERIFY_FAILED',
      detail: e?.message || ''
    });
  }
};

app.get('/api/auth-check', mondayAuth, (req, res) => {
  res.json({ ok: true, monday: req.monday });
});

app.get('/api/debug/verify', mondayAuth, (req, res) => {
  res.json({ ok: true, monday: req.monday });
});

app.get('/api/debug/whoami', mondayAuth, (req, res) => {
  res.json({
    ok: true,
    appId: req.monday?.dat?.app_id,
    accountId: req.monday?.dat?.account_id,
    userId: req.monday?.dat?.user_id
  });
});

app.get('/health', (_, res) => {
  res.json({ ok: true, serverBaseUrl, redirectUri });
});

app.get('/auth/authorize', (req, res) => {
  const accountId = req.query?.accountId;
  if (!accountId) {
    return res.status(400).json({ ok: false, error: 'MISSING_ACCOUNT_ID' });
  }
  const url = new URL('https://auth.monday.com/oauth2/authorize');
  url.searchParams.set('client_id', process.env.MONDAY_CLIENT_ID);
  url.searchParams.set('redirect_uri', redirectUri);
  const nonce = crypto.randomBytes(16).toString('hex');
  const state = `${String(accountId)}.${nonce}`;
  url.searchParams.set('state', state);
  console.log(`[OAUTH] authorize start accountId=${accountId} state=${state}`);
  res.redirect(url.toString());
});

app.get('/auth/callback', async (req, res) => {
  console.log(`[OAUTH] callback hit hasCode=${Boolean(req.query.code)} hasState=${Boolean(req.query.state)}`);
  const { code, error, error_description, state } = req.query;
  const authCode = Array.isArray(code) ? code[0] : code;
  const stateValue = Array.isArray(state) ? state[0] : state;
  const stateString = stateValue ? String(stateValue) : '';
  const stateAccountId = stateString.split('.')[0];
  if (!stateAccountId) {
    console.log('[OAUTH] callback missing accountId');
    return res.status(400).json({ ok: false, error: 'MISSING_ACCOUNT_ID' });
  }
  if (error) return res.status(400).send(String(error_description || error));
  if (!authCode) return res.status(400).send('Missing code');
  try {
    const r = await axios.post('https://auth.monday.com/oauth2/token', {
      client_id: process.env.MONDAY_CLIENT_ID,
      client_secret: process.env.MONDAY_CLIENT_SECRET,
      code: authCode,
      redirect_uri: redirectUri
    });
    const accessToken = r.data?.access_token;
    saveToken(String(stateAccountId), accessToken);
    console.log(`[OAUTH] token ok account_id=${stateAccountId} stored=true source=state`);
    res.send(`<!doctype html>
<html>
  <body>Authorized. You can close this tab.
    <script>
      try {
        if (window.opener) {
          window.opener.postMessage({ type: "BFR_OAUTH_OK", accountId: "${tokenAccountId}" }, "*");
        }
      } catch (e) {}
      try { window.close(); } catch (e) {}
    </script>
  </body>
</html>`);
  } catch (err) {
    console.error(`[OAUTH] callback error ${err.message}`);
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
  if (!token) return res.status(401).json({ ok: false, error: 'NOT_AUTHORIZED' });
  const r = await axios.post('https://api.monday.com/v2', { query, variables }, {
    headers: { Authorization: token }
  });
  res.json(r.data);
});

app.get('/api/auth/status', (req, res) => {
  const accountId = req.query?.accountId || req.body?.accountId;
  if (!accountId) {
    return res.status(400).json({ ok: false, error: 'MISSING_ACCOUNT_ID' });
  }
  if (typeof accountId !== 'string' || !/^\d+$/.test(accountId)) {
    return res.status(400).send('Invalid accountId');
  }
  const token = getToken(accountId);
  return res.json({ ok: true, authorized: Boolean(token) });
});

const truncateSnippet = (text, max = 120) => {
  if (typeof text !== 'string') return '';
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}…`;
};

const countOccurrences = (text, find) => {
  if (!text || !find) return 0;
  let count = 0;
  let idx = 0;
  while (true) {
    const next = text.indexOf(find, idx);
    if (next === -1) break;
    count += 1;
    idx = next + find.length;
  }
  return count;
};

app.post('/api/preview', rateLimit, mondayAuth, async (req, res) => {
  const { accountId, boardId, find, replace } = req.body || {};
  if (!accountId) {
    return res.status(400).json({ ok: false, error: 'MISSING_ACCOUNT_ID' });
  }
  if (typeof accountId !== 'string' || !/^\d+$/.test(accountId)) {
    return res.status(400).send('Invalid accountId');
  }
  if (typeof boardId !== 'number' && typeof boardId !== 'string') {
    return res.status(400).send('Invalid boardId');
  }
  if (typeof find !== 'string' || find.trim().length === 0) {
    return res.status(400).send('Find text is required');
  }

  const token = getToken(accountId);
  if (!token) return res.status(401).json({ ok: false, error: 'NOT_AUTHORIZED' });

  const boardIdValue = String(boardId);
  const findText = find;
  const replaceText = typeof replace === 'string' ? replace : '';

  try {
    const columnsQuery = `
      query($id: ID!) {
        boards(ids: [$id]) {
          columns { id title type }
        }
      }
    `;
    const columnsRes = await axios.post('https://api.monday.com/v2', {
      query: columnsQuery,
      variables: { id: boardIdValue }
    }, { headers: { Authorization: token } });

    if (columnsRes.data?.errors?.length) {
      return res.status(502).send('Failed to load board columns');
    }

    const columns = columnsRes.data?.data?.boards?.[0]?.columns || [];
    const eligibleColumns = columns.filter(c => c.type === 'text' || c.type === 'long_text');
    const eligibleIds = eligibleColumns.map(c => c.id);
    const columnTitleById = new Map(eligibleColumns.map(c => [c.id, c.title]));

    if (eligibleIds.length === 0) {
      return res.json({ totalMatches: 0, totalItems: 0, rows: [] });
    }

    const rows = [];
    let totalMatches = 0;
    const itemIds = new Set();
    let cursor = null;

    const itemsQuery = `
      query($id: ID!, $cursor: String, $columnIds: [String!]) {
        boards(ids: [$id]) {
          items_page(limit: 500, cursor: $cursor) {
            cursor
            items {
              id
              name
              column_values(ids: $columnIds) { id text }
            }
          }
        }
      }
    `;

    do {
      const itemsRes = await axios.post('https://api.monday.com/v2', {
        query: itemsQuery,
        variables: { id: boardIdValue, cursor, columnIds: eligibleIds }
      }, { headers: { Authorization: token } });

      if (itemsRes.data?.errors?.length) {
        return res.status(502).send('Failed to load board items');
      }

      const page = itemsRes.data?.data?.boards?.[0]?.items_page;
      const items = page?.items || [];
      cursor = page?.cursor || null;

      for (const item of items) {
        for (const col of item.column_values || []) {
          const text = col?.text || '';
          if (!text.includes(findText)) continue;
          const matchCount = countOccurrences(text, findText);
          if (matchCount === 0) continue;
          totalMatches += matchCount;
          itemIds.add(item.id);
          rows.push({
            itemId: item.id,
            itemName: item.name,
            columnId: col.id,
            columnTitle: columnTitleById.get(col.id) || col.id,
            before: truncateSnippet(text),
            after: truncateSnippet(text.split(findText).join(replaceText))
          });
        }
      }
    } while (cursor);

    console.log(`Preview: board ${boardIdValue}, matches ${totalMatches}, items ${itemIds.size}`);
    return res.json({ totalMatches, totalItems: itemIds.size, rows });
  } catch (err) {
    console.error('Preview failed', err.response?.status || err.message);
    return res.status(500).send('Preview failed');
  }
});

app.listen(port, () => {
  const version = process.env.APP_VERSION || 'unknown';
  console.log(`Server on ${port} version=${version}`);
});
