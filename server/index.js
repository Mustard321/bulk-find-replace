
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

const secretFingerprint = (value) => {
  if (!value) return null;
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 8);
};

app.use((req, _res, next) => {
  console.log(`[REQ] ${req.method} ${req.path}`);
  next();
});

const signingSecret = (process.env.MONDAY_SIGNING_SECRET || '').trim();
const clientSecret = (process.env.MONDAY_CLIENT_SECRET || '').trim();
const signingSecretLen = signingSecret.length;
const clientSecretLen = clientSecret.length;
const signingSecretFp = secretFingerprint(signingSecret);
const clientSecretFp = secretFingerprint(clientSecret);
console.log('[env] MONDAY_SIGNING_SECRET present:', Boolean(signingSecret), 'len:', signingSecretLen, 'fp:', signingSecretFp);
console.log('[env] MONDAY_CLIENT_SECRET present:', Boolean(clientSecret), 'len:', clientSecretLen, 'fp:', clientSecretFp);
console.log('[env] ALLOWED_ORIGINS:', process.env.ALLOWED_ORIGINS);

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

const corsOptions = {
  origin: (origin, cb) => {
    if (isAllowedOrigin(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET', 'POST', 'OPTIONS']
};
app.use(cors(corsOptions));
app.options('/api/*', cors(corsOptions));
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

const buildAuthDebug = ({ authHeader, token, startsWithBearer }) => {
  const trimmedToken = token.trim();
  const hasDots = trimmedToken.split('.').length === 3;
  const tokenType = startsWithBearer ? 'bearer' : (authHeader ? 'raw' : 'none');
  return {
    authHeaderPresent: Boolean(authHeader),
    tokenType,
    tokenLength: trimmedToken.length,
    hasDots,
    startsWithBearer
  };
};

const mondayAuth = (req, res, next) => {
  const authHeader = req.headers.authorization || '';
  const startsWithBearer = authHeader.startsWith('Bearer ');
  const token = (startsWithBearer ? authHeader.slice(7) : authHeader).trim();
  const debug = buildAuthDebug({ authHeader, token, startsWithBearer });
  const signing = (process.env.MONDAY_SIGNING_SECRET || '').trim();
  const secretLen = signing.length;
  const secretFp = secretFingerprint(signing);

  if (!token) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn('[mondayAuth] missing token', { secretLen, secretFp, ...debug });
    }
    return res.status(401).json({ ok: false, error: 'UNAUTHORIZED', reason: 'MISSING_TOKEN', debug });
  }
  if (!debug.hasDots) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn('[mondayAuth] token not jwt', { secretLen, secretFp, ...debug });
    }
    return res.status(401).json({ ok: false, error: 'UNAUTHORIZED', reason: 'TOKEN_NOT_JWT', debug });
  }
  if (!signing) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn('[mondayAuth] missing MONDAY_SIGNING_SECRET', { secretLen, secretFp });
    }
    return res.status(401).json({ ok: false, error: 'UNAUTHORIZED', reason: 'MISSING_SECRET', debug });
  }

  try {
    const decoded = jwt.verify(token.trim(), signing, { algorithms: ['HS256'] });
    req.mondayJwt = decoded;
    req.mondayDat = decoded?.dat || decoded?.data?.dat || null;
    console.log('[mondayAuth] verify ok', {
      hasDat: Boolean(req.mondayDat),
      accountId: decoded?.dat?.account_id || decoded?.accountId || null
    });
    return next();
  } catch (e) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn(
        `[mondayAuth] verify failed name=${e?.name || 'Error'} message=${e?.message || ''} secretLen=${secretLen} secretFp=${secretFp}`,
        debug
      );
    }
    return res.status(401).json({
      ok: false,
      error: 'UNAUTHORIZED',
      reason: e?.name || 'VERIFY_FAILED',
      debug
    });
  }
};

app.get('/api/debug/echo-auth', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const startsWithBearer = authHeader.startsWith('Bearer ');
  const token = startsWithBearer ? authHeader.slice(7) : authHeader;
  const debug = buildAuthDebug({ authHeader, token, startsWithBearer });
  res.json({ ok: true, debug });
});

app.get('/api/debug/env-fp', (_req, res) => {
  res.json({
    signingPresent: Boolean(signingSecret),
    signingLen: signingSecretLen,
    signingFp: signingSecretFp,
    clientPresent: Boolean(clientSecret),
    clientLen: clientSecretLen,
    clientFp: clientSecretFp
  });
});

app.get('/api/debug/env-check', (_req, res) => {
  res.json({
    signingPresent: Boolean(signingSecret),
    signingLen: signingSecretLen,
    signingFp: signingSecretFp,
    clientPresent: Boolean(clientSecret),
    clientLen: clientSecretLen,
    clientFp: clientSecretFp,
    areEqual: signingSecret === clientSecret,
    nodeEnv: process.env.NODE_ENV || null,
    commitSha: process.env.RENDER_GIT_COMMIT || process.env.COMMIT_SHA || null
  });
});

app.get('/api/debug/which-secret', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const startsWithBearer = authHeader.startsWith('Bearer ');
  const token = (startsWithBearer ? authHeader.slice(7) : authHeader).trim();
  const tokenLooksJwt = token.split('.').length === 3;
  if (!tokenLooksJwt) {
    return res.json({
      ok: false,
      verifiedWith: null,
      signingWorked: false,
      clientWorked: false,
      tokenLooksJwt
    });
  }
  const signing = (process.env.MONDAY_SIGNING_SECRET || '').trim();
  const client = (process.env.MONDAY_CLIENT_SECRET || '').trim();
  let signingWorked = false;
  let clientWorked = false;
  try {
    jwt.verify(token, signing, { algorithms: ['HS256'] });
    signingWorked = true;
  } catch {
    signingWorked = false;
  }
  if (!signingWorked) {
    try {
      jwt.verify(token, client, { algorithms: ['HS256'] });
      clientWorked = true;
    } catch {
      clientWorked = false;
    }
  }
  if (signingWorked) {
    return res.json({ ok: true, verifiedWith: 'SIGNING' });
  }
  if (clientWorked) {
    return res.json({ ok: true, verifiedWith: 'CLIENT' });
  }
  return res.json({
    ok: false,
    verifiedWith: null,
    signingWorked,
    clientWorked,
    tokenLooksJwt
  });
});

app.get('/api/auth-check', mondayAuth, (req, res) => {
  res.json({ ok: true, monday: req.mondayJwt });
});

app.get('/api/debug/verify', mondayAuth, (req, res) => {
  const dat = req.mondayDat || null;
  const jwtData = req.mondayJwt || {};
  res.json({
    ok: true,
    dat,
    user_id: dat?.user_id || jwtData?.user_id,
    account_id: dat?.account_id || jwtData?.account_id,
    app_id: dat?.app_id || jwtData?.app_id
  });
});

app.get('/api/debug/whoami', mondayAuth, (req, res) => {
  const dat = req.mondayDat || null;
  const jwt = req.mondayJwt || {};
  res.json({
    ok: true,
    accountId: dat?.account_id || jwt?.account_id,
    userId: dat?.user_id || jwt?.user_id,
    appId: dat?.app_id || jwt?.app_id
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
    if (!accessToken) {
      return res.status(500).json({ ok: false, error: 'MISSING_ACCESS_TOKEN' });
    }
    let tokenAccountId = r.data?.account_id;
    let source = 'token_response';
    if (!tokenAccountId && stateAccountId) {
      tokenAccountId = stateAccountId;
      source = 'state';
    }
    const queryAccountId = Array.isArray(req.query.accountId) ? req.query.accountId[0] : req.query.accountId;
    if (!tokenAccountId && queryAccountId) {
      tokenAccountId = queryAccountId;
      source = 'query';
    }
    if (!tokenAccountId) {
      console.log('[OAUTH] callback missing accountId');
      return res.status(400).json({ ok: false, error: 'MISSING_ACCOUNT_ID' });
    }
    saveToken(String(tokenAccountId), accessToken);
    console.log(`[OAUTH] token ok account_id=${tokenAccountId} stored=true source=${source}`);
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
