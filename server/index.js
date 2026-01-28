
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

app.use((req, res, next) => {
  req.requestId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(12).toString('hex');
  res.setHeader('x-request-id', req.requestId);
  next();
});

app.use((req, _res, next) => {
  console.log(`[REQ] ${req.method} ${req.path} requestId=${req.requestId}`);
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

const getTokensDbPath = () => {
  const configured = (process.env.TOKENS_DB_PATH || '').trim();
  const fallback = path.join(process.cwd(), 'tokens.db');
  return path.resolve(configured || fallback);
};
const resolvedDbPath = getTokensDbPath();
console.log('[env] TOKENS_DB_PATH:', resolvedDbPath);
const serverBuildId = process.env.GIT_SHA || process.env.RENDER_GIT_COMMIT || process.env.COMMIT_SHA || 'unknown';
console.log('[env] SERVER_BUILD_SHA:', serverBuildId);
const db = new Database(resolvedDbPath);
db.prepare('CREATE TABLE IF NOT EXISTS tokens (account_id TEXT PRIMARY KEY, token TEXT)').run();
db.prepare(`CREATE TABLE IF NOT EXISTS audit_log (
  run_id TEXT,
  account_id TEXT,
  board_id TEXT,
  target_type TEXT,
  object_id TEXT,
  column_or_block_id TEXT,
  item_name TEXT,
  column_title TEXT,
  before TEXT,
  after TEXT,
  status TEXT,
  error TEXT,
  created_at INTEGER
)`).run();
try { db.prepare('ALTER TABLE audit_log ADD COLUMN item_name TEXT').run(); } catch {}
try { db.prepare('ALTER TABLE audit_log ADD COLUMN column_title TEXT').run(); } catch {}

const saveToken = (id, token) => {
  db.prepare('INSERT OR REPLACE INTO tokens VALUES (?, ?)').run(id, token);
  console.log(`[oauth] tokenStored=true accountId=${id} tokensDbPath=${resolvedDbPath}`);
};

const getToken = id => {
  const row = db.prepare('SELECT token FROM tokens WHERE account_id = ?').get(id);
  const tokenRowFound = Boolean(row?.token);
  console.log(`[oauth] tokenRowFound=${tokenRowFound} accountIdUsed=${id} tokensDbPath=${resolvedDbPath}`);
  return row?.token;
};

const insertAudit = db.prepare(
  `INSERT INTO audit_log
   (run_id, account_id, board_id, target_type, object_id, column_or_block_id, item_name, column_title, before, after, status, error, created_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
);


const rateWindowMs = 60_000;
const rateMax = 120;
const rateBuckets = new Map();
const MAX_UPDATES_PER_RUN = Number(process.env.MAX_UPDATES_PER_RUN) || 250;
const MAX_SUBITEMS_PER_ITEM = Number(process.env.MAX_SUBITEMS_PER_ITEM) || 200;
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
  const tokenPrefix = trimmedToken ? `${trimmedToken.slice(0, 6)}…` : '';
  const tokenSuffix = trimmedToken ? `…${trimmedToken.slice(-6)}` : '';
  return {
    authHeaderPresent: Boolean(authHeader),
    tokenType,
    tokenLength: trimmedToken.length,
    hasDots,
    startsWithBearer,
    tokenPrefix,
    tokenSuffix
  };
};

const verifyMondayJwt = (token) => {
  const signing = (process.env.MONDAY_SIGNING_SECRET || '').trim();
  const fallback = (process.env.MONDAY_CLIENT_SECRET || '').trim();
  const secret = signing || fallback;
  const label = signing ? 'SIGNING' : 'CLIENT_FALLBACK';
  if (!secret) {
    const err = new Error('Signing secret missing');
    err.name = 'SIGNING_SECRET_MISSING';
    throw err;
  }
  const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
  return { decoded, verifiedWith: label };
};

const normalizeAccountId = (value) => {
  if (value === null || value === undefined) return null;
  const text = String(value).trim();
  if (!/^\d+$/.test(text)) return null;
  return Number(text);
};

const deriveAccountId = (req) => {
  const bodyId = req.body?.accountId ?? req.body?.account_id;
  const normalized = normalizeAccountId(bodyId);
  if (normalized) return { accountId: normalized, source: 'body' };
  if (bodyId !== undefined) return { accountId: null, source: 'body_invalid' };

  const authHeader = req.headers.authorization || '';
  const startsWithBearer = authHeader.startsWith('Bearer ');
  const token = (startsWithBearer ? authHeader.slice(7) : authHeader).trim();
  if (!token) return { accountId: null, source: 'missing' };
  try {
    const { decoded } = verifyMondayJwt(token);
    const dat = decoded?.dat || decoded?.data?.dat || null;
    const datAccountId = normalizeAccountId(dat?.account_id || decoded?.account_id);
    if (datAccountId) return { accountId: datAccountId, source: 'session' };
    return { accountId: null, source: 'session_missing' };
  } catch {
    return { accountId: null, source: 'session_invalid', sessionError: 'AUTH_SESSION_INVALID' };
  }
};

const mondayAuth = (req, res, next) => {
  const authHeader = req.headers.authorization || '';
  const startsWithBearer = authHeader.startsWith('Bearer ');
  const token = (startsWithBearer ? authHeader.slice(7) : authHeader).trim();
  const debug = buildAuthDebug({ authHeader, token, startsWithBearer });

  if (!token) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn('[mondayAuth] missing token', { ...debug });
    }
    return res.status(401).json({
      error: 'Unauthorized',
      code: 'AUTH_SESSION_INVALID',
      requestId: req.requestId
    });
  }
  if (!debug.hasDots) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn('[mondayAuth] token not jwt', { ...debug });
    }
    return res.status(401).json({
      error: 'Unauthorized',
      code: 'AUTH_SESSION_INVALID',
      requestId: req.requestId
    });
  }

  try {
    console.log('[mondayAuth] using session token');
    const { decoded, verifiedWith } = verifyMondayJwt(token);
    req.mondayJwt = decoded;
    req.mondayVerifiedWith = verifiedWith;
    req.mondayDat = decoded?.dat || decoded?.data?.dat || null;
    console.log('[mondayAuth] verify ok', {
      hasDat: Boolean(req.mondayDat),
      accountId: decoded?.dat?.account_id || decoded?.accountId || null,
      verifiedWith
    });
    return next();
  } catch (e) {
    const signingLen = (process.env.MONDAY_SIGNING_SECRET || '').trim().length;
    const clientLen = (process.env.MONDAY_CLIENT_SECRET || '').trim().length;
    const reason = e?.name === 'TokenExpiredError'
      ? 'EXPIRED'
      : e?.name === 'SIGNING_SECRET_MISSING'
        ? 'MISSING'
        : 'INVALID_SIGNATURE';
    console.warn(
      `[mondayAuth] verify failed name=${e?.name || 'Error'} reason=${reason} tokenLength=${debug.tokenLength} hasDots=${debug.hasDots} startsWithBearer=${debug.startsWithBearer} signingLen=${signingLen} clientLen=${clientLen}`
    );
    return res.status(401).json({
      error: 'Unauthorized',
      code: 'AUTH_SESSION_INVALID',
      authError: 'AUTH_INVALID',
      requestId: req.requestId
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
  return res.json({
    ok: Boolean(signingSecret),
    used: 'MONDAY_SIGNING_SECRET',
    signingPresent: Boolean(signingSecret),
    signingLen: signingSecretLen,
    signingFp: signingSecretFp
  });
});

app.get('/api/auth-check', mondayAuth, (req, res) => {
  res.json({ ok: true, monday: req.mondayJwt });
});

app.get('/api/debug/verify', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const startsWithBearer = authHeader.startsWith('Bearer ');
  const token = (startsWithBearer ? authHeader.slice(7) : authHeader).trim();
  const debug = buildAuthDebug({ authHeader, token, startsWithBearer });
  try {
    const { decoded } = verifyMondayJwt(token);
    const dat = decoded?.dat || decoded?.data?.dat || null;
    return res.json({
      ok: true,
      tokenShape: debug,
      datPresent: Boolean(dat),
      user_id: dat?.user_id || decoded?.user_id || null,
      account_id: dat?.account_id || decoded?.account_id || null,
      app_id: dat?.app_id || decoded?.app_id || null,
      iat: decoded?.iat || null,
      exp: decoded?.exp || null
    });
  } catch (e) {
    return res.status(401).json({
      ok: false,
      code: 'AUTH_SESSION_INVALID',
      tokenShape: debug,
      requestId: req.requestId
    });
  }
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
  <body>
    Authorized. You can close this tab.
    <script>
      (function () {
        try {
          if (window.opener) {
            window.opener.postMessage({ type: "mustard_oauth_success", accountId: "${tokenAccountId}" }, "*");
            window.opener.postMessage({ type: "BFR_OAUTH_OK", accountId: "${tokenAccountId}" }, "*");
          }
        } catch (e) {}
        try { window.close(); } catch (e) {}
      })();
    </script>
  </body>
</html>`);
  } catch (err) {
    console.error(`[OAUTH] callback error ${err.message}`);
    res.status(500).send('OAuth exchange failed');
  }
});

app.post('/api/graphql', rateLimit, async (req, res) => {
  const accountInfo = deriveAccountId(req);
  if (!accountInfo.accountId) {
    if (accountInfo.sessionError) {
      console.log(`[graphql] requestId=${req.requestId} accountIdUsed=null tokensDbPath=${resolvedDbPath} tokenRowFound=false reason=${accountInfo.sessionError}`);
      return res.status(401).json({ error: 'Unauthorized', code: 'AUTH_SESSION_INVALID', requestId: req.requestId });
    }
    if (accountInfo.source === 'body_invalid') {
      return res.status(400).json({ error: 'BadRequest', code: 'ACCOUNT_ID_INVALID', requestId: req.requestId });
    }
    return res.status(400).json({ error: 'BadRequest', code: 'ACCOUNT_ID_MISSING', requestId: req.requestId });
  }
  const { query, variables } = req.body || {};
  if (typeof query !== 'string') return res.status(400).send('Invalid query');
  if (variables !== undefined && (typeof variables !== 'object' || Array.isArray(variables))) {
    return res.status(400).send('Invalid variables');
  }
  const accountId = String(accountInfo.accountId);
  const token = getToken(accountId);
  const tokenRowFound = Boolean(token);
  console.log(`[graphql] requestId=${req.requestId} accountIdUsed=${accountId} tokensDbPath=${resolvedDbPath} tokenRowFound=${tokenRowFound}`);
  if (!token) {
    console.log(`[graphql] requestId=${req.requestId} reason=AUTH_NOT_CONNECTED`);
    return res.status(401).json({ error: 'Unauthorized', code: 'AUTH_NOT_CONNECTED', requestId: req.requestId });
  }
  try {
    const r = await axios.post('https://api.monday.com/v2', { query, variables }, {
      headers: { Authorization: token }
    });
    return res.json(r.data);
  } catch (err) {
    if (err?.response?.status === 401) {
      console.log(`[graphql] requestId=${req.requestId} reason=AUTH_OAUTH_FAILED`);
      return res.status(401).json({ error: 'Unauthorized', code: 'AUTH_OAUTH_FAILED', requestId: req.requestId });
    }
    throw err;
  }
});

app.get('/api/auth/status', (req, res) => {
  const accountId = req.query?.accountId || req.body?.accountId;
  if (!accountId) {
    return res.status(400).json({ ok: false, error: 'MISSING_ACCOUNT_ID' });
  }
  const normalizedText = String(accountId).trim();
  if (!/^\d+$/.test(normalizedText)) {
    return res.status(400).send('Invalid accountId');
  }
  const token = getToken(normalizedText);
  const connected = Boolean(token);
  console.log(`[auth-status] accountIdUsed=${normalizedText} tokensDbPath=${resolvedDbPath} tokenRowFound=${connected}`);
  return res.json({
    ok: true,
    authorized: connected,
    connected,
    code: connected ? null : 'AUTH_NOT_CONNECTED'
  });
});

const normalizeLineEndings = (text) => String(text || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');

const truncateSnippet = (text, max = 120) => {
  if (typeof text !== 'string') return '';
  const normalized = normalizeLineEndings(text);
  if (normalized.length <= max) return normalized;
  return `${normalized.slice(0, max - 1)}…`;
};

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const countOccurrences = (text, find) => {
  const safeText = normalizeLineEndings(String(text || ''));
  const safeFind = normalizeLineEndings(String(find || ''));
  if (!safeText || !safeFind) return 0;
  let count = 0;
  let idx = 0;
  while (true) {
    const next = safeText.indexOf(safeFind, idx);
    if (next === -1) break;
    count += 1;
    idx = next + safeFind.length;
  }
  return count;
};

const buildMatcher = (findText, replaceText, rules = {}) => {
  const caseSensitive = Boolean(rules.caseSensitive);
  const wholeWord = Boolean(rules.wholeWord);
  const safeFind = normalizeLineEndings(String(findText || ''));
  const safeReplace = normalizeLineEndings(String(replaceText || ''));
  const normalizeText = (text) => normalizeLineEndings(String(text || ''));

  if (wholeWord) {
    const pattern = `\\b${escapeRegex(safeFind)}\\b`;
    const flags = caseSensitive ? 'g' : 'gi';
    return {
      count: (text) => {
        const safeText = normalizeText(text);
        if (!safeText) return 0;
        const matches = safeText.match(new RegExp(pattern, flags));
        return matches ? matches.length : 0;
      },
      replace: (text) => normalizeText(text).replace(new RegExp(pattern, flags), safeReplace),
      includes: (text) => {
        const safeText = normalizeText(text);
        if (!safeText) return false;
        return new RegExp(pattern, caseSensitive ? '' : 'i').test(safeText);
      }
    };
  }

  if (caseSensitive) {
    return {
      count: (text) => countOccurrences(text, safeFind),
      replace: (text) => normalizeText(text).split(safeFind).join(safeReplace),
      includes: (text) => normalizeText(text).includes(safeFind)
    };
  }

  const regex = new RegExp(escapeRegex(safeFind), 'gi');
  return {
    count: (text) => {
      const safeText = normalizeText(text);
      if (!safeText) return 0;
      const matches = safeText.match(regex);
      return matches ? matches.length : 0;
    },
    replace: (text) => normalizeText(text).replace(regex, safeReplace),
    includes: (text) => {
      const safeText = normalizeText(text);
      if (!safeText) return false;
      return safeText.toLowerCase().includes(safeFind.toLowerCase());
    }
  };
};

const normalizeArray = (value) => {
  if (!value) return [];
  if (Array.isArray(value)) return value.filter(Boolean).map(String);
  if (typeof value === 'string') {
    return value.split(',').map(s => s.trim()).filter(Boolean);
  }
  return [];
};

const sortArray = (values) => [...values].sort();

const normalizeTargets = (targets) => ({
  items: targets?.items !== false,
  subitems: Boolean(targets?.subitems),
  docs: Boolean(targets?.docs)
});

const normalizeRules = (rules) => ({
  caseSensitive: Boolean(rules?.caseSensitive),
  wholeWord: Boolean(rules?.wholeWord)
});

const normalizeFilters = (filters) => ({
  includeColumnIds: sortArray(normalizeArray(filters?.includeColumnIds)),
  excludeColumnIds: sortArray(normalizeArray(filters?.excludeColumnIds)),
  includeGroupIds: sortArray(normalizeArray(filters?.includeGroupIds)),
  excludeGroupIds: sortArray(normalizeArray(filters?.excludeGroupIds)),
  includeNameContains: sortArray(normalizeArray(filters?.includeNameContains)),
  excludeNameContains: sortArray(normalizeArray(filters?.excludeNameContains)),
  docIds: sortArray(normalizeArray(filters?.docIds))
});

const normalizeLimit = (limit) => ({
  maxChanges: limit?.maxChanges ? Number(limit.maxChanges) : null
});

const normalizePagination = (pagination) => ({
  cursor: pagination?.cursor ? String(pagination.cursor) : null,
  pageSize: pagination?.pageSize ? Math.min(Math.max(Number(pagination.pageSize) || 0, 1), 500) : null
});

const buildRunId = ({ accountId, boardId, find, replace, targets, rules, filters, limit }) => {
  const payload = {
    accountId: String(accountId || ''),
    boardId: String(boardId || ''),
    find: String(find || ''),
    replace: String(replace || ''),
    targets,
    rules,
    filters,
    limit
  };
  const hash = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
  return hash.slice(0, 12);
};

const applyNameFilters = (name, includeList, excludeList) => {
  const safeName = String(name || '');
  const lower = safeName.toLowerCase();
  if (includeList.length > 0) {
    const matches = includeList.some((entry) => lower.includes(String(entry).toLowerCase()));
    if (!matches) return false;
  }
  if (excludeList.length > 0) {
    const blocked = excludeList.some((entry) => lower.includes(String(entry).toLowerCase()));
    if (blocked) return false;
  }
  return true;
};

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const shouldRetry = (err) => {
  const status = err?.response?.status;
  return status === 429 || status >= 500;
};

const withRetry = async (fn, { retries = 3, baseDelay = 250 } = {}) => {
  let attempt = 0;
  while (true) {
    try {
      return await fn();
    } catch (err) {
      attempt += 1;
      if (!shouldRetry(err) || attempt > retries) throw err;
      const delay = baseDelay * Math.pow(2, attempt - 1);
      await sleep(delay);
    }
  }
};

const runWithConcurrency = async (items, worker, concurrency = 3) => {
  let index = 0;
  const results = [];
  const runners = new Array(concurrency).fill(null).map(async () => {
    while (index < items.length) {
      const currentIndex = index;
      index += 1;
      results[currentIndex] = await worker(items[currentIndex], currentIndex);
    }
  });
  await Promise.all(runners);
  return results;
};

const fetchBoardColumns = async (token, boardIdValue) => {
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
    throw new Error('Failed to load board columns');
  }

  const columns = columnsRes.data?.data?.boards?.[0]?.columns || [];
  const eligibleColumns = columns.filter(c => c.type === 'text' || c.type === 'long_text');
  const docColumns = columns.filter(c => c.type === 'doc');
  const columnTitleById = new Map(columns.map(c => [c.id, c.title]));
  return { columns, eligibleColumns, docColumns, columnTitleById };
};

const filterColumnIds = (eligibleColumns, filters) => {
  const includeIds = filters.includeColumnIds;
  const excludeIds = filters.excludeColumnIds;
  let filtered = eligibleColumns;
  if (includeIds.length > 0) {
    const includeSet = new Set(includeIds);
    filtered = filtered.filter(c => includeSet.has(c.id));
  }
  if (excludeIds.length > 0) {
    const excludeSet = new Set(excludeIds);
    filtered = filtered.filter(c => !excludeSet.has(c.id));
  }
  return filtered;
};

const extractDocIdsFromValue = (value) => {
  if (!value) return [];
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      if (parsed?.doc_id) return [String(parsed.doc_id)];
      if (parsed?.docId) return [String(parsed.docId)];
      if (parsed?.id) return [String(parsed.id)];
    } catch {
      return [];
    }
  }
  if (typeof value === 'object') {
    if (value.doc_id) return [String(value.doc_id)];
    if (value.docId) return [String(value.docId)];
    if (value.id) return [String(value.id)];
  }
  return [];
};

const parseDocIds = (columnValues, docColumnIds) => {
  const docIds = new Set();
  for (const col of columnValues || []) {
    if (!docColumnIds.has(col.id)) continue;
    const ids = extractDocIdsFromValue(col.value);
    ids.forEach(id => docIds.add(id));
  }
  return docIds;
};

const fetchItemsPage = async ({ token, boardIdValue, cursor, columnIds, pageSize, includeSubitems }) => {
  const itemsQuery = `
    query($id: ID!, $cursor: String, $columnIds: [String!], $limit: Int) {
      boards(ids: [$id]) {
        items_page(limit: $limit, cursor: $cursor) {
          cursor
          items {
            id
            name
            group { id }
            column_values(ids: $columnIds) { id text value }
            ${includeSubitems ? 'subitems { id name column_values { id text } board { id } }' : ''}
          }
        }
      }
    }
  `;

  const itemsRes = await axios.post('https://api.monday.com/v2', {
    query: itemsQuery,
    variables: { id: boardIdValue, cursor, columnIds, limit: pageSize }
  }, { headers: { Authorization: token } });

  if (itemsRes.data?.errors?.length) {
    throw new Error('Failed to load board items');
  }

  const page = itemsRes.data?.data?.boards?.[0]?.items_page;
  return {
    cursor: page?.cursor || null,
    items: page?.items || []
  };
};

const fetchDocBlocks = async ({ token, docId }) => {
  const docQuery = `
    query($id: ID!) {
      docs(ids: [$id]) {
        id
        name
        blocks {
          id
          type
          content
          text
        }
      }
    }
  `;
  const docRes = await axios.post('https://api.monday.com/v2', {
    query: docQuery,
    variables: { id: docId }
  }, { headers: { Authorization: token } });
  if (docRes.data?.errors?.length) {
    throw new Error('Failed to load doc blocks');
  }
  const doc = docRes.data?.data?.docs?.[0];
  return { docName: doc?.name || `Doc ${docId}`, blocks: doc?.blocks || [] };
};

const extractDocBlockText = (block) => {
  if (!block) return '';
  if (typeof block.text === 'string') return normalizeLineEndings(block.text);
  if (typeof block.content === 'string') return normalizeLineEndings(block.content);
  if (block.content && typeof block.content.text === 'string') return normalizeLineEndings(block.content.text);
  return '';
};

const updateDocBlock = async ({ token, blockId, content }) => {
  const mutation = `
    mutation($id: ID!, $content: JSON!) {
      update_doc_block(id: $id, content: $content) {
        id
      }
    }
  `;
  const response = await axios.post('https://api.monday.com/v2', {
    query: mutation,
    variables: { id: blockId, content }
  }, { headers: { Authorization: token } });
  if (response.data?.errors?.length) {
    throw new Error('Failed to update doc block');
  }
  return response.data;
};

app.post('/api/preview', rateLimit, async (req, res) => {
  const { boardId, find, replace } = req.body || {};
  const accountInfo = deriveAccountId(req);
  if (!accountInfo.accountId) {
    if (accountInfo.sessionError) {
      console.log(`[preview] requestId=${req.requestId} accountIdUsed=null tokensDbPath=${resolvedDbPath} tokenRowFound=false reason=AUTH_SESSION_INVALID`);
      return res.status(401).json({ error: 'Unauthorized', code: 'AUTH_SESSION_INVALID', requestId: req.requestId });
    }
    if (accountInfo.source === 'body_invalid') {
      return res.status(400).json({ error: 'BadRequest', code: 'ACCOUNT_ID_INVALID', requestId: req.requestId });
    }
    return res.status(400).json({ error: 'BadRequest', code: 'ACCOUNT_ID_MISSING', requestId: req.requestId });
  }
  const accountId = String(accountInfo.accountId);
  if (typeof boardId !== 'number' && typeof boardId !== 'string') {
    return res.status(400).send('Invalid boardId');
  }
  if (typeof find !== 'string' || find.trim().length === 0) {
    return res.status(400).send('Find text is required');
  }

  const token = getToken(accountId);
  const tokenRowFound = Boolean(token);
  console.log(`[preview] requestId=${req.requestId} accountIdUsed=${accountId} tokensDbPath=${resolvedDbPath} tokenRowFound=${tokenRowFound}`);
  if (!token) {
    console.log(`[preview] requestId=${req.requestId} reason=AUTH_NOT_CONNECTED`);
    return res.status(401).json({ error: 'Unauthorized', code: 'AUTH_NOT_CONNECTED', requestId: req.requestId });
  }
  console.log('[preview] using oauth token');

  const targets = normalizeTargets(req.body?.targets);
  const rules = normalizeRules(req.body?.rules);
  const filters = normalizeFilters(req.body?.filters);
  const limit = normalizeLimit(req.body?.limit);
  const pagination = normalizePagination(req.body?.pagination);
  const usePaging = Boolean(pagination.cursor) || Boolean(pagination.pageSize);

  const boardIdValue = String(boardId);
  const findText = find;
  const replaceText = typeof replace === 'string' ? replace : '';
  const effectiveMax = limit.maxChanges ? Math.min(limit.maxChanges, MAX_UPDATES_PER_RUN) : MAX_UPDATES_PER_RUN;
  const runId = buildRunId({
    accountId,
    boardId: boardIdValue,
    find: findText,
    replace: replaceText,
    targets,
    rules,
    filters,
    limit: { maxChanges: effectiveMax }
  });
  const incomingRunId = req.body?.runId || req.body?.run_id;
  if (incomingRunId && incomingRunId !== runId) {
    return res.status(400).json({ ok: false, error: 'RUN_ID_MISMATCH', requestId: req.requestId, runId });
  }
  const matcher = buildMatcher(findText, replaceText, rules);
  const pageSize = pagination.pageSize || 200;

  try {
    const { eligibleColumns, docColumns, columnTitleById } = await fetchBoardColumns(token, boardIdValue);
    const filteredColumns = filterColumnIds(eligibleColumns, filters);
    const eligibleIds = filteredColumns.map(c => c.id);
    const docColumnIds = new Set(docColumns.map(c => c.id));
    const columnIdsForQuery = Array.from(new Set([...eligibleIds, ...docColumnIds]));

    if (eligibleIds.length === 0 && !targets.docs) {
      return res.json({ requestId: req.requestId, runId, totalMatches: 0, totalItems: 0, rows: [] });
    }

    const rows = [];
    const itemIds = new Set();
    let totalMatches = 0;
    let cursor = pagination.cursor || null;
    let limitReached = false;
    const warnings = [];
    let subitemCapNoted = false;
    const docIds = new Set(filters.docIds);

    do {
      const page = await fetchItemsPage({
        token,
        boardIdValue,
        cursor,
        columnIds: columnIdsForQuery,
        pageSize,
        includeSubitems: targets.subitems
      });
      const items = page.items;
      cursor = page.cursor;

      for (const item of items) {
        const groupId = item?.group?.id || null;
        if (filters.includeGroupIds.length > 0 && groupId && !filters.includeGroupIds.includes(groupId)) {
          continue;
        }
        if (filters.excludeGroupIds.includes(groupId)) continue;
        if (!applyNameFilters(item?.name, filters.includeNameContains, filters.excludeNameContains)) {
          continue;
        }

        if (targets.items) {
          for (const col of item.column_values || []) {
            if (!eligibleIds.includes(col.id)) continue;
            const text = normalizeLineEndings(col?.text || '');
            if (!matcher.includes(text)) continue;
            const matchCount = matcher.count(text);
            if (matchCount === 0) continue;
            totalMatches += matchCount;
            itemIds.add(item.id);
            rows.push({
              targetType: 'item',
              itemId: item.id,
              itemName: item.name,
              columnId: col.id,
              columnTitle: columnTitleById.get(col.id) || col.id,
              before: truncateSnippet(text),
              after: truncateSnippet(matcher.replace(text))
            });
            if (effectiveMax && totalMatches >= effectiveMax) {
              limitReached = true;
              break;
            }
          }
        }

        if (targets.docs && docColumnIds.size > 0) {
          const docIdSet = parseDocIds(item.column_values, docColumnIds);
          docIdSet.forEach(id => docIds.add(id));
        }

        if (targets.subitems && item?.subitems?.length) {
          const subitems = Array.isArray(item.subitems)
            ? item.subitems.slice(0, MAX_SUBITEMS_PER_ITEM)
            : [];
          if (!subitemCapNoted && item.subitems.length > MAX_SUBITEMS_PER_ITEM) {
            warnings.push(`Subitems capped at ${MAX_SUBITEMS_PER_ITEM} per item to keep previews fast.`);
            subitemCapNoted = true;
          }
          for (const subitem of subitems) {
            if (!applyNameFilters(subitem?.name, filters.includeNameContains, filters.excludeNameContains)) {
              continue;
            }
            for (const col of subitem.column_values || []) {
              if (filters.includeColumnIds.length > 0 && !filters.includeColumnIds.includes(col.id)) continue;
              if (filters.excludeColumnIds.includes(col.id)) continue;
              const text = normalizeLineEndings(col?.text || '');
              if (!matcher.includes(text)) continue;
              const matchCount = matcher.count(text);
              if (matchCount === 0) continue;
              totalMatches += matchCount;
              itemIds.add(subitem.id);
              rows.push({
                targetType: 'subitem',
                itemId: subitem.id,
                itemName: subitem.name,
                columnId: col.id,
                columnTitle: col.id,
                before: truncateSnippet(text),
                after: truncateSnippet(matcher.replace(text)),
                subitemBoardId: subitem?.board?.id || null
              });
              if (effectiveMax && totalMatches >= effectiveMax) {
                limitReached = true;
                break;
              }
            }
            if (limitReached) break;
          }
        }

        if (limitReached) break;
      }

      if (limitReached || usePaging) break;
    } while (cursor);

    if (targets.docs && docIds.size > 0 && !(effectiveMax && totalMatches >= effectiveMax)) {
      try {
        for (const docId of docIds) {
          const { docName, blocks } = await fetchDocBlocks({ token, docId });
          for (const block of blocks) {
            const text = extractDocBlockText(block);
            if (!matcher.includes(text)) continue;
            const matchCount = matcher.count(text);
            if (matchCount === 0) continue;
            totalMatches += matchCount;
            rows.push({
              targetType: 'doc_block',
              itemId: docId,
              itemName: docName,
              columnId: block.id,
              columnTitle: block.type || 'doc block',
              before: truncateSnippet(text),
              after: truncateSnippet(matcher.replace(text))
            });
            if (effectiveMax && totalMatches >= effectiveMax) {
              limitReached = true;
              break;
            }
          }
          if (limitReached) break;
        }
      } catch (e) {
        warnings.push('Docs support pending API confirmation. Docs were skipped in this preview.');
      }
    }

    console.log(`[preview] requestId=${req.requestId} runId=${runId} board=${boardIdValue} matches=${totalMatches} items=${itemIds.size}`);
    return res.json({
      requestId: req.requestId,
      runId,
      totalMatches,
      totalItems: itemIds.size,
      rows,
      nextCursor: cursor,
      limitReached,
      warnings
    });
  } catch (err) {
    if (err?.response?.status === 401) {
      console.log(`[preview] requestId=${req.requestId} reason=AUTH_OAUTH_FAILED`);
      return res.status(401).json({ error: 'Unauthorized', code: 'AUTH_OAUTH_FAILED', requestId: req.requestId });
    }
    console.error(`[preview] failed requestId=${req.requestId} status=${err.response?.status || ''} message=${err.message || ''}`);
    return res.status(500).send('Preview failed');
  }
});

app.post('/api/apply', rateLimit, async (req, res) => {
  const { boardId, find, replace, confirmText, confirmed } = req.body || {};
  const accountInfo = deriveAccountId(req);
  if (!accountInfo.accountId) {
    if (accountInfo.sessionError) {
      return res.status(401).json({ error: 'Unauthorized', code: 'AUTH_SESSION_INVALID', requestId: req.requestId });
    }
    if (accountInfo.source === 'body_invalid') {
      return res.status(400).json({ error: 'BadRequest', code: 'ACCOUNT_ID_INVALID', requestId: req.requestId });
    }
    return res.status(400).json({ error: 'BadRequest', code: 'ACCOUNT_ID_MISSING', requestId: req.requestId });
  }
  const accountId = String(accountInfo.accountId);
  if (typeof boardId !== 'number' && typeof boardId !== 'string') {
    return res.status(400).send('Invalid boardId');
  }
  if (typeof find !== 'string' || find.trim().length === 0) {
    return res.status(400).send('Find text is required');
  }
  if (!confirmed && confirmText !== 'APPLY') {
    return res.status(400).json({ ok: false, error: 'CONFIRMATION_REQUIRED' });
  }

  const token = getToken(accountId);
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized', code: 'AUTH_NOT_CONNECTED', requestId: req.requestId });
  }
  console.log('[apply] using oauth token');

  const targets = normalizeTargets(req.body?.targets);
  const rules = normalizeRules(req.body?.rules);
  const filters = normalizeFilters(req.body?.filters);
  const limit = normalizeLimit(req.body?.limit);
  const boardIdValue = String(boardId);
  const findText = find;
  const replaceText = typeof replace === 'string' ? replace : '';
  const effectiveMax = limit.maxChanges ? Math.min(limit.maxChanges, MAX_UPDATES_PER_RUN) : MAX_UPDATES_PER_RUN;
  const runId = buildRunId({
    accountId,
    boardId: boardIdValue,
    find: findText,
    replace: replaceText,
    targets,
    rules,
    filters,
    limit: { maxChanges: effectiveMax }
  });
  const incomingRunId = req.body?.runId || req.body?.run_id;
  if (incomingRunId && incomingRunId !== runId) {
    return res.status(400).json({ ok: false, error: 'RUN_ID_MISMATCH', requestId: req.requestId, runId });
  }
  const matcher = buildMatcher(findText, replaceText, rules);

  try {
    const { eligibleColumns, docColumns, columnTitleById } = await fetchBoardColumns(token, boardIdValue);
    const filteredColumns = filterColumnIds(eligibleColumns, filters);
    const eligibleIds = filteredColumns.map(c => c.id);
    const docColumnIds = new Set(docColumns.map(c => c.id));
    const columnIdsForQuery = Array.from(new Set([...eligibleIds, ...docColumnIds]));

    const changes = [];
    const docIds = new Set(filters.docIds);
    let cursor = null;
    let totalMatches = 0;
    let limitReached = false;

    do {
      const page = await fetchItemsPage({
        token,
        boardIdValue,
        cursor,
        columnIds: columnIdsForQuery,
        pageSize: 200,
        includeSubitems: targets.subitems
      });
      const items = page.items;
      cursor = page.cursor;

      for (const item of items) {
        const groupId = item?.group?.id || null;
        if (filters.includeGroupIds.length > 0 && groupId && !filters.includeGroupIds.includes(groupId)) {
          continue;
        }
        if (filters.excludeGroupIds.includes(groupId)) continue;
        if (!applyNameFilters(item?.name, filters.includeNameContains, filters.excludeNameContains)) {
          continue;
        }

        if (targets.items) {
          for (const col of item.column_values || []) {
            if (!eligibleIds.includes(col.id)) continue;
            const text = normalizeLineEndings(col?.text || '');
            if (!matcher.includes(text)) continue;
            const matchCount = matcher.count(text);
            if (matchCount === 0) continue;
            totalMatches += matchCount;
            changes.push({
              targetType: 'item',
              itemId: item.id,
              itemName: item.name,
              columnId: col.id,
              columnTitle: columnTitleById.get(col.id) || col.id,
              before: text,
              after: matcher.replace(text)
            });
            if (effectiveMax && totalMatches >= effectiveMax) {
              limitReached = true;
              break;
            }
          }
        }

        if (targets.docs && docColumnIds.size > 0) {
          const docIdSet = parseDocIds(item.column_values, docColumnIds);
          docIdSet.forEach(id => docIds.add(id));
        }

        if (targets.subitems && item?.subitems?.length) {
          const subitems = Array.isArray(item.subitems)
            ? item.subitems.slice(0, MAX_SUBITEMS_PER_ITEM)
            : [];
          if (item.subitems.length > MAX_SUBITEMS_PER_ITEM) {
            console.warn(`[apply] requestId=${req.requestId} subitems capped at ${MAX_SUBITEMS_PER_ITEM} for item=${item.id}`);
          }
          for (const subitem of subitems) {
            if (!applyNameFilters(subitem?.name, filters.includeNameContains, filters.excludeNameContains)) {
              continue;
            }
            for (const col of subitem.column_values || []) {
              if (filters.includeColumnIds.length > 0 && !filters.includeColumnIds.includes(col.id)) continue;
              if (filters.excludeColumnIds.includes(col.id)) continue;
              const text = normalizeLineEndings(col?.text || '');
              if (!matcher.includes(text)) continue;
              const matchCount = matcher.count(text);
              if (matchCount === 0) continue;
              totalMatches += matchCount;
              changes.push({
                targetType: 'subitem',
                itemId: subitem.id,
                itemName: subitem.name,
                columnId: col.id,
                columnTitle: col.id,
                before: text,
                after: matcher.replace(text),
                subitemBoardId: subitem?.board?.id || null
              });
              if (effectiveMax && totalMatches >= effectiveMax) {
                limitReached = true;
                break;
              }
            }
            if (limitReached) break;
          }
        }

        if (limitReached) break;
      }

      if (limitReached) break;
    } while (cursor);

    const errors = [];
    let updated = 0;
    let skipped = 0;

    const updatesByTarget = new Map();
    const changesByTarget = new Map();
    for (const change of changes) {
      if (change.targetType === 'doc_block') continue;
      const boardKey = change.targetType === 'subitem' ? change.subitemBoardId : boardIdValue;
      if (!boardKey) {
        skipped += 1;
        insertAudit.run(
          runId,
          accountId,
          boardIdValue,
          change.targetType,
          change.itemId,
          change.columnId,
          change.itemName || null,
          change.columnTitle || null,
          change.before,
          change.after,
          'skipped',
          'Missing board id',
          Date.now()
        );
        continue;
      }
      const key = `${change.targetType}:${boardKey}:${change.itemId}`;
      if (!updatesByTarget.has(key)) {
        updatesByTarget.set(key, { boardId: boardKey, itemId: change.itemId, columnValues: {} });
      }
      if (!changesByTarget.has(key)) {
        changesByTarget.set(key, []);
      }
      updatesByTarget.get(key).columnValues[change.columnId] = change.after;
      changesByTarget.get(key).push(change);
    }

    const mutation = `
      mutation($boardId: ID!, $itemId: ID!, $columnValues: JSON!) {
        change_multiple_column_values(board_id: $boardId, item_id: $itemId, column_values: $columnValues) {
          id
        }
      }
    `;

    const updateTasks = Array.from(updatesByTarget.entries()).map(([key, payload]) => ({ key, payload }));
    await runWithConcurrency(updateTasks, async ({ key, payload }) => {
      try {
        await withRetry(() => axios.post('https://api.monday.com/v2', {
          query: mutation,
          variables: {
            boardId: payload.boardId,
            itemId: payload.itemId,
            columnValues: payload.columnValues
          }
        }, { headers: { Authorization: token } }));
        updated += 1;
        const changeList = changesByTarget.get(key) || [];
        changeList.forEach(change => {
          insertAudit.run(
            runId,
            accountId,
            boardIdValue,
            change.targetType,
            change.itemId,
            change.columnId,
            change.itemName || null,
            change.columnTitle || null,
            change.before,
            change.after,
            'success',
            null,
            Date.now()
          );
        });
      } catch (e) {
        skipped += 1;
        errors.push({ key, message: e?.response?.data || e?.message || 'Update failed' });
        const changeList = changesByTarget.get(key) || [];
        changeList.forEach(change => {
          insertAudit.run(
            runId,
            accountId,
            boardIdValue,
            change.targetType,
            change.itemId,
            change.columnId,
            change.itemName || null,
            change.columnTitle || null,
            change.before,
            change.after,
            'failed',
            String(e?.message || 'Update failed'),
            Date.now()
          );
        });
      }
      await sleep(120);
    }, 3);

    if (targets.docs && docIds.size > 0 && !(effectiveMax && totalMatches >= effectiveMax)) {
      for (const docId of docIds) {
        try {
          const { docName, blocks } = await fetchDocBlocks({ token, docId });
          for (const block of blocks) {
            const text = extractDocBlockText(block);
            if (!matcher.includes(text)) continue;
            const after = matcher.replace(text);
            await withRetry(() => updateDocBlock({ token, blockId: block.id, content: after }));
            updated += 1;
            insertAudit.run(
              runId,
              accountId,
              boardIdValue,
              'doc_block',
              docId,
              block.id,
              docName || null,
              block.type || null,
              text,
              after,
              'success',
              null,
              Date.now()
            );
            totalMatches += 1;
            if (effectiveMax && totalMatches >= effectiveMax) break;
          }
        } catch (e) {
          errors.push({ docId, message: e?.message || 'Doc update failed' });
          insertAudit.run(
            runId,
            accountId,
            boardIdValue,
            'doc_block',
            docId,
            null,
            null,
            null,
            null,
            null,
            'failed',
            String(e?.message || 'Doc update failed'),
            Date.now()
          );
        }
        if (effectiveMax && totalMatches >= effectiveMax) break;
      }
    }

    console.log(`[apply] requestId=${req.requestId} runId=${runId} updated=${updated} skipped=${skipped}`);
    return res.json({
      ok: true,
      requestId: req.requestId,
      runId,
      updated,
      skipped,
      errors,
      limitReached
    });
  } catch (err) {
    if (err?.response?.status === 401) {
      return res.status(401).json({ error: 'Unauthorized', code: 'AUTH_OAUTH_FAILED', requestId: req.requestId });
    }
    console.error(`[apply] failed requestId=${req.requestId} status=${err.response?.status || ''} message=${err.message || ''}`);
    return res.status(500).send('Apply failed');
  }
});

app.get('/api/audit', (req, res) => {
  const runId = req.query?.run_id || req.query?.runId;
  if (!runId) return res.status(400).send('Missing run_id');
  const rows = db.prepare('SELECT * FROM audit_log WHERE run_id = ? ORDER BY created_at ASC').all(runId);
  res.json({ ok: true, runId, rows });
});

app.listen(port, () => {
  const version = process.env.APP_VERSION || 'unknown';
  console.log(`Server on ${port} version=${version}`);
});
