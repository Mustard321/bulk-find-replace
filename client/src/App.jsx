import React, { useEffect, useMemo, useRef, useState } from 'react';
import mondaySdk from 'monday-sdk-js';
import './App.css';
import TopBar from './components/TopBar';
import Stepper from './components/Stepper';
import ScopeCard from './components/ScopeCard';
import FindReplaceForm from './components/FindReplaceForm';
import PreviewPanel from './components/PreviewPanel';
import ConfirmModal from './components/ConfirmModal';
import Toast from './components/Toast';
import useDebouncedValue from './utils/useDebouncedValue';

const PAGE_SIZE = 20;
const APPLY_AVAILABLE = false;

const InlineNotice = ({ tone = 'neutral', children }) => (
  <div className={`notice notice--${tone} surface-2`} role={tone === 'error' ? 'alert' : 'status'}>
    {children}
  </div>
);

export default function App() {
  const monday = useMemo(() => {
    if (window.__BFR_MONDAY) return window.__BFR_MONDAY;
    const sdk = window.mondaySdk ? window.mondaySdk() : mondaySdk();
    window.__BFR_MONDAY = sdk;
    return sdk;
  }, []);
  const API_BASE = import.meta.env.VITE_API_BASE_URL || '';
  const hasApiBase = Boolean(API_BASE);

  const [ctx, setCtx] = useState(null);
  const [ctxRaw, setCtxRaw] = useState(null);
  const [ctxErr, setCtxErr] = useState(null);
  const [find, setFind] = useState('');
  const [replace, setReplace] = useState('');
  const [preview, setPreview] = useState([]);
  const [summary, setSummary] = useState({ totalMatches: 0, totalItems: 0 });
  const [loading, setLoading] = useState(true);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [error, setError] = useState('');
  const [authRequired, setAuthRequired] = useState(false);
  const [boardId, setBoardId] = useState(null);
  const [oauthAccountId, setOauthAccountId] = useState('');
  const [sessionTokenInfo, setSessionTokenInfo] = useState({
    present: false,
    looksJwt: false,
    masked: ''
  });
  const [lastRequest, setLastRequest] = useState(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const [toast, setToast] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [showOnlyChanged, setShowOnlyChanged] = useState(true);
  const [compactView, setCompactView] = useState(false);
  const [page, setPage] = useState(1);
  const authPollRef = useRef(null);

  const debugEnabled = typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('debug') === '1';

  useEffect(() => {
    window.__BFR_APP_LOADED = true;
    window.__BFR_LOCATION = String(window.location.href);
    window.__BFR_IN_IFRAME = window.self !== window.top;
    window.__BFR_MONDAY = window.__BFR_MONDAY || monday;
  }, [monday]);

  useEffect(() => {
    let mounted = true;
    const normalizeContext = (data) => data?.data ?? data;
    const extractAccountId = (data) =>
      data?.data?.accountId ||
      data?.data?.account_id ||
      data?.data?.account?.id ||
      data?.data?.user?.account?.id ||
      data?.data?.user?.account_id ||
      data?.data?.user?.accountId ||
      null;
    const unsubscribe = monday.listen('context', (c) => {
      if (!mounted) return;
      setCtxRaw(c);
      const next = normalizeContext(c);
      setCtx(next);
      setBoardId(next?.boardId ?? next?.board?.id ?? null);
      const nextAccountId = extractAccountId(c);
      if (nextAccountId) setOauthAccountId(String(nextAccountId));
      setLoading(false);
    });
    monday
      .get('context')
      .then((res) => {
        if (!mounted) return;
        window.__BFR_CTX = res;
        window.__BFR_CTX_DATA = res?.data || null;
        setCtxRaw(res);
        const next = normalizeContext(res);
        if (next) setCtx(next);
        setBoardId(next?.boardId ?? next?.board?.id ?? null);
        const nextAccountId = extractAccountId(res);
        if (nextAccountId) setOauthAccountId(String(nextAccountId));
        setLoading(false);
      })
      .catch((e) => {
        const message = String(e?.message || e);
        setCtxErr(message);
        window.__BFR_CTX_ERR = message;
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
      unsubscribe?.();
    };
  }, [monday]);

  useEffect(() => () => {
    if (authPollRef.current) clearInterval(authPollRef.current);
  }, []);

  useEffect(() => {
    const handler = (e) => {
      if (e?.data?.type !== 'BFR_OAUTH_OK') return;
      const accountId = String(e.data.accountId || '');
      if (accountId) setOauthAccountId(accountId);
      if (!accountId) return;
      fetch(`${API_BASE}/api/auth/status?accountId=${encodeURIComponent(accountId)}`)
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => {
          if (d?.authorized) setAuthRequired(false);
        })
        .catch(() => {});
    };
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, [API_BASE]);

  const startAuthPoll = (accountId) => {
    if (authPollRef.current) clearInterval(authPollRef.current);
    let attempts = 0;
    authPollRef.current = setInterval(async () => {
      attempts += 1;
      if (attempts > 10) {
        clearInterval(authPollRef.current);
        authPollRef.current = null;
        return;
      }
      try {
        const r = await fetch(`${API_BASE}/api/auth/status?accountId=${encodeURIComponent(accountId)}`);
        if (!r.ok) return;
        const d = await r.json();
        if (d?.authorized) {
          setAuthRequired(false);
          clearInterval(authPollRef.current);
          authPollRef.current = null;
        }
      } catch {
        // ignore transient polling errors
      }
    }, 1000);
  };

  const formatTokenInfo = (token) => {
    const safe = token || '';
    const looksJwt = safe.split('.').length === 3;
    const masked = safe.length > 24 ? `${safe.slice(0, 12)}…${safe.slice(-8)}` : safe ? `${safe.slice(0, 6)}…` : '';
    return { present: Boolean(safe), looksJwt, masked };
  };

  const getSessionToken = async () => {
    try {
      const tokenRes = await monday.get('sessionToken');
      const token = tokenRes?.data || '';
      setSessionTokenInfo(formatTokenInfo(token));
      return token || null;
    } catch {
      setSessionTokenInfo({ present: false, looksJwt: false, masked: '' });
      return null;
    }
  };

  useEffect(() => {
    if (!ctxRaw) return;
    getSessionToken();
  }, [ctxRaw]);

  const accountId = oauthAccountId;
  const hasAccountId = Boolean(accountId);
  const authorizeUrl = hasApiBase && hasAccountId ? `${API_BASE.replace(/\/$/, '')}/auth/authorize?accountId=${encodeURIComponent(accountId)}` : '';

  async function previewRun() {
    setError('');
    setAuthRequired(false);
    setPreview([]);
    setSummary({ totalMatches: 0, totalItems: 0 });
    setPreviewLoading(true);

    if (!hasApiBase) {
      setError('Preview service is unavailable. Add VITE_API_BASE_URL and try again.');
      setPreviewLoading(false);
      return;
    }
    if (!accountId || !boardId) {
      setError('Open the app inside a board to load preview results.');
      setPreviewLoading(false);
      return;
    }
    const sessionToken = await getSessionToken();
    if (!sessionToken) {
      setError('Session token missing. Open the app inside Monday.');
      setPreviewLoading(false);
      return;
    }
    if (sessionToken.split('.').length !== 3) {
      setError('Session token is not a JWT. Open the app inside Monday.');
      setPreviewLoading(false);
      return;
    }

    const requestId = Date.now();
    const requestTime = new Date().toLocaleString();
    setLastRequest({ id: requestId, time: requestTime, endpoint: `${API_BASE}/api/preview`, status: '—' });

    try {
      const r = await fetch(`${API_BASE}/api/preview`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionToken}`
        },
        body: JSON.stringify({
          accountId,
          boardId,
          find,
          replace
        })
      });
      const raw = await r.text();
      setLastRequest({ id: requestId, time: requestTime, endpoint: `${API_BASE}/api/preview`, status: r.status });
      if (r.status === 401) {
        let payload;
        try {
          payload = raw ? JSON.parse(raw) : null;
        } catch {
          payload = null;
        }
        if (payload?.error === 'NOT_AUTHORIZED') {
          setAuthRequired(true);
          setError('Authorization is required before previewing.');
          return;
        }
      }
      if (!r.ok) {
        setError('We could not load preview results. Try again or open Diagnostics.');
        return;
      }
      let data;
      try {
        data = raw ? JSON.parse(raw) : null;
      } catch {
        data = raw;
      }
      const rows = (data?.rows || []).map((row) => ({
        ...row,
        findTerm: find,
        replaceTerm: replace
      }));
      setPreview(rows);
      setSummary({
        totalMatches: data?.totalMatches || 0,
        totalItems: data?.totalItems || 0
      });
      setToast(data?.totalMatches ? 'Preview ready.' : 'Preview ready. No matches found.');
    } catch (e) {
      setError('We could not load preview results. Try again or open Diagnostics.');
    } finally {
      setPreviewLoading(false);
    }
  }

  const findTrimmed = find.trim();
  const canPreview = Boolean(boardId) && findTrimmed.length >= 2 && !previewLoading && !loading && hasAccountId;
  const previewDisabled = !canPreview;
  const showError = Boolean(error) && !(authRequired && error === 'Authorization is required before previewing.');

  const debouncedSearch = useDebouncedValue(searchInput);
  const filteredRows = useMemo(() => {
    const term = debouncedSearch.trim().toLowerCase();
    return preview.filter((row) => {
      const isChanged = row.before !== row.after;
      if (showOnlyChanged && !isChanged) return false;
      if (!term) return true;
      const haystack = `${row.itemName} ${row.columnTitle} ${row.before} ${row.after}`.toLowerCase();
      return haystack.includes(term);
    });
  }, [preview, debouncedSearch, showOnlyChanged]);

  const totalPages = Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE));
  const pageRows = filteredRows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  useEffect(() => {
    setPage(1);
  }, [preview]);

  const currentStep = previewLoading || preview.length > 0 ? 3 : findTrimmed.length >= 2 ? 2 : 1;
  const applyDisabled = !APPLY_AVAILABLE;
  const applyTooltip = 'Apply will be enabled once bulk update is available. Preview is safe.';

  const DiagnosticsPanel = () => (
    <div className="diagnostics surface-2">
      <div className="diagnostics__grid">
        <div>
          <div className="diagnostics__label">Message</div>
          <div className="diagnostics__value">{error || 'None'}</div>
        </div>
        <div>
          <div className="diagnostics__label">Request id/time</div>
          <div className="diagnostics__value">
            {lastRequest ? `${lastRequest.id} · ${lastRequest.time}` : '—'}
          </div>
        </div>
        <div>
          <div className="diagnostics__label">Endpoint</div>
          <div className="diagnostics__value">{lastRequest?.endpoint || '—'}</div>
        </div>
        <div>
          <div className="diagnostics__label">Status code</div>
          <div className="diagnostics__value">{lastRequest?.status || '—'}</div>
        </div>
        <div>
          <div className="diagnostics__label">API base</div>
          <div className="diagnostics__value">{API_BASE || '—'}</div>
        </div>
        <div>
          <div className="diagnostics__label">Session token</div>
          <div className="diagnostics__value">
            {sessionTokenInfo.present
              ? `Present (${sessionTokenInfo.masked})`
              : 'Missing'}
          </div>
        </div>
      </div>
      <div className="diagnostics__actions">
        <a className="btn btn-secondary" href={`${API_BASE}/__debug/ping`} target="_blank" rel="noreferrer">
          Open ping
        </a>
        <a className="btn btn-secondary" href={`${API_BASE}/__debug/version`} target="_blank" rel="noreferrer">
          Version
        </a>
        <a className="btn btn-secondary" href={`${API_BASE}/api/debug/echo-auth`} target="_blank" rel="noreferrer">
          Echo auth
        </a>
        {authorizeUrl && (
          <a className="btn btn-secondary" href={authorizeUrl} target="_blank" rel="noreferrer">
            Authorize link
          </a>
        )}
      </div>
    </div>
  );

  return (
    <div className="app-shell">
      <TopBar onHelp={() => setHelpOpen(true)} />
      <main className="content">
        <Stepper currentStep={currentStep} connected={Boolean(boardId)} />

        {!hasApiBase && (
          <InlineNotice tone="error">Missing VITE_API_BASE_URL. Set the client env var and redeploy.</InlineNotice>
        )}
        {!hasAccountId && !loading && (
          <InlineNotice tone="error">Missing account context from Monday. Open the app inside Monday.</InlineNotice>
        )}
        {loading && <InlineNotice tone="neutral">Loading Monday context…</InlineNotice>}
        {!loading && !ctx && <InlineNotice tone="error">Unable to load Monday context.</InlineNotice>}
        {ctxErr && <InlineNotice tone="error">Context error: {ctxErr}</InlineNotice>}

        {showError && (
          <InlineNotice tone="error">
            {error}
            {debugEnabled && <DiagnosticsPanel />}
          </InlineNotice>
        )}

        {authRequired && (
          <section className="card surface">
            <div className="section-header">
              <h2>Authorize Mustard</h2>
              <span className="pill">Required</span>
            </div>
            <p className="muted">Connect your Monday account to load previews.</p>
            <div className="auth-actions">
              <button
                className="btn btn-primary"
                type="button"
                onClick={() => {
                  if (!hasAccountId) {
                    setError('Missing accountId.');
                    alert('Missing accountId from Monday context. Open console and screenshot debug box.');
                    return;
                  }
                  monday.execute('openLink', { url: authorizeUrl, target: 'newTab' });
                  startAuthPoll(accountId);
                }}
                disabled={!hasAccountId}
              >
                Authorize
              </button>
              <button
                className="btn btn-secondary"
                type="button"
                onClick={() => {
                  if (!authorizeUrl) return;
                  navigator.clipboard?.writeText(authorizeUrl).catch(() => {});
                }}
              >
                Copy link
              </button>
            </div>
            <div className="muted">If the popup is blocked, paste the copied link into a new tab.</div>
          </section>
        )}

        <ScopeCard boardId={boardId} ctxLoaded={!loading} />

        <FindReplaceForm
          find={find}
          replace={replace}
          setFind={setFind}
          setReplace={setReplace}
          onPreview={previewRun}
          previewDisabled={previewDisabled}
          previewLoading={previewLoading}
          canPreview={canPreview}
        />

        <PreviewPanel
          preview={preview}
          summary={summary}
          previewLoading={previewLoading}
          searchInput={searchInput}
          setSearchInput={setSearchInput}
          showOnlyChanged={showOnlyChanged}
          setShowOnlyChanged={setShowOnlyChanged}
          compactView={compactView}
          setCompactView={setCompactView}
          page={page}
          setPage={setPage}
          filteredRows={filteredRows}
          pageRows={pageRows}
          totalPages={totalPages}
          find={findTrimmed}
        />

        <section className="apply-bar panel">
          <div>
            <div className="apply-title">Apply changes</div>
            <div className="muted">Preview only</div>
          </div>
          <button
            className="btn btn-ink"
            type="button"
            disabled={applyDisabled}
            title={applyTooltip}
          >
            Apply changes
          </button>
        </section>
      </main>

      {helpOpen && (
        <ConfirmModal title="What this does" onClose={() => setHelpOpen(false)}>
          <div className="modal-content">
            <p>
              Bulk Find &amp; Replace scans text and long-text columns on the active board, previews matches, and keeps
              changes safe until bulk update is available.
            </p>
            <ul className="help-list">
              <li>Preview is always safe and doesn&apos;t change data.</li>
              <li>Review before/after diffs before deciding on next steps.</li>
              <li>Use Diagnostics only if preview results fail to load.</li>
            </ul>
            <button
              className="btn btn-secondary"
              type="button"
              onClick={() => setShowDiagnostics((prev) => !prev)}
            >
              {showDiagnostics ? 'Hide diagnostics' : 'Diagnostics'}
            </button>
            {showDiagnostics && <DiagnosticsPanel />}
          </div>
        </ConfirmModal>
      )}

      {toast && <Toast message={toast} onClose={() => setToast('')} />}
    </div>
  );
}
