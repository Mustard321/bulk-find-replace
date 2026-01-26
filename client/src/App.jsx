import React, { useEffect, useMemo, useRef, useState } from 'react';
import mondaySdk from 'monday-sdk-js';
import './App.css';

const STEP_LABELS = ['Choose scope', 'Find & replace', 'Preview & apply'];
const PAGE_SIZE = 20;

const useDebouncedValue = (value, delay = 250) => {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const handle = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(handle);
  }, [value, delay]);
  return debounced;
};

const LogoWordmark = () => (
  <div className="wordmark" aria-label="mustard">
    <span className="wordmark__primary">mustard</span>
  </div>
);

const TopBar = ({ onHelp }) => (
  <header className="topbar">
    <div className="topbar__brand">
      <LogoWordmark />
      <div className="topbar__subtitle">Bulk Find &amp; Replace</div>
    </div>
    <button className="ghost-button" type="button" onClick={onHelp}>
      What this does
    </button>
  </header>
);

const Stepper = ({ currentStep }) => (
  <div className="stepper" role="list">
    {STEP_LABELS.map((label, index) => {
      const stepIndex = index + 1;
      const isActive = stepIndex === currentStep;
      const isComplete = stepIndex < currentStep;
      return (
        <div key={label} className={`stepper__step ${isActive ? 'is-active' : ''} ${isComplete ? 'is-complete' : ''}`} role="listitem">
          <div className="stepper__badge">{stepIndex}</div>
          <div className="stepper__label">{label}</div>
        </div>
      );
    })}
  </div>
);

const InlineNotice = ({ tone = 'neutral', children }) => (
  <div className={`notice notice--${tone}`} role={tone === 'error' ? 'alert' : 'status`}>
    {children}
  </div>
);

const Modal = ({ title, children, onClose }) => {
  const modalRef = useRef(null);
  useEffect(() => {
    const el = modalRef.current;
    if (!el) return;
    const focusable = el.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    first?.focus();
    const handleKey = (event) => {
      if (event.key === 'Escape') onClose();
      if (event.key !== 'Tab' || focusable.length === 0) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      }
      if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    el.addEventListener('keydown', handleKey);
    return () => el.removeEventListener('keydown', handleKey);
  }, [onClose]);

  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} onClick={(e) => e.stopPropagation()} ref={modalRef}>
        <div className="modal__header">
          <h3>{title}</h3>
          <button className="ghost-button" type="button" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="modal__body">{children}</div>
      </div>
    </div>
  );
};

const ScopeSelector = ({ boardId, ctxLoaded }) => (
  <section className="card card--padded">
    <div className="section-header">
      <h2>Step 1 · Choose scope</h2>
      <span className="pill">Safe</span>
    </div>
    <div className="scope-grid">
      <div className="scope-item">
        <div className="scope-label">Board</div>
        <div className="scope-value">{ctxLoaded ? (boardId || 'Waiting for board') : 'Loading context…'}</div>
        <div className="scope-hint">Bulk find &amp; replace runs on the active board.</div>
      </div>
      <div className="scope-item is-muted">
        <div className="scope-label">Columns</div>
        <div className="scope-value">All text + long text columns</div>
        <div className="scope-hint">Auto-selected to keep results consistent.</div>
      </div>
      <div className="scope-item is-muted">
        <div className="scope-label">Filters</div>
        <div className="scope-value">Optional</div>
        <div className="scope-hint">Filtering is coming soon.</div>
      </div>
    </div>
  </section>
);

const FindReplaceForm = ({ find, replace, setFind, setReplace, onPreview, previewDisabled, previewLoading }) => (
  <section className="card card--padded">
    <div className="section-header">
      <h2>Step 2 · Find &amp; replace</h2>
      <span className="pill">Safe</span>
    </div>
    <div className="form-grid">
      <label className="field">
        <span className="field__label">Find</span>
        <input
          value={find}
          onChange={(e) => setFind(e.target.value)}
          placeholder="Text to find"
        />
      </label>
      <label className="field">
        <span className="field__label">Replace with</span>
        <input
          value={replace}
          onChange={(e) => setReplace(e.target.value)}
          placeholder="Replacement text (optional)"
        />
      </label>
      <div className="form-actions">
        <button className="primary-button" type="button" onClick={onPreview} disabled={previewDisabled}>
          {previewLoading ? 'Previewing…' : 'Preview changes'}
        </button>
        <div className="form-note">Preview is a safe dry run. No changes are applied yet.</div>
      </div>
    </div>
  </section>
);

const SummaryCard = ({ label, value }) => (
  <div className="summary-card">
    <div className="summary-card__label">{label}</div>
    <div className="summary-card__value">{value}</div>
  </div>
);

const highlightText = (text, term) => {
  if (!term) return [text];
  const parts = String(text).split(term);
  return parts.flatMap((part, index) => {
    if (index === parts.length - 1) return [part];
    return [
      part,
      <mark key={`${part}-${index}`} className="diff-highlight">
        {term}
      </mark>
    ];
  });
};

const DiffRow = ({ row, find, replace, compact }) => (
  <div className={`diff-row ${compact ? 'is-compact' : ''}`}>
    <div className="diff-meta">
      <div className="diff-title">{row.itemName}</div>
      <div className="diff-subtitle">{row.columnTitle}</div>
    </div>
    <div className="diff-values">
      <div className="diff-cell">
        <div className="diff-label">Before</div>
        <div className="diff-text">{highlightText(row.before || '—', find)}</div>
      </div>
      <div className="diff-cell">
        <div className="diff-label">After</div>
        <div className="diff-text">{highlightText(row.after || '—', replace || '')}</div>
      </div>
    </div>
  </div>
);

const PreviewPanel = ({
  preview,
  summary,
  previewLoading,
  searchInput,
  setSearchInput,
  showOnlyChanged,
  setShowOnlyChanged,
  compactView,
  setCompactView,
  page,
  setPage,
  filteredRows,
  pageRows
}) => {
  const totalPages = Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE));

  return (
    <section className="card card--padded">
      <div className="section-header">
        <h2>Step 3 · Preview &amp; apply</h2>
        <span className="pill pill--warn">Destructive</span>
      </div>
      <div className="summary-grid">
        <SummaryCard label="Items matched" value={summary.totalItems} />
        <SummaryCard label="Fields affected" value={preview.length} />
        <SummaryCard label="Estimated changes" value={summary.totalMatches} />
      </div>

      <div className="preview-toolbar">
        <label className="search-field">
          <span className="sr-only">Search preview</span>
          <input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search within preview"
          />
        </label>
        <label className="toggle">
          <input
            type="checkbox"
            checked={showOnlyChanged}
            onChange={(e) => setShowOnlyChanged(e.target.checked)}
          />
          <span>Show only changed</span>
        </label>
        <label className="toggle">
          <input
            type="checkbox"
            checked={compactView}
            onChange={(e) => setCompactView(e.target.checked)}
          />
          <span>Compact view</span>
        </label>
      </div>

      {previewLoading && (
        <div className="skeleton-stack">
          {Array.from({ length: 4 }).map((_, idx) => (
            <div className="skeleton" key={`skeleton-${idx}`} />
          ))}
        </div>
      )}

      {!previewLoading && preview.length === 0 && (
        <InlineNotice tone="neutral">No preview results yet. Run a preview to see changes.</InlineNotice>
      )}

      {!previewLoading && preview.length > 0 && filteredRows.length === 0 && (
        <InlineNotice tone="neutral">No rows match the current filters.</InlineNotice>
      )}

      {!previewLoading && pageRows.length > 0 && (
        <div className="diff-list">
          {pageRows.map((row, index) => (
            <DiffRow key={`${row.itemId}-${row.columnId}-${index}`} row={row} find={row.findTerm} replace={row.replaceTerm} compact={compactView} />
          ))}
        </div>
      )}

      {!previewLoading && filteredRows.length > PAGE_SIZE && (
        <div className="pagination">
          <button className="ghost-button" type="button" onClick={() => setPage(Math.max(1, page - 1))} disabled={page === 1}>
            Previous
          </button>
          <div className="pagination__status">
            Page {page} of {totalPages}
          </div>
          <button className="ghost-button" type="button" onClick={() => setPage(Math.min(totalPages, page + 1))} disabled={page === totalPages}>
            Next
          </button>
        </div>
      )}
    </section>
  );
};

const ApplyConfirmModal = ({ summary, onClose, onConfirm }) => {
  const [confirmed, setConfirmed] = useState(false);
  return (
    <Modal title="Confirm apply" onClose={onClose}>
      <div className="modal-content">
        <p>Review the impact before applying changes.</p>
        <div className="modal-summary">
          <SummaryCard label="Items" value={summary.totalItems} />
          <SummaryCard label="Matches" value={summary.totalMatches} />
        </div>
        <label className="toggle">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
          />
          <span>I understand this will modify {summary.totalItems} items.</span>
        </label>
        <InlineNotice tone="neutral">Dry run only in this build. No changes are applied.</InlineNotice>
        <div className="modal-actions">
          <button className="ghost-button" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary-button" type="button" disabled={!confirmed} onClick={onConfirm}>
            Apply changes
          </button>
        </div>
      </div>
    </Modal>
  );
};

const DiagnosticsPanel = ({ error, lastRequest, apiBase, sessionTokenInfo, authorizeUrl }) => (
  <details className="diagnostics">
    <summary>Diagnostics</summary>
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
        <div className="diagnostics__value">{apiBase || '—'}</div>
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
      <a className="ghost-button" href={`${apiBase}/__debug/ping`} target="_blank" rel="noreferrer">
        Open ping
      </a>
      <a className="ghost-button" href={`${apiBase}/__debug/version`} target="_blank" rel="noreferrer">
        Version
      </a>
      <a className="ghost-button" href={`${apiBase}/api/debug/echo-auth`} target="_blank" rel="noreferrer">
        Echo auth
      </a>
      {authorizeUrl && (
        <a className="ghost-button" href={authorizeUrl} target="_blank" rel="noreferrer">
          Authorize link
        </a>
      )}
    </div>
  </details>
);

const Toast = ({ message, onClose }) => (
  <div className="toast" role="status">
    <span>{message}</span>
    <button className="ghost-button" type="button" onClick={onClose}>
      Dismiss
    </button>
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
  const [applyOpen, setApplyOpen] = useState(false);
  const [toast, setToast] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [showOnlyChanged, setShowOnlyChanged] = useState(true);
  const [compactView, setCompactView] = useState(false);
  const [page, setPage] = useState(1);
  const authPollRef = useRef(null);

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

  useEffect(() => {
    setPage(1);
  }, [searchInput, showOnlyChanged, compactView, preview]);

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
      setError('We could not reach the preview service. Add VITE_API_BASE_URL and redeploy.');
      setPreviewLoading(false);
      return;
    }
    if (!accountId || !boardId) {
      setError('Waiting for board context. Please reopen the app inside a board.');
      setPreviewLoading(false);
      return;
    }
    const sessionToken = await getSessionToken();
    if (!sessionToken) {
      setError('No Monday session token. Open the app inside Monday.');
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
        setError('We could not load preview results. Try again, or open Diagnostics.');
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
    } catch (e) {
      setError('We could not load preview results. Try again, or open Diagnostics.');
    } finally {
      setPreviewLoading(false);
    }
  }

  const previewDisabled = !boardId || !find || previewLoading || loading || !accountId;
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

  const pageRows = filteredRows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const currentStep = previewLoading || preview.length > 0 ? 3 : find || replace ? 2 : 1;

  const applyDisabled = previewLoading || preview.length === 0 || summary.totalMatches === 0;

  return (
    <div className="app-shell">
      <TopBar onHelp={() => setHelpOpen(true)} />
      <main className="content">
        <Stepper currentStep={currentStep} />

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
            <DiagnosticsPanel
              error={error}
              lastRequest={lastRequest}
              apiBase={API_BASE}
              sessionTokenInfo={sessionTokenInfo}
              authorizeUrl={authorizeUrl}
            />
          </InlineNotice>
        )}

        {authRequired && (
          <div className="card card--padded">
            <div className="section-header">
              <h2>Authorize Mustard</h2>
              <span className="pill">Required</span>
            </div>
            <p>Before running preview, connect your Monday account.</p>
            <div className="auth-actions">
              <button
                className="primary-button"
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
                className="ghost-button"
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
          </div>
        )}

        <ScopeSelector boardId={boardId} ctxLoaded={!loading} />

        <FindReplaceForm
          find={find}
          replace={replace}
          setFind={setFind}
          setReplace={setReplace}
          onPreview={previewRun}
          previewDisabled={previewDisabled}
          previewLoading={previewLoading}
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
        />

        <section className="apply-bar">
          <div>
            <div className="apply-title">Apply changes</div>
            <div className="muted">Dry run / preview only</div>
          </div>
          <button className="primary-button" type="button" onClick={() => setApplyOpen(true)} disabled={applyDisabled}>
            Apply changes
          </button>
        </section>
      </main>

      {helpOpen && (
        <Modal title="What this does" onClose={() => setHelpOpen(false)}>
          <div className="modal-content">
            <p>
              Bulk Find &amp; Replace scans all text and long-text columns on the current board, previews the changes, and
              lets you apply them deliberately.
            </p>
            <ul className="help-list">
              <li>Preview is always safe and doesn&apos;t change data.</li>
              <li>Review matches in the diff list before applying.</li>
              <li>Use Diagnostics if preview results fail to load.</li>
            </ul>
          </div>
        </Modal>
      )}

      {applyOpen && (
        <ApplyConfirmModal
          summary={summary}
          onClose={() => setApplyOpen(false)}
          onConfirm={() => {
            setApplyOpen(false);
            setToast('Preview-only mode: no changes were applied.');
          }}
        />
      )}

      {toast && <Toast message={toast} onClose={() => setToast('')} />}
    </div>
  );
}
