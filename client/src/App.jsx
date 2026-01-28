import React, { useEffect, useMemo, useRef, useState } from 'react';
import mondaySdk from 'monday-sdk-js';
import './App.css';
import TopBar from './components/TopBar';
import Stepper from './components/Stepper';
import ScopeSummaryCard from './components/ScopeSummaryCard';
import WhereToLookCard from './components/WhereToLookCard';
import WhatToChangeCard from './components/WhatToChangeCard';
import SafetyCard from './components/SafetyCard';
import PreviewPanel from './components/PreviewPanel';
import ConfirmModal from './components/ConfirmModal';
import Toast from './components/Toast';
import useDebouncedValue from './utils/useDebouncedValue';
import { formatNumber } from './utils/formatters.jsx';

const PAGE_SIZE = 200;
const APPLY_AVAILABLE = true;
const AUTH_EXPIRED_MESSAGE = 'Session expired. Reload the app.';
const OAUTH_REQUIRED_MESSAGE = 'Connect Mustard to Monday to load board fields and run previews.';
const ONBOARDING_KEY = 'mustard_bfr_seen_onboarding';
const DRY_RUN_KEY = 'mustard_bfr_dry_run';
const META_CACHE_KEY = '__BFR_BOARD_META_CACHE';
const RELOAD_ATTEMPT_KEY = 'bfr_reload_attempted';

const InlineNotice = ({ tone = 'neutral', children }) => (
  <div className={`notice notice--${tone} surface-2`} role={tone === 'error' ? 'alert' : 'status'}>
    {children}
  </div>
);

const parseFreeformList = (value) =>
  String(value || '')
    .split(/[\n,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);

const formatRequestError = (message, requestId) =>
  requestId ? `${message} Request ID: ${requestId}.` : message;

export default function App() {
  const monday = useMemo(() => {
    if (window.__BFR_MONDAY) return window.__BFR_MONDAY;
    const sdk = window.mondaySdk ? window.mondaySdk() : mondaySdk();
    window.__BFR_MONDAY = sdk;
    return sdk;
  }, []);
  const API_BASE = import.meta.env.VITE_API_BASE_URL || '';
  const hasApiBase = Boolean(API_BASE);
  const buildId = import.meta.env.VITE_COMMIT_SHA || import.meta.env.VITE_APP_VERSION || 'unknown';
  const buildEnv = import.meta.env.PROD ? 'production' : import.meta.env.MODE || 'unknown';

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
  const [authIssue, setAuthIssue] = useState(null);
  const [boardId, setBoardId] = useState(null);
  const [oauthAccountId, setOauthAccountId] = useState('');
  const [sessionTokenInfo, setSessionTokenInfo] = useState({
    present: false,
    looksJwt: false,
    length: 0,
    tail: ''
  });
  const [lastRequest, setLastRequest] = useState(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const [toast, setToast] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [showOnlyChanged, setShowOnlyChanged] = useState(true);
  const [compactView, setCompactView] = useState(false);
  const [cursorStack, setCursorStack] = useState([null]);
  const [cursorIndex, setCursorIndex] = useState(0);
  const [nextCursor, setNextCursor] = useState(null);
  const [warnings, setWarnings] = useState([]);
  const [applyOpen, setApplyOpen] = useState(false);
  const [confirmText, setConfirmText] = useState('');
  const [confirmUnderstood, setConfirmUnderstood] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [applyLoading, setApplyLoading] = useState(false);
  const [applyProgress, setApplyProgress] = useState(0);
  const [applyTotal, setApplyTotal] = useState(0);
  const [applyFailures, setApplyFailures] = useState(0);
  const [lastRunId, setLastRunId] = useState('');
  const [previewRunId, setPreviewRunId] = useState('');
  const [applyResult, setApplyResult] = useState(null);
  const [onboardingOpen, setOnboardingOpen] = useState(false);
  const [dryRun, setDryRun] = useState(true);
  const [reloadAttempted, setReloadAttempted] = useState(false);
  const [lastAuthRefresh, setLastAuthRefresh] = useState('');
  const [lastRequestStatus, setLastRequestStatus] = useState('—');
  const [popupBlocked, setPopupBlocked] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const applyTimerRef = useRef(null);
  const lastFailedActionRef = useRef(null);
  const authRetryRef = useRef(false);

  const [targets, setTargets] = useState({ items: true, subitems: false, docs: false });
  const [rules, setRules] = useState({ caseSensitive: false, wholeWord: false });
  const [columnScope, setColumnScope] = useState('all');
  const [includeColumnIds, setIncludeColumnIds] = useState([]);
  const [excludeColumnIds, setExcludeColumnIds] = useState([]);
  const [includeGroupIds, setIncludeGroupIds] = useState([]);
  const [includeNameContains, setIncludeNameContains] = useState('');
  const [excludeNameContains, setExcludeNameContains] = useState('');
  const [docIdsText, setDocIdsText] = useState('');
  const [limit, setLimit] = useState({ maxChanges: 250 });
  const [boardMeta, setBoardMeta] = useState({ columns: [], groups: [] });
  const [metaLoading, setMetaLoading] = useState(false);
  const [metaError, setMetaError] = useState('');

  const authPollRef = useRef(null);

  const debugEnabled = typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('debug') === '1';

  useEffect(() => {
    window.__BFR_APP_LOADED = true;
    window.__BFR_LOCATION = String(window.location.href);
    window.__BFR_IN_IFRAME = window.self !== window.top;
    window.__BFR_MONDAY = window.__BFR_MONDAY || monday;
  }, [monday]);

  const decodeJwtPayload = (token) => {
    if (!token) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    try {
      const base = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      const padded = base.padEnd(Math.ceil(base.length / 4) * 4, '=');
      return JSON.parse(atob(padded));
    } catch {
      return null;
    }
  };

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
      data?.accountId ||
      data?.account_id ||
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

  useEffect(() => () => {
    if (applyTimerRef.current) clearInterval(applyTimerRef.current);
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const seen = window.localStorage.getItem(ONBOARDING_KEY) === 'true';
    if (!seen) {
      setOnboardingOpen(true);
      window.localStorage.setItem(ONBOARDING_KEY, 'true');
    }
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const saved = window.localStorage.getItem(DRY_RUN_KEY);
    if (saved === null) {
      setDryRun(true);
      window.localStorage.setItem(DRY_RUN_KEY, 'true');
    } else {
      setDryRun(saved === 'true');
    }
  }, []);

  useEffect(() => {
    if (applyOpen) return;
    setConfirmText('');
    setConfirmUnderstood(false);
    setConfirmRemove(false);
  }, [applyOpen]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const attempted = window.sessionStorage.getItem(RELOAD_ATTEMPT_KEY) === 'true';
    setReloadAttempted(attempted);
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (!authIssue || authIssue !== 'session') {
      window.sessionStorage.removeItem(RELOAD_ATTEMPT_KEY);
      setReloadAttempted(false);
    }
  }, [authIssue]);

  const loadBoardMeta = async () => {
    if (!boardId || !accountId) {
      setMetaError('Waiting for Monday context…');
      return;
    }
    if (typeof window === 'undefined') return;
    const cacheStore = window[META_CACHE_KEY] || {};
    if (cacheStore[boardId]) {
      setBoardMeta(cacheStore[boardId]);
      setMetaLoading(false);
      return;
    }
    setMetaLoading(true);
    setMetaError('');
    try {
      const res = await monday.api(
        `query($id: ID!) {
          boards(ids: [$id]) {
            columns { id title type }
            groups { id title }
          }
        }`,
        { variables: { id: boardId } }
      );
      const board = res?.data?.boards?.[0];
      const nextMeta = {
        columns: board?.columns || [],
        groups: board?.groups || []
      };
      setBoardMeta(nextMeta);
      window[META_CACHE_KEY] = { ...cacheStore, [boardId]: nextMeta };
    } catch (err) {
      if (!boardId || !accountId) {
        setMetaError('Waiting for Monday context…');
      } else {
        setMetaError(String(err?.message || 'Unable to load fields or groups.'));
      }
      setBoardMeta({ columns: [], groups: [] });
    } finally {
      setMetaLoading(false);
    }
  };

  const handleAuthSuccess = (incomingAccountId) => {
    const nextAccountId = String(incomingAccountId || '');
    if (nextAccountId) setOauthAccountId(nextAccountId);
    if (!nextAccountId) return;
    fetch(`${API_BASE}/api/auth/status?accountId=${encodeURIComponent(nextAccountId)}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d?.connected || d?.authorized) {
          setAuthIssue(null);
          authRetryRef.current = false;
          if (typeof window !== 'undefined') {
            const cacheStore = window[META_CACHE_KEY] || {};
            delete cacheStore[boardId];
            window[META_CACHE_KEY] = cacheStore;
          }
          loadBoardMeta();
          if (!authRetryRef.current) {
            authRetryRef.current = true;
            retryLastAction();
          }
        } else if (d?.code === 'AUTH_NOT_CONNECTED') {
          setAuthIssue('oauth');
          setError(OAUTH_REQUIRED_MESSAGE);
        }
        setIsConnecting(false);
      })
      .catch(() => {});
  };

  useEffect(() => {
    const handler = (e) => {
      if (!e?.data?.type) return;
      if (e.data.type !== 'BFR_OAUTH_OK' && e.data.type !== 'mustard_oauth_success' && e.data.type !== 'MUSTARD_OAUTH_SUCCESS') return;
      handleAuthSuccess(e.data.accountId);
    };
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, [API_BASE]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('authorized') === '1' && accountId) {
      startAuthPoll(accountId);
    }
  }, [accountId]);

  const startAuthPoll = (accountId) => {
    if (authPollRef.current) clearInterval(authPollRef.current);
    let attempts = 0;
    setIsConnecting(true);
    authPollRef.current = setInterval(async () => {
      attempts += 1;
      if (attempts > 30) {
        clearInterval(authPollRef.current);
        authPollRef.current = null;
        setIsConnecting(false);
        return;
      }
      try {
        const r = await fetch(`${API_BASE}/api/auth/status?accountId=${encodeURIComponent(accountId)}`);
        if (!r.ok) return;
        const d = await r.json();
        if (d?.connected || d?.authorized) {
          setAuthIssue(null);
          retryLastAction();
          clearInterval(authPollRef.current);
          authPollRef.current = null;
          setIsConnecting(false);
        }
      } catch {
        // ignore transient polling errors
      }
    }, 1000);
  };

  const formatTokenInfo = (token) => {
    const safe = token || '';
    const looksJwt = safe.split('.').length === 3;
    const length = safe.length;
    const tail = safe.length >= 6 ? safe.slice(-6) : safe;
    return { present: Boolean(safe), looksJwt, length, tail };
  };

  const getSessionToken = async () => {
    try {
      const tokenRes = await monday.get('sessionToken');
      const token = tokenRes?.data || '';
      setSessionTokenInfo(formatTokenInfo(token));
      setLastAuthRefresh(new Date().toLocaleString());
      if (!oauthAccountId) {
        const payload = decodeJwtPayload(token);
        const datAccountId = payload?.dat?.account_id || payload?.data?.dat?.account_id || payload?.account_id || null;
        if (datAccountId) setOauthAccountId(String(datAccountId));
      }
      return token || null;
    } catch {
      setSessionTokenInfo({ present: false, looksJwt: false, length: 0, tail: '' });
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

  const textColumns = useMemo(
    () =>
      (boardMeta.columns || [])
        .filter((col) => col.type === 'text' || col.type === 'long_text')
        .map((col) => ({ id: col.id, label: col.title })),
    [boardMeta.columns]
  );
  const groupOptions = useMemo(
    () => (boardMeta.groups || []).map((group) => ({ id: group.id, label: group.title })),
    [boardMeta.groups]
  );

  const handleReconnect = () => {
    setError('');
    setAuthIssue(null);
    // sessionToken is per iframe session; OAuth token lives server-side.
    // A reload is the correct recovery for an expired sessionToken.
    if (typeof window !== 'undefined') {
      window.sessionStorage.setItem(RELOAD_ATTEMPT_KEY, 'true');
      window.location.reload();
    }
  };

  const handleOAuthReconnect = () => {
    setError('');
    setAuthIssue(null);
    setPopupBlocked(false);
    if (!hasAccountId) {
      setError('Missing accountId.');
      return;
    }
    if (!authorizeUrl) {
      setError('Authorization URL is unavailable. Check VITE_API_BASE_URL.');
      return;
    }
    const popup = window.open(authorizeUrl, '_blank', 'noopener,noreferrer');
    if (!popup) {
      setPopupBlocked(true);
      return;
    }
    startAuthPoll(accountId);
  };

  const apiRequest = async ({ path, body }) => {
    const parseAuthCode = (text) => {
      try {
        const payload = text ? JSON.parse(text) : null;
        return payload?.code || '';
      } catch {
        return '';
      }
    };
    const attempt = async () => {
      const token = await getSessionToken();
      if (!token) return { error: 'NO_TOKEN' };
      const response = await fetch(`${API_BASE}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(body)
      });
      setLastRequestStatus(String(response.status));
      const text = await response.text();
      return { response, text };
    };

    let result = await attempt();
    if (result?.error === 'NO_TOKEN') {
      setAuthIssue('session');
      setError(AUTH_EXPIRED_MESSAGE);
      return null;
    }
    if (result?.response?.status === 401) {
      result = await attempt();
      if (result?.error === 'NO_TOKEN') {
        setAuthIssue('session');
        setError(AUTH_EXPIRED_MESSAGE);
        return null;
      }
      if (result?.response?.status === 401) {
        const code = parseAuthCode(result.text);
        if (code === 'AUTH_NOT_CONNECTED' || code === 'AUTH_OAUTH_FAILED') {
          setMetaError('');
          setAuthIssue('oauth');
          setError(OAUTH_REQUIRED_MESSAGE);
        } else if (code === 'AUTH_SESSION_INVALID') {
          setAuthIssue('session');
          setError(AUTH_EXPIRED_MESSAGE);
        } else {
          setAuthIssue('session');
          setError(AUTH_EXPIRED_MESSAGE);
        }
        return null;
      }
    }
    setAuthIssue(null);
    return result;
  };

  const handleRetryMeta = () => {
    if (typeof window !== 'undefined') {
      const cacheStore = window[META_CACHE_KEY] || {};
      delete cacheStore[boardId];
      window[META_CACHE_KEY] = cacheStore;
    }
    setMetaError('');
    loadBoardMeta();
  };
  useEffect(() => {
    if (!boardId || !accountId) return () => {};
    loadBoardMeta();
    return () => {};
  }, [boardId, accountId, authIssue]);

  const setDryRunPreference = (value) => {
    setDryRun(value);
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(DRY_RUN_KEY, value ? 'true' : 'false');
    }
  };

  const buildPayload = (cursor) => ({
    accountId,
    boardId,
    find,
    replace,
    targets,
    rules,
    filters: {
      includeColumnIds: columnScope === 'custom' ? includeColumnIds : [],
      excludeColumnIds: excludeColumnIds,
      includeGroupIds: includeGroupIds,
      excludeGroupIds: [],
      includeNameContains: includeNameContains ? [includeNameContains] : [],
      excludeNameContains: excludeNameContains ? [excludeNameContains] : [],
      docIds: parseFreeformList(docIdsText)
    },
    limit: {
      maxChanges: limit.maxChanges ? Number(limit.maxChanges) : undefined
    },
    pagination: {
      cursor,
      pageSize: PAGE_SIZE
    }
  });

  const runPreview = async ({ cursor = null, reset = false } = {}) => {
    setError('');
    setAuthIssue(null);
    setPreview([]);
    setSummary({ totalMatches: 0, totalItems: 0 });
    setPreviewLoading(true);
    setWarnings([]);
    setApplyResult(null);
    lastFailedActionRef.current = { type: 'preview', cursor, reset };

    if (find.trim() && replace === find) {
      setError('Nothing to change.');
      setPreviewLoading(false);
      return;
    }

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
    if (reset) {
      setCursorStack([null]);
      setCursorIndex(0);
    }

    const requestId = Date.now();
    const requestTime = new Date().toLocaleString();
    setLastRequest({ id: requestId, time: requestTime, endpoint: `${API_BASE}/api/preview`, status: '—' });

    try {
      const result = await apiRequest({ path: '/api/preview', body: buildPayload(cursor) });
      if (!result) return;
      const responseRequestId = result.response.headers.get('x-request-id') || '';
      setLastRequest({ id: requestId, time: requestTime, endpoint: `${API_BASE}/api/preview`, status: result.response.status, requestId: responseRequestId });
      if (!result.response.ok) {
        setError(formatRequestError('We could not load preview results. Try again or open Diagnostics.', responseRequestId));
        return;
      }
      let data;
      try {
        data = result.text ? JSON.parse(result.text) : null;
      } catch {
        data = result.text;
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
      setNextCursor(data?.nextCursor || null);
      setWarnings(data?.warnings || []);
      setPreviewRunId(data?.runId || '');
      setToast(data?.totalMatches ? 'Preview ready.' : 'Preview ready. No matches found.');
    } catch (e) {
      setError('We could not load preview results. Try again or open Diagnostics.');
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleNextPage = () => {
    if (!nextCursor) return;
    const newStack = [...cursorStack, nextCursor];
    setCursorStack(newStack);
    setCursorIndex(newStack.length - 1);
    runPreview({ cursor: nextCursor });
  };

  const handlePrevPage = () => {
    if (cursorIndex === 0) return;
    const prevCursor = cursorStack[cursorIndex - 1] || null;
    setCursorIndex(cursorIndex - 1);
    runPreview({ cursor: prevCursor });
  };

  const runApply = async () => {
    if (find.trim() && replace === find) {
      setError('Nothing to change.');
      return;
    }
    if (!confirmText || confirmText.trim().toUpperCase() !== 'APPLY') {
      setError('Type APPLY to confirm.');
      return;
    }
    if (!confirmUnderstood || (replace.length === 0 && !confirmRemove)) {
      setError('Confirm the acknowledgement to continue.');
      return;
    }
    lastFailedActionRef.current = { type: 'apply' };
    if (dryRun) {
      const counts = buildApplyCounts();
      setApplyResult({ mode: 'dry', ...counts });
      setToast(`Dry run complete. Would apply ${formatNumber(counts.updates)} updates.`);
      setApplyOpen(false);
      return;
    }
    setApplyLoading(true);
    setError('');
    setAuthIssue(null);
    setApplyTotal(summary.totalMatches || 0);
    setApplyProgress(0);
    setApplyFailures(0);
    if (applyTimerRef.current) clearInterval(applyTimerRef.current);
    if (summary.totalMatches) {
      applyTimerRef.current = setInterval(() => {
        setApplyProgress((prev) => {
          const next = prev + Math.max(1, Math.ceil(summary.totalMatches / 20));
          return Math.min(next, summary.totalMatches);
        });
      }, 350);
    }

    try {
      const result = await apiRequest({
        path: '/api/apply',
        body: {
          ...buildPayload(null),
          runId: previewRunId || undefined,
          confirmText: confirmText.trim().toUpperCase()
        }
      });
      if (!result) return;
      const responseRequestId = result.response.headers.get('x-request-id') || '';
      setLastRequest({ id: Date.now(), time: new Date().toLocaleString(), endpoint: `${API_BASE}/api/apply`, status: result.response.status, requestId: responseRequestId });
      if (!result.response.ok) {
        setError(formatRequestError('Couldn’t apply changes. Try again. If it persists, open Diagnostics and share Request ID.', responseRequestId));
        return;
      }
      let data;
      try {
        data = result.text ? JSON.parse(result.text) : null;
      } catch {
        data = null;
      }
      if (data?.runId) setLastRunId(data.runId);
      setApplyProgress(data?.updated || 0);
      setApplyFailures(data?.errors?.length || 0);
      setToast(`Applied ${data?.updated || 0} updates.`);
      setApplyResult({ mode: 'apply', ...buildApplyCounts(), runId: data?.runId || '' });
      try {
        await monday.execute?.('reloadBoard');
      } catch {}
      try {
        await monday.execute?.('reload');
      } catch {}
      try {
        await monday.execute?.('refresh');
      } catch {}
      setApplyOpen(false);
      setDryRunPreference(false);
    } catch (e) {
      setError('Couldn’t apply changes. Try again. If it persists, open Diagnostics and share Request ID.');
    } finally {
      setApplyLoading(false);
      if (applyTimerRef.current) {
        clearInterval(applyTimerRef.current);
        applyTimerRef.current = null;
      }
    }
  };

  const findTrimmed = find.trim();
  const targetsSelected = targets.items || targets.subitems || targets.docs;
  const hasFieldSelection = columnScope !== 'custom' || includeColumnIds.length > 0;
  const canPreview =
    Boolean(boardId) && findTrimmed.length >= 2 && targetsSelected && hasFieldSelection && !previewLoading && !loading && hasAccountId;
  const previewDisabled = !canPreview;
  const showError = Boolean(error) && !authIssue;
  const needsRemoveConfirm = replace.length === 0 && findTrimmed.length > 0;

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

  const currentStep = previewLoading || preview.length > 0 ? 4 : findTrimmed.length >= 2 ? 3 : targetsSelected ? 2 : 1;
  const applyDisabled = !APPLY_AVAILABLE || previewLoading || preview.length === 0 || summary.totalMatches === 0 || applyLoading || dryRun;

  const applyStatus = APPLY_AVAILABLE ? (summary.totalMatches > 0 ? 'Ready' : 'Preview only') : 'Preview only';
  const applyHelper = APPLY_AVAILABLE
    ? dryRun
      ? 'Dry run is on. Turn it off to apply changes.'
      : summary.totalMatches > 0
        ? 'Review the preview and confirm to apply.'
        : 'Run a preview to unlock apply.'
    : 'Bulk apply will be enabled once updates are available.';

  const buildApplyCounts = () => {
    const itemIds = new Set();
    const subitemIds = new Set();
    const docBlockIds = new Set();
    preview.forEach((row) => {
      if (row.targetType === 'item') itemIds.add(row.itemId);
      if (row.targetType === 'subitem') subitemIds.add(row.itemId);
      if (row.targetType === 'doc_block') docBlockIds.add(`${row.itemId}:${row.columnId}`);
    });
    return {
      updates: summary.totalMatches || 0,
      items: itemIds.size,
      subitems: subitemIds.size,
      docBlocks: docBlockIds.size
    };
  };

  const applyCounts = buildApplyCounts();
  const confirmReady =
    confirmText.trim().toUpperCase() === 'APPLY' &&
    confirmUnderstood &&
    (!needsRemoveConfirm || confirmRemove) &&
    !applyLoading;

  const retryLastAction = () => {
    const last = lastFailedActionRef.current;
    if (!last) return;
    if (last.type === 'preview') {
      runPreview({ cursor: last.cursor, reset: last.reset });
      return;
    }
    if (last.type === 'apply' && confirmReady && !applyLoading) {
      runApply();
    }
  };

  const targetLabels = [
    targets.items && 'Items',
    targets.subitems && 'Subitems',
    targets.docs && 'Docs'
  ].filter(Boolean);
  const docIds = parseFreeformList(docIdsText);
  const filtersActive =
    (columnScope === 'custom' && includeColumnIds.length > 0) ||
    excludeColumnIds.length > 0 ||
    includeGroupIds.length > 0 ||
    Boolean(includeNameContains) ||
    Boolean(excludeNameContains) ||
    docIds.length > 0;
  const columnRule =
    columnScope === 'custom'
      ? `Selected fields (${includeColumnIds.length})`
      : excludeColumnIds.length > 0
        ? `All text fields (excluding ${excludeColumnIds.length})`
        : 'All text fields';
  const selectedGroupNames = groupOptions
    .filter((group) => includeGroupIds.includes(group.id))
    .map((group) => group.label);
  const selectedFieldNames = textColumns
    .filter((col) => includeColumnIds.includes(col.id))
    .map((col) => col.label);
  const fieldsSummary =
    columnScope === 'custom'
      ? selectedFieldNames.length
        ? `Selected fields: ${selectedFieldNames.join(', ')}`
        : 'Selected fields: none'
      : `All text fields (${textColumns.length})`;
  const groupsSummary = includeGroupIds.length
    ? `Selected groups: ${selectedGroupNames.join(', ')}`
    : `All groups (${groupOptions.length})`;
  const dryRunSummary = dryRun ? 'Dry run: on' : 'Dry run: off';
  const metaWaiting = metaError === 'Waiting for Monday context…';

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
          <div className="diagnostics__label">Last auth refresh</div>
          <div className="diagnostics__value">{lastAuthRefresh || '—'}</div>
        </div>
        <div>
          <div className="diagnostics__label">Last request status</div>
          <div className="diagnostics__value">{lastRequestStatus || '—'}</div>
        </div>
        <div>
          <div className="diagnostics__label">API base</div>
          <div className="diagnostics__value">{API_BASE || '—'}</div>
        </div>
        <div>
          <div className="diagnostics__label">Session token</div>
          <div className="diagnostics__value">
            {sessionTokenInfo.present
              ? debugEnabled
                ? `Present (len ${sessionTokenInfo.length}, …${sessionTokenInfo.tail})`
                : 'Present'
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

        <section className="card surface">
          <div className="section-header">
            <h2>How to use</h2>
            <button
              className="btn btn-secondary"
              type="button"
              onClick={() => setOnboardingOpen((prev) => !prev)}
              aria-expanded={onboardingOpen}
            >
              {onboardingOpen ? 'Hide' : 'Show'}
            </button>
          </div>
          {onboardingOpen && (
            <div className="onboarding-body">
              <ol className="onboarding-steps">
                <li>Choose targets to scan.</li>
                <li>Preview the changes (safe, no data changes).</li>
                <li>Apply to update data. You can undo using the audit log.</li>
              </ol>
              <div className="onboarding-note">
                Recommended first run: set max changes to 5.
              </div>
            </div>
          )}
        </section>

        {debugEnabled && (
          <div className="health-strip surface-2">
            <div>Board: {boardId ? 'Present' : 'Missing'}</div>
            <div>Account: {hasAccountId ? 'Present' : 'Missing'}</div>
            <div>Token: {sessionTokenInfo.present ? 'Present' : 'Missing'}</div>
            <div>API: {API_BASE || 'Missing'}</div>
            <div>Last status: {lastRequest?.status ?? '—'}</div>
            <div>Request ID: {lastRequest?.requestId || '—'}</div>
            <div>Last auth refresh: {lastAuthRefresh || '—'}</div>
            <div>Last request status: {lastRequestStatus || '—'}</div>
            <div>Build: {buildId}</div>
            <div>Env: {buildEnv}</div>
          </div>
        )}

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

        {authIssue === 'session' && (
          <InlineNotice tone="error">
            <div className="notice__row">
              <div>{AUTH_EXPIRED_MESSAGE}</div>
              <button className="btn btn-primary" type="button" onClick={handleReconnect}>
                Reload app
              </button>
            </div>
            <div className="muted">Your session expired. Reloading will restore access.</div>
            {reloadAttempted && (
              <div className="muted">If this keeps happening, remove and re-add the app view.</div>
            )}
          </InlineNotice>
        )}

        {authIssue === 'oauth' && (
          <InlineNotice tone="error">
            <div className="notice__row">
              <div>{OAUTH_REQUIRED_MESSAGE}</div>
              <button className="btn btn-primary" type="button" onClick={handleOAuthReconnect}>
                Connect
              </button>
            </div>
            {popupBlocked && (
              <div className="muted">Pop-up blocked. Please allow pop-ups for monday.com and try again.</div>
            )}
            {isConnecting && <div className="muted">Connecting to Monday…</div>}
          </InlineNotice>
        )}

        <ScopeSummaryCard
          boardId={boardId}
          ctxLoaded={!loading}
          targetsLabel={targetLabels.length ? `${targetLabels.length} selected (${targetLabels.join(', ')})` : 'None selected'}
          columnRule={columnRule}
          filtersActive={filtersActive}
        />

        <WhereToLookCard
          targets={targets}
          setTargets={setTargets}
          columnScope={columnScope}
          setColumnScope={setColumnScope}
          textColumns={textColumns}
          groupOptions={groupOptions}
          includeColumnIds={includeColumnIds}
          setIncludeColumnIds={setIncludeColumnIds}
          includeGroupIds={includeGroupIds}
          setIncludeGroupIds={setIncludeGroupIds}
          includeNameContains={includeNameContains}
          setIncludeNameContains={setIncludeNameContains}
          excludeNameContains={excludeNameContains}
          setExcludeNameContains={setExcludeNameContains}
          excludeColumnIds={excludeColumnIds}
          setExcludeColumnIds={setExcludeColumnIds}
          docIdsText={docIdsText}
          setDocIdsText={setDocIdsText}
          metaLoading={metaLoading}
          metaError={metaError}
          onRetryMeta={handleRetryMeta}
          metaWaiting={metaWaiting}
        />

        <WhatToChangeCard
          find={find}
          replace={replace}
          setFind={setFind}
          setReplace={setReplace}
          rules={rules}
          setRules={setRules}
          onPreview={() => runPreview({ cursor: cursorStack[cursorIndex], reset: true })}
          previewDisabled={previewDisabled}
          previewLoading={previewLoading}
          canPreview={canPreview}
        />

        <SafetyCard
          limit={limit}
          setLimit={setLimit}
          dryRun={dryRun}
          setDryRunPreference={setDryRunPreference}
        />

        {!targetsSelected && (
          <InlineNotice tone="neutral">Select at least one target to preview.</InlineNotice>
        )}
        {targetsSelected && columnScope === 'custom' && includeColumnIds.length === 0 && (
          <InlineNotice tone="neutral">Select at least one field or switch to all text fields.</InlineNotice>
        )}

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
          filteredRows={filteredRows}
          find={findTrimmed}
          hasNext={Boolean(nextCursor)}
          hasPrev={cursorIndex > 0}
          onNextPage={handleNextPage}
          onPrevPage={handlePrevPage}
          pageIndex={cursorIndex + 1}
          warnings={warnings}
        />

        {applyResult && (
          <section className="card surface">
            <div className="section-header">
              <h2>{applyResult.mode === 'dry' ? 'Dry run complete' : 'Apply complete'}</h2>
              <span className={`pill ${applyResult.mode === 'dry' ? 'pill-gold' : 'pill-green'}`}>
                {applyResult.mode === 'dry' ? 'No changes applied' : 'Success'}
              </span>
            </div>
            <div className="summary-grid">
              <div className="summary-card surface-2">
                <div className="summary-card__label">Updates</div>
                <div className="summary-card__value">{formatNumber(applyResult.updates)}</div>
              </div>
              <div className="summary-card surface-2">
                <div className="summary-card__label">Items</div>
                <div className="summary-card__value">{formatNumber(applyResult.items)}</div>
              </div>
              <div className="summary-card surface-2">
                <div className="summary-card__label">Subitems</div>
                <div className="summary-card__value">{formatNumber(applyResult.subitems)}</div>
              </div>
              <div className="summary-card surface-2">
                <div className="summary-card__label">Docs blocks</div>
                <div className="summary-card__value">{formatNumber(applyResult.docBlocks)}</div>
              </div>
            </div>
            {applyResult.mode !== 'dry' && applyResult.runId && (
              <div className="apply-success__meta">
                <div className="muted">Run ID: {applyResult.runId}</div>
                <a className="btn btn-secondary" href={`${API_BASE}/api/audit?run_id=${encodeURIComponent(applyResult.runId)}`} target="_blank" rel="noreferrer">
                  Export audit log
                </a>
              </div>
            )}
            <div className="muted apply-undo">
              Undo plan: re-run with swapped find/replace using the audit log as reference.
            </div>
            {applyResult.mode !== 'dry' && (
              <div className="muted">If you don’t see updates yet, refresh the board view.</div>
            )}
          </section>
        )}

        <section className="apply-bar surface">
          <div className="apply-meta">
            <div className="apply-row">
              <div className="apply-title">Apply changes</div>
              <span className={`pill ${applyStatus === 'Ready' ? 'pill-green' : 'pill-gold'}`}>{applyStatus}</span>
            </div>
            <div className="muted apply-helper">{applyHelper}</div>
            {lastRunId && (
              <a className="muted" href={`${API_BASE}/api/audit?run_id=${encodeURIComponent(lastRunId)}`} target="_blank" rel="noreferrer">
                Export audit log
              </a>
            )}
          </div>
          <button
            className="btn btn-secondary"
            type="button"
            disabled={applyDisabled}
            onClick={() => setApplyOpen(true)}
            title={
              applyDisabled
                ? dryRun
                  ? 'Turn off dry run to apply changes.'
                  : 'Run a preview before applying changes.'
                : 'Apply changes'
            }
          >
            Apply changes
          </button>
        </section>
      </main>

      {helpOpen && (
        <ConfirmModal title="What this does" onClose={() => setHelpOpen(false)}>
          <div className="modal-content">
            <p>
              Bulk Find &amp; Replace scans items, subitems, and docs on the active board, previews matches, and applies
              changes only after confirmation.
            </p>
            <ul className="help-list">
              <li>Preview is always safe and doesn&apos;t change data.</li>
              <li>Use filters to scope results before applying.</li>
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

      {applyOpen && (
        <ConfirmModal title="Confirm apply" onClose={() => setApplyOpen(false)}>
          <div className="modal-content">
            <p>
              You are about to update {formatNumber(applyCounts.updates)} fields across {formatNumber(applyCounts.items)} items
              ({formatNumber(applyCounts.subitems)} subitems, {formatNumber(applyCounts.docBlocks)} docs blocks).
            </p>
            <div className="summary-grid">
              <div className="summary-card surface-2">
                <div className="summary-card__label">Targets</div>
                <div className="summary-card__value">{targetLabels.join(', ') || 'None'}</div>
              </div>
              <div className="summary-card surface-2">
                <div className="summary-card__label">Fields</div>
                <div className="summary-card__value">{fieldsSummary}</div>
              </div>
              <div className="summary-card surface-2">
                <div className="summary-card__label">Groups</div>
                <div className="summary-card__value">{groupsSummary}</div>
              </div>
              <div className="summary-card surface-2">
                <div className="summary-card__label">Dry run</div>
                <div className="summary-card__value">{dryRunSummary}</div>
              </div>
            </div>
            {needsRemoveConfirm && (
              <div className="notice notice--error surface-2">
                You are replacing with empty text. Please confirm you intend to remove the matched text.
              </div>
            )}
            <label className="toggle">
              <input
                type="checkbox"
                checked={confirmUnderstood}
                onChange={(e) => setConfirmUnderstood(e.target.checked)}
              />
              <span>I understand these changes will update my board.</span>
            </label>
            {needsRemoveConfirm && (
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={confirmRemove}
                  onChange={(e) => setConfirmRemove(e.target.checked)}
                />
                <span>I understand this will remove text.</span>
              </label>
            )}
            <input
              className="input"
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              placeholder="Type APPLY"
            />
            {applyLoading && (
              <div className="muted">
                Applying {applyProgress}/{applyTotal || summary.totalMatches || 0} · Failures {applyFailures}
              </div>
            )}
            {applyLoading && (
              <div className="progress-track" aria-hidden="true">
                <div
                  className="progress-fill"
                  style={{
                    width: `${Math.min(
                      100,
                      ((applyProgress || 0) / Math.max(1, applyTotal || summary.totalMatches || 1)) * 100
                    ).toFixed(1)}%`
                  }}
                />
              </div>
            )}
            <div className="modal-actions">
              <button className="btn btn-secondary" type="button" onClick={() => setApplyOpen(false)}>
                Cancel
              </button>
              <button className="btn btn-primary" type="button" onClick={runApply} disabled={!confirmReady}>
                {applyLoading ? 'Applying…' : dryRun ? 'Confirm dry run' : 'Confirm apply'}
              </button>
            </div>
          </div>
        </ConfirmModal>
      )}

      {toast && <Toast message={toast} onClose={() => setToast('')} />}
    </div>
  );
}
