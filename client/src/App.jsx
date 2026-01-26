
import React, { useEffect, useMemo, useState } from 'react';
import mondaySdk from 'monday-sdk-js';

export default function App() {
  const monday = useMemo(() => (window.mondaySdk ? window.mondaySdk() : mondaySdk()), []);
  const rawApiBase = import.meta.env.VITE_API_BASE_URL || '';
  const API_BASE = rawApiBase || 'https://bulk-find-replace-server.onrender.com';
  const hasApiBase = Boolean(rawApiBase);
  const [ctx,setCtx]=useState(null);
  const [ctxRaw,setCtxRaw]=useState(null);
  const [ctxErr,setCtxErr]=useState(null);
  const [find,setFind]=useState('');
  const [replace,setReplace]=useState('');
  const [preview,setPreview]=useState([]);
  const [summary,setSummary]=useState({ totalMatches: 0, totalItems: 0 });
  const [loading,setLoading]=useState(true);
  const [previewLoading,setPreviewLoading]=useState(false);
  const [error,setError]=useState('');
  const [authRequired,setAuthRequired]=useState(false);
  const [boardId,setBoardId]=useState(null);
  const [oauthAccountId,setOauthAccountId]=useState('');
  const [sessionTokenInfo,setSessionTokenInfo]=useState({
    present: false,
    looksJwt: false,
    masked: ''
  });
  const authPollRef = React.useRef(null);

  useEffect(() => {
    window.__BFR_APP_LOADED = true;
    window.__BFR_LOCATION = String(window.location.href);
    window.__BFR_IN_IFRAME = window.self !== window.top;
    window.__BFR_MONDAY = monday;
  }, [monday]);

  useEffect(()=>{
    let mounted = true;
    const normalizeContext = data => data?.data ?? data;
    const extractAccountId = data =>
      data?.data?.accountId ||
      data?.data?.account_id ||
      data?.data?.account?.id ||
      data?.data?.user?.account?.id ||
      data?.data?.user?.account_id ||
      data?.data?.user?.accountId ||
      null;
    const unsubscribe = monday.listen('context',c=>{
      if (!mounted) return;
      setCtxRaw(c);
      const next = normalizeContext(c);
      setCtx(next);
      setBoardId(next?.boardId ?? next?.board?.id ?? null);
      const nextAccountId = extractAccountId(c);
      if (nextAccountId) setOauthAccountId(String(nextAccountId));
      setLoading(false);
    });
    monday.get('context').then(res => {
      if (!mounted) return;
      console.log('[BFR] context', res);
      window.__BFR_CTX = res;
      window.__BFR_CTX_DATA = res?.data || null;
      setCtxRaw(res);
      const next = normalizeContext(res);
      if (next) setCtx(next);
      setBoardId(next?.boardId ?? next?.board?.id ?? null);
      const nextAccountId = extractAccountId(res);
      if (nextAccountId) setOauthAccountId(String(nextAccountId));
      setLoading(false);
    }).catch((e)=>{
      const message = String(e?.message || e);
      setCtxErr(message);
      window.__BFR_CTX_ERR = message;
      if (mounted) setLoading(false);
    });
    return ()=>{ mounted = false; unsubscribe?.(); };
  },[]);

  useEffect(()=>{
    return () => {
      if (authPollRef.current) clearInterval(authPollRef.current);
    };
  },[]);

  useEffect(() => {
    const handler = (e) => {
      if (e?.data?.type !== 'BFR_OAUTH_OK') return;
      const accountId = String(e.data.accountId || '');
      if (accountId) setOauthAccountId(accountId);
      if (!accountId) return;
      fetch(`${API_BASE}/api/auth/status?accountId=${encodeURIComponent(accountId)}`)
        .then(r => r.ok ? r.json() : null)
        .then(d => {
          if (d?.authorized) setAuthRequired(false);
        })
        .catch(() => {});
    };
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, [API_BASE, hasApiBase]);

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
    const masked = safe.length > 24
      ? `${safe.slice(0, 12)}…${safe.slice(-8)}`
      : (safe ? `${safe.slice(0, 6)}…` : '');
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

  async function previewRun(){
    setError('');
    setAuthRequired(false);
    setPreview([]);
    setSummary({ totalMatches: 0, totalItems: 0 });
    setPreviewLoading(true);
    if (!accountId || !boardId) {
      setError('Missing board context (boardId).');
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
    let inIframe = true;
    try {
      inIframe = window.self !== window.top;
    } catch {
      inIframe = true;
    }
    console.debug('[BFR] preview', { inIframe, tokenLen: sessionToken.length, apiBase: API_BASE });
    try {
      const r = await fetch(`${API_BASE}/api/preview`,{
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          Authorization:`Bearer ${sessionToken}`
        },
        body:JSON.stringify({
          accountId,
          boardId,
          find,
          replace
        })
      });
      const raw = await r.text();
      if (r.status === 401) {
        let payload;
        try {
          payload = raw ? JSON.parse(raw) : null;
        } catch {
          payload = null;
        }
        if (payload?.error === 'NOT_AUTHORIZED') {
          setAuthRequired(true);
          setError('Not authorized yet — click Authorize.');
          return;
        }
      }
      if (!r.ok) {
        setError(`Preview failed (${r.status}): ${raw || 'No body'}`);
        return;
      }
      let data;
      try {
        data = raw ? JSON.parse(raw) : null;
      } catch {
        data = raw;
      }
      setPreview(data?.rows || []);
      setSummary({
        totalMatches: data?.totalMatches || 0,
        totalItems: data?.totalItems || 0
      });
    } catch (e) {
      setError(String(e?.message || e));
    } finally {
      setPreviewLoading(false);
    }
  }

  const accountId = oauthAccountId;
  const previewDisabled = !boardId || !find || previewLoading || loading || !accountId;
  const hasAccountId = Boolean(accountId);
  const authorizeUrl = hasAccountId
    ? `${API_BASE.replace(/\/$/, '')}/auth/authorize?accountId=${encodeURIComponent(accountId)}`
    : '';
  const ctxAccountId =
    ctx?.account?.id ||
    ctx?.user?.account?.id ||
    ctx?.user?.account_id ||
    null;

  const showError = error && !(authRequired && error === 'Not authorized yet — click Authorize.');

  return (
    <div style={{padding:20}}>
      <div style={{border:'1px solid #ccc',padding:8,marginBottom:12,fontSize:12}}>
        <div>
          appLoaded={String(Boolean(window.__BFR_APP_LOADED))}{' '}
          inIframe={String(window.self !== window.top)}{' '}
          ctxLoaded={String(Boolean(ctxRaw))}{' '}
          accountId={String(accountId || '')}{' '}
          ctxErr={String(ctxErr || '')}
        </div>
        <div>apiBaseUrl: {API_BASE || '(missing)'}</div>
        <div>accountId: {accountId || '(missing)'}</div>
        <div>
          sessionToken present: {String(sessionTokenInfo.present)}{' '}
          jwt: {String(sessionTokenInfo.looksJwt)}{' '}
          token: {sessionTokenInfo.masked || '(missing)'}
        </div>
        <div>ctxLoaded: {String(Boolean(ctxRaw))}</div>
        <div>ctxAccountId: {ctxAccountId || '(missing)'}</div>
        <div>ctxErr: {ctxErr || ''}</div>
        <div>ctx keys: {Object.keys(ctxRaw?.data || {}).join(', ') || '(none)'}</div>
        {!accountId && <div style={{color:'crimson'}}>ACCOUNT ID MISSING — cannot authorize</div>}
      </div>
      <h2>Bulk Find & Replace</h2>
      {!hasApiBase && <div style={{color:'crimson'}}>Missing VITE_API_BASE_URL (set in Vercel and redeploy)</div>}
      {!hasAccountId && <div style={{color:'crimson'}}>Missing accountId from Monday context.</div>}
      {loading && <div>Loading Monday context…</div>}
      {!loading && !ctx && <div>Unable to load Monday context.</div>}
      {!loading && !boardId && <div>Waiting for boardId…</div>}
      {showError && <div style={{color:'crimson'}}>{error}</div>}
      {authRequired && (
        <div>
          <div>{error === 'Not authorized yet — click Authorize.' ? error : 'Authorization required.'}</div>
          <button
            onClick={()=>{
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
          <div style={{marginTop:8}}>
            <div>Authorize URL:</div>
            <input readOnly value={authorizeUrl} style={{width:'100%'}} />
            <button
              onClick={()=>{
                if (!authorizeUrl) return;
                navigator.clipboard?.writeText(authorizeUrl).catch(()=>{});
              }}
            >
              Copy
            </button>
            <div>If the button is blocked, paste this URL into a new tab.</div>
          </div>
        </div>
      )}
      <input value={find} onChange={e=>setFind(e.target.value)} placeholder="Find"/>
      <input value={replace} onChange={e=>setReplace(e.target.value)} placeholder="Replace"/>
      <button onClick={previewRun} disabled={previewDisabled || !hasAccountId}>
        {previewLoading ? 'Previewing…' : 'Preview'}
      </button>
      {!previewLoading && preview.length === 0 && !loading && <div>No preview results yet.</div>}
      {preview.length > 0 && (
        <div style={{marginTop:12}}>
          <div>Total matches: {summary.totalMatches}</div>
          <div>Items affected: {summary.totalItems}</div>
          <table style={{width:'100%',marginTop:8,borderCollapse:'collapse'}}>
            <thead>
              <tr>
                <th align="left">Item</th>
                <th align="left">Column</th>
                <th align="left">Before</th>
                <th align="left">After</th>
              </tr>
            </thead>
            <tbody>
              {preview.map((p,i)=>(
                <tr key={`${p.itemId}-${p.columnId}-${i}`}>
                  <td>{p.itemName}</td>
                  <td>{p.columnTitle}</td>
                  <td>{p.before}</td>
                  <td>{p.after}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
