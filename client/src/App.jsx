
import React, { useEffect, useMemo, useState } from 'react';
import mondaySdk from 'monday-sdk-js';

export default function App() {
  const monday = useMemo(() => mondaySdk(), []);
  const API_BASE = import.meta.env.VITE_API_BASE_URL || '';
  const hasApiBase = Boolean(API_BASE);
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
      if (!hasApiBase || !accountId) return;
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

  async function previewRun(){
    setError('');
    setAuthRequired(false);
    setPreview([]);
    setSummary({ totalMatches: 0, totalItems: 0 });
    if (!hasApiBase) {
      setError('Missing VITE_API_BASE_URL.');
      return;
    }
    if (!accountId || !boardId) {
      setError('Missing board context (boardId).');
      return;
    }
    setPreviewLoading(true);
    const r = await fetch(`${API_BASE}/api/preview`,{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        accountId,
        boardId,
        find,
        replace
      })
    });
    try {
      if (r.status === 401) {
        let payload;
        try {
          payload = await r.json();
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
        const msg = await r.text();
        setError(msg || 'Failed to load preview.');
        return;
      }
      const d = await r.json();
      setPreview(d?.rows || []);
      setSummary({
        totalMatches: d?.totalMatches || 0,
        totalItems: d?.totalItems || 0
      });
    } finally {
      setPreviewLoading(false);
    }
  }

  const accountId = oauthAccountId;
  const previewDisabled = !hasApiBase || !boardId || !find || previewLoading || loading || !accountId;
  const hasAccountId = Boolean(accountId);
  const authorizeUrl = hasApiBase && hasAccountId
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
              if (!hasApiBase) {
                setError('Missing VITE_API_BASE_URL.');
                return;
              }
              if (!hasAccountId) {
                setError('Missing accountId.');
                alert('Missing accountId from Monday context. Open console and screenshot debug box.');
                return;
              }
              monday.execute('openLink', { url: authorizeUrl, target: 'newTab' });
              startAuthPoll(accountId);
            }}
            disabled={!hasApiBase || !hasAccountId}
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
