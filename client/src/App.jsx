
import React, { useEffect, useMemo, useState } from 'react';
import mondaySdk from 'monday-sdk-js';

export default function App() {
  const monday = useMemo(() => mondaySdk(), []);
  const apiBase = import.meta.env.VITE_API_BASE_URL || '';
  const [ctx,setCtx]=useState(null);
  const [find,setFind]=useState('');
  const [replace,setReplace]=useState('');
  const [preview,setPreview]=useState([]);
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState('');
  const [authRequired,setAuthRequired]=useState(false);

  useEffect(()=>{
    let mounted = true;
    const unsubscribe = monday.listen('context',c=>{
      if (!mounted) return;
      setCtx(c);
      setLoading(false);
    });
    monday.get('context').then(res => {
      if (!mounted) return;
      if (res?.data) {
        setCtx(res.data);
      }
      setLoading(false);
    }).catch(()=>{
      if (mounted) setLoading(false);
    });
    return ()=>{ mounted = false; unsubscribe?.(); };
  },[]);

  async function previewRun(){
    setError('');
    setAuthRequired(false);
    if (!ctx?.account?.id || !ctx?.boardId) {
      setError('Missing board context.');
      return;
    }
    const q = `query($id:ID!){boards(ids:[$id]){items{id column_values{id text}}}}`;
    const r = await fetch(`${apiBase}/api/graphql`,{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({accountId:String(ctx.account.id),query:q,variables:{id:ctx.boardId}})
    });
    if (r.status === 401) {
      setAuthRequired(true);
      return;
    }
    if (!r.ok) {
      setError('Failed to load preview.');
      return;
    }
    const d = await r.json();
    const out=[];
    (d?.data?.boards?.[0]?.items || []).forEach(i=>i.column_values.forEach(c=>{
      if(c.text && c.text.includes(find)) out.push({before:c.text,after:c.text.replaceAll(find,replace)});
    }));
    setPreview(out);
  }

  return (
    <div style={{padding:20}}>
      <h2>Bulk Find & Replace</h2>
      {loading && <div>Loading Monday context…</div>}
      {!loading && !ctx && <div>Unable to load Monday context.</div>}
      {error && <div style={{color:'crimson'}}>{error}</div>}
      {authRequired && (
        <div>
          <div>Authorization required.</div>
          <button onClick={()=>window.open(`${apiBase}/auth/authorize`,'_blank')}>Authorize</button>
        </div>
      )}
      <input value={find} onChange={e=>setFind(e.target.value)} placeholder="Find"/>
      <input value={replace} onChange={e=>setReplace(e.target.value)} placeholder="Replace"/>
      <button onClick={previewRun} disabled={!find}>Preview</button>
      {preview.length === 0 && !loading && <div>No preview results yet.</div>}
      <ul>{preview.map((p,i)=><li key={i}>{p.before} → {p.after}</li>)}</ul>
    </div>
  );
}
