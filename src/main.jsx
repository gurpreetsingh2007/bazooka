import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

const ACTIONS = [
  { signal: 'term', label: 'End task', icon: '↘', tone: 'danger' },
  { signal: 'kill', label: 'Force kill', icon: '×', tone: 'danger' },
  { signal: 'stop', label: 'Pause process', icon: 'Ⅱ' },
  { signal: 'cont', label: 'Resume process', icon: '▶' },
];
const QUERY_FIELDS = new Set(['pid', 'ppid', 'port', 'ports', 'service', 'name', 'user', 'cmd', 'command', 'location', 'exe', 'cwd', 'state']);
const fmtBytes = n => {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  return `${(n / 1024 ** i).toFixed(i > 1 ? 1 : 0)} ${units[i]}`;
};
const formatUptime = seconds => {
  const d = Math.floor(seconds / 86400), h = Math.floor(seconds % 86400 / 3600), m = Math.floor(seconds % 3600 / 60);
  return `${d}d ${h}h ${m}m`;
};
const tokenize = query => query.match(/(?:"[^"]*"|'[^']*'|\S+)/g)?.map(x => x.replace(/^["']|["']$/g, '')) ?? [];
function matchesProcess(process, query) {
  const fields = tokenize(query);
  if (!fields.length) return true;
  const allText = [process.name, process.user, process.service, process.cmdline, process.exe, process.cwd, process.state,
    process.pid, process.ppid, ...(process.ports || [])].join(' ').toLowerCase();
  return fields.every(field => {
    const colon = field.indexOf(':');
    const key = colon > 0 ? field.slice(0, colon).toLowerCase() : '';
    const value = (colon > 0 ? field.slice(colon + 1) : field).toLowerCase();
    if (!value) return true;
    if (!QUERY_FIELDS.has(key)) return allText.includes(field.toLowerCase());
    const includes = candidate => String(candidate ?? '').toLowerCase().includes(value);
    switch (key) {
      case 'pid': return String(process.pid) === value;
      case 'ppid': return String(process.ppid) === value;
      case 'port': case 'ports': return (process.ports || []).some(port => String(port) === value);
      case 'service': return includes(process.service) || includes(process.name);
      case 'name': return includes(process.name);
      case 'user': return includes(process.user);
      case 'cmd': case 'command': return includes(process.cmdline);
      case 'location': return includes(process.exe) || includes(process.cwd);
      case 'exe': return includes(process.exe);
      case 'cwd': return includes(process.cwd);
      case 'state': return includes(process.state);
      default: return allText.includes(value);
    }
  });
}
function App() {
  const [token, setToken] = useState('');
  const [authed, setAuthed] = useState(false);
  const [authReady, setAuthReady] = useState(false);
  const [authError, setAuthError] = useState('');
  const [rows, setRows] = useState([]);
  const [stats, setStats] = useState(null);
  const [error, setError] = useState('');
  const [toast, setToast] = useState('');
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState('');
  const [selectedPid, setSelectedPid] = useState(null);
  const [sort, setSort] = useState({ key: 'cpu', dir: -1 });
  const [tree, setTree] = useState(false);
  const [children, setChildren] = useState(false);
  const [dialog, setDialog] = useState(null);
  const [busy, setBusy] = useState(false);
  const searchRef = useRef(null);

  const request = useCallback(async (url, opts = {}) => {
    const res = await fetch(url, { ...opts, headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) }, credentials: 'same-origin' });
    let data = {};
    try { data = await res.json(); } catch { /* non JSON response */ }
    if (res.status === 401) { setAuthed(false); throw Error(data.error || 'Session expired'); }
    if (!res.ok) throw Error(data.error || data.message || `Request failed (${res.status})`);
    return data;
  }, []);

  useEffect(() => {
    let active = true;
    request('/api/session').then(() => { if (active) setAuthed(true); }).catch(() => { if (active) setAuthed(false); }).finally(() => { if (active) setAuthReady(true); });
    return () => { active = false; };
  }, [request]);

  const refresh = useCallback(async () => {
    if (paused || !authed) return;
    try {
      const [processes, system] = await Promise.all([request('/api/processes'), request('/api/stats')]);
      setRows(processes);
      setStats(system);
      setError('');
    } catch (e) { setError(e.message); }
  }, [authed, paused, request]);
  useEffect(() => {
    if (!authed || paused) return;
    refresh();
    const id = setInterval(refresh, 2000);
    return () => clearInterval(id);
  }, [authed, paused, refresh]);
  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(''), 4500);
    return () => clearTimeout(id);
  }, [toast]);
  useEffect(() => {
    const onKey = e => {
      if (e.key === '/' && document.activeElement?.tagName !== 'INPUT') { e.preventDefault(); searchRef.current?.focus(); }
      if (e.key === 'Escape') { setDialog(null); setSelectedPid(null); searchRef.current?.blur(); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  async function login(e) {
    e.preventDefault(); setAuthError('');
    try { await request('/api/login', { method: 'POST', body: JSON.stringify({ token }) }); setAuthed(true); setToken(''); }
    catch (e) { setAuthError(e.message); }
  }
  async function logout() {
    try { await request('/api/logout', { method: 'POST' }); } catch { /* local sign out still works */ }
    setAuthed(false); setRows([]); setSelectedPid(null);
  }
  const selected = rows.find(p => p.pid === selectedPid) || null;
  const filtered = useMemo(() => {
    const list = rows.filter(p => matchesProcess(p, filter));
    const compare = (a, b) => {
      const x = a[sort.key], y = b[sort.key];
      const n = typeof x === 'number' && typeof y === 'number' ? x - y : String(Array.isArray(x) ? x.join(',') : x ?? '').localeCompare(String(Array.isArray(y) ? y.join(',') : y ?? ''), undefined, { numeric: true, sensitivity: 'base' });
      return n * sort.dir;
    };
    list.sort(compare);
    if (!tree) return list;
    const childrenByParent = new Map();
    for (const process of list) {
      const group = childrenByParent.get(process.ppid) || [];
      group.push(process); childrenByParent.set(process.ppid, group);
    }
    const output = [], seen = new Set();
    const walk = (pid, depth) => {
      for (const process of (childrenByParent.get(pid) || []).sort(compare)) {
        if (seen.has(process.pid)) continue;
        seen.add(process.pid); output.push({ ...process, depth }); walk(process.pid, depth + 1);
      }
    };
    walk(0, 0);
    for (const process of list) if (!seen.has(process.pid)) { output.push({ ...process, depth: 0 }); walk(process.pid, 1); }
    return output;
  }, [rows, filter, sort, tree]);

  function sortBy(key) {
    setSort(current => ({ key, dir: current.key === key ? -current.dir : (['name', 'user', 'service', 'exe', 'cwd', 'cmdline', 'state'].includes(key) ? 1 : -1) }));
  }
  async function sendSignal(action) {
    if (!selected) return;
    setBusy(true);
    try {
      const result = await request('/api/signal', { method: 'POST', body: JSON.stringify({ pid: selected.pid, signal: action.signal, children }) });
      setToast(result.message + (result.errors?.length ? ` · ${result.errors.join('; ')}` : ''));
      setDialog(null);
      if (action.signal === 'term' || action.signal === 'kill') setSelectedPid(null);
      setTimeout(refresh, 350);
    } catch (e) { setToast(e.message); setDialog(null); }
    finally { setBusy(false); }
  }
  function chooseAction(action) {
    if (action.signal === 'term' || action.signal === 'kill') setDialog(action);
    else sendSignal(action);
  }

  if (!authReady) return <main className="login-wrap"><div className="login card auth-loading"><div className="brand-mark">BZ</div><div className="eyebrow">RESTORING SESSION</div><div className="loading-bar"><i /></div></div></main>;
  if (!authed) return <main className="login-wrap"><form className="login card" onSubmit={login}><div className="brand-mark">BZ</div><div className="eyebrow">HOST PROCESS CONTROL</div><h1>Bazooka</h1><p>Sign in with the <code>TM_TOKEN</code> configured for this container.</p><label htmlFor="token">Access token</label><input id="token" autoFocus type="password" value={token} onChange={e => setToken(e.target.value)} autoComplete="current-password" required /><button className="primary full">Connect to host</button>{authError && <div className="login-error">{authError}</div>}</form><div className="login-foot">Your session will be remembered on this device</div></main>;

  return <main className="app-shell">
    <header className="topbar"><div className="brand"><div className="brand-mark">BZ</div><div><strong>Bazooka</strong><span>HOST TASK MANAGER</span></div></div><div className="top-actions"><span className="live"><i />HOST CONNECTED</span><button className="quiet" onClick={logout}>Sign out</button></div></header>
    <section className="intro"><div><div className="eyebrow">SYSTEM OVERVIEW</div><h1>Processes <span className="count">{stats?.count ?? '—'}</span></h1></div><div className="update-label"><span className={paused ? 'paused-dot' : 'pulse-dot'} />{paused ? 'Updates paused' : 'Refreshes every 2 seconds'}</div></section>
    <section className="metrics">{[
      ['CPU', `${stats?.cpu?.toFixed(1) ?? '—'}%`, <div className="meter"><i style={{ width: `${Math.min(stats?.cpu || 0, 100)}%` }} /></div>],
      ['MEMORY', stats ? `${fmtBytes(stats.memoryUsed)} / ${fmtBytes(stats.memoryTotal)}` : '—', <div className="meter"><i style={{ width: `${stats ? Math.min(stats.memoryUsed / stats.memoryTotal * 100, 100) : 0}%` }} /></div>],
      ['LOAD AVERAGE', stats?.load?.map(n => n.toFixed(2)).join('  /  ') || '—', '1m  /  5m  /  15m'],
      ['UPTIME', stats ? formatUptime(stats.uptime) : '—', 'Since last boot'],
    ].map(([label, value, sub]) => <article className="metric card" key={label}><span>{label}</span><strong>{value}</strong><small>{sub}</small></article>)}</section>

    <div className={`manager-layout ${selected ? 'with-inspector' : ''}`}>
      <section className="workspace card">
        <div className="toolbar">
          <div className="search-area"><div className="searchbox"><span>⌕</span><input ref={searchRef} value={filter} onChange={e => setFilter(e.target.value)} placeholder="Search processes… try pid:81320 port:443 service:traefik" aria-label="Search processes" />{filter && <button className="clear-search" onClick={() => setFilter('')} aria-label="Clear search">×</button>}<kbd>/</kbd></div><div className="search-help"><span>Try</span><code>pid:1234</code><code>port:443</code><code>service:docker</code><code>location:/usr/bin</code><span>· combine filters · quote phrases</span></div></div>
          <div className="tool-actions"><label className="switch-label"><input type="checkbox" checked={tree} onChange={e => setTree(e.target.checked)} /><span className="switch" />Tree view</label><button className={paused ? 'primary button' : 'quiet button'} onClick={() => setPaused(!paused)}>{paused ? '▶ Resume' : 'Ⅱ Pause'}</button></div>
        </div>
        {error && <div className="inline-error">{error} <button onClick={refresh}>Retry</button></div>}
        <div className="table-scroll"><table><thead><tr>{[['pid','PID'],['ppid','PPID'],['name','NAME'],['user','USER'],['cpu','CPU'],['rss','MEMORY'],['threads','THREADS'],['ports','PORTS'],['state','STATE'],['cmdline','COMMAND']].map(([key, label]) => <th key={key} className={`col-${key}`} onClick={() => sortBy(key)}>{label}{sort.key === key && <span className="sort">{sort.dir === 1 ? '↑' : '↓'}</span>}</th>)}</tr></thead>
          <tbody>{filtered.map(p => <tr key={p.pid} className={selectedPid === p.pid ? 'selected' : ''} onClick={() => setSelectedPid(p.pid)}>
            <td className="mono">{p.pid}</td><td className="mono muted">{p.ppid}</td><td className="proc-name"><span className="process-icon">{p.name?.slice(0, 1).toUpperCase() || '?'}</span><span style={{ paddingLeft: tree ? (p.depth || 0) * 15 : 0 }}>{tree && p.depth > 0 ? '↳ ' : ''}{p.name || '—'}</span></td><td>{p.user || '—'}</td><td className="num">{p.cpu?.toFixed(1)}%</td><td className="num">{fmtBytes(p.rss)}</td><td className="num">{p.threads}</td><td className="ports mono">{p.ports?.length ? p.ports.map(port => <span className="port-chip" key={port}>{port}</span>) : <span className="muted">—</span>}</td><td><span className={`state state-${String(p.state || '').toLowerCase()[0]}`}>{p.state || '?'}</span></td><td className="command" title={p.cmdline}>{p.cmdline || p.name}</td>
          </tr>)}{!filtered.length && <tr><td colSpan="10" className="empty"><span>{filter ? 'No processes match this search' : 'No processes found'}</span><small>Try a process name, pid:1234, port:443, service:name or location:/path</small></td></tr>}</tbody></table></div>
        <footer className="table-foot"><span><b>{filtered.length}</b> of {rows.length} processes</span><span>Host namespace <i className="ok-dot" /> active</span></footer>
      </section>

      {selected && <aside className="process-inspector card" key={selected.pid}>
        <div className="inspector-head"><div><div className="eyebrow">PROCESS DETAILS</div><h2>{selected.name || 'Unknown process'}</h2></div><button className="icon-button" onClick={() => setSelectedPid(null)} aria-label="Close process details">×</button></div>
        <div className="process-identity"><div className="large-process-icon">{selected.name?.slice(0, 1).toUpperCase() || '?'}</div><div><span>PID {selected.pid}</span><small>Parent {selected.ppid}</small></div><span className={`state state-${String(selected.state || '').toLowerCase()[0]}`}>{selected.state || '?'}</span></div>
        <div className="detail-grid"><div><span>CPU</span><b>{selected.cpu?.toFixed(1)}%</b></div><div><span>MEMORY</span><b>{fmtBytes(selected.rss)}</b></div><div><span>THREADS</span><b>{selected.threads}</b></div><div><span>USER</span><b>{selected.user || '—'}</b></div></div>
        <div className="detail-block"><span className="detail-label">SERVICE</span><p>{selected.service || selected.name || '—'}</p></div>
        <div className="detail-block"><span className="detail-label">LISTENING PORTS</span><div className="detail-ports">{selected.ports?.length ? selected.ports.map(port => <span className="port-chip" key={port}>{port}</span>) : <p>No listening TCP or bound UDP ports</p>}</div></div>
        <div className="detail-block"><span className="detail-label">EXECUTABLE</span><p className="path-value" title={selected.exe}>{selected.exe || 'Unavailable'}</p></div>
        <div className="detail-block"><span className="detail-label">WORKING DIRECTORY</span><p className="path-value" title={selected.cwd}>{selected.cwd || 'Unavailable'}</p></div>
        <div className="detail-block command-block"><span className="detail-label">COMMAND LINE</span><p>{selected.cmdline || selected.name || 'Unavailable'}</p></div>
        <div className="inspector-actions"><div className="actions-title">PROCESS ACTIONS</div><label className="child-check"><input type="checkbox" checked={children} onChange={e => setChildren(e.target.checked)} />Also signal child processes</label><div className="action-grid">{ACTIONS.map(action => <button key={action.signal} className={`action-button ${action.tone || ''}`} disabled={busy} onClick={() => chooseAction(action)}><span>{action.icon}</span>{action.label}</button>)}</div></div>
      </aside>}
    </div>

    <footer className="page-foot"><span>BAZOOKA <b>·</b> HOST PROCESS MANAGER</span><span>Signals require confirmation · PID 1 and Bazooka are protected</span></footer>
    {toast && <div className="toast" role="status">{toast}</div>}
    {dialog && <div className="backdrop" onMouseDown={e => e.target === e.currentTarget && setDialog(null)}><section className="confirm card"><div className="confirm-icon">!</div><div className="eyebrow">PROCESS ACTION</div><h2>{dialog.label}?</h2><p>Send <b>{dialog.signal.toUpperCase()}</b> to <b>{selected?.name}</b> (PID {selected?.pid}){children ? ' and its child processes' : ''}?</p><p className="confirm-note">This action affects a process on the host machine.</p><div className="confirm-actions"><button className="quiet button" onClick={() => setDialog(null)}>Cancel</button><button className="danger" disabled={busy} onClick={() => sendSignal(dialog)}>{busy ? 'Sending…' : `Confirm ${dialog.label.toLowerCase()}`}</button></div></section></div>}
  </main>;
}

createRoot(document.getElementById('root')).render(<App />);
