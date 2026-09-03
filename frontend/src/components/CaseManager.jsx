import { useState, useEffect, useCallback } from 'react'
import { listCases, createCase, deleteCase, updateCaseStatus, getCase } from '../services/api'
import { FolderOpen, Plus, Trash2, ChevronRight, X, Mail, Clock, AlertTriangle, Search } from 'lucide-react'
import { useToast } from './Toast'

const STATUS = {
  open:      { bg: 'var(--accent-dim)', color: 'var(--accent)' },
  escalated: { bg: 'rgba(255,152,0,0.15)', color: 'var(--high)' },
  closed:    { bg: 'rgba(76,175,80,0.12)', color: 'var(--low)' },
}

function ScoreBadge({ score }) {
  const c = score >= 75 ? 'var(--critical)' : score >= 50 ? 'var(--high)' : score >= 25 ? 'var(--medium)' : 'var(--low)'
  return (
    <span style={{ fontSize: '0.7rem', fontWeight: 700, color: c, background: `${c}22`, padding: '2px 8px', borderRadius: 100, fontFamily: 'monospace' }}>
      {score}/100
    </span>
  )
}

function CaseDetail({ caseId, onClose }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [updating, setUpdating] = useState(false)
  const load = useCallback(async () => { setLoading(true); try { setData(await getCase(caseId)) } finally { setLoading(false) } }, [caseId])
  useEffect(() => { load() }, [load])

  const changeStatus = async (s) => { setUpdating(true); try { await updateCaseStatus(caseId, s); await load() } finally { setUpdating(false) } }

  return (
    <div className="card fade-in" style={{ position: 'relative' }}>
      <button onClick={onClose} style={{ position: 'absolute', top: 12, right: 12, background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
        <X size={18} />
      </button>
      {loading ? (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>Loading…</div>
      ) : data ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 4 }}>Case Detail</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-primary)' }}>{data.title}</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 4 }}>ID: <code>{data.id}</code> · {new Date(data.created_at).toLocaleString()}</div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Status:</span>
            {['open', 'escalated', 'closed'].map(s => (
              <button key={s} disabled={updating || data.status === s} onClick={() => changeStatus(s)} style={{
                padding: '3px 12px', borderRadius: 100, fontSize: '0.72rem', fontWeight: 600, cursor: data.status === s ? 'default' : 'pointer',
                border: `1px solid ${STATUS[s].color}`, background: data.status === s ? STATUS[s].bg : 'transparent',
                color: STATUS[s].color, opacity: updating ? 0.6 : 1, transition: 'all 0.2s',
              }}>{s}</button>
            ))}
          </div>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Linked Emails ({data.emails?.length || 0})
            </div>
            {!data.emails?.length ? (
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textAlign: 'center', padding: 20 }}>No emails linked yet. Analyze an email from the Analyzer page.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {data.emails.map(e => (
                  <div key={e.id} style={{ background: 'var(--surface-2)', borderRadius: 8, padding: '10px 14px', display: 'flex', alignItems: 'center', gap: 12, border: '1px solid var(--border-subtle)' }}>
                    <Mail size={14} color="var(--accent)" style={{ flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{e.subject || '(no subject)'}</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{e.from_address}</div>
                    </div>
                    <ScoreBadge score={e.fraud_score || 0} />
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{e.analyzed_at ? new Date(e.analyzed_at).toLocaleDateString() : '—'}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : <div style={{ color: 'var(--text-muted)', padding: 20 }}>Case not found</div>}
    </div>
  )
}

export default function CaseManager() {
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState(null)
  const toast = useToast()
  
  const [filters, setFilters] = useState({ q: '', sender: '', domain: '', ip: '', date: '', classification: '' })

  const load = async () => { 
    setLoading(true); 
    try { 
      const activeFilters = Object.fromEntries(Object.entries(filters).filter(([_, v]) => v.trim() !== ''));
      setCases(await listCases(activeFilters));
    } catch { 
      setError('Failed to load cases'); 
    } finally { 
      setLoading(false); 
    } 
  }
  
  // Load initially
  useEffect(() => { load() }, [])

  const handleSearch = (e) => {
    e.preventDefault();
    load();
  }

  const handleClear = () => {
    setFilters({ q: '', sender: '', domain: '', ip: '', date: '', classification: '' });
    // Will be picked up by another effect? Better to clear and load directly.
    setTimeout(() => load(), 0);
  }

  const handleCreate = async (e) => {
    e.preventDefault()
    if (!newTitle.trim()) return
    setCreating(true)
    try {
      await createCase(newTitle.trim())
      setNewTitle(''); setShowForm(false)
      await load()
      toast.push(`Case "${newTitle.trim()}" created`, 'success')
    }
    catch { toast.push('Failed to create case', 'error') }
    finally { setCreating(false) }
  }

  const handleDelete = async (id, e) => {
    e.stopPropagation()
    if (!confirm('Delete this case?')) return
    try {
      await deleteCase(id)
      if (selected === id) setSelected(null)
      await load()
      toast.push('Case deleted', 'warning')
    }
    catch { toast.push('Failed to delete case', 'error') }
  }

  const counts = { open: 0, escalated: 0, closed: 0 }
  cases.forEach(c => { if (c.status in counts) counts[c.status]++ })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <FolderOpen size={20} color="var(--accent)" /> Case Manager
          </h2>
          <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Organize investigations and track email clusters by case.</p>
        </div>
        <button id="btn-new-case" onClick={() => setShowForm(v => !v)}
          style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 8, background: 'var(--accent)', border: 'none', color: '#000', fontWeight: 700, fontSize: '0.82rem', cursor: 'pointer' }}>
          <Plus size={14} /> New Case
        </button>
      </div>

      <div className="grid-4" style={{ gap: 12 }}>
        {[{ label: 'Total', value: cases.length, color: 'var(--text-primary)' },
          { label: 'Open', value: counts.open, color: 'var(--accent)' },
          { label: 'Escalated', value: counts.escalated, color: 'var(--high)' },
          { label: 'Closed', value: counts.closed, color: 'var(--low)' }
        ].map(s => (
          <div key={s.label} className="stat-card">
            <div className="stat-label">{s.label}</div>
            <div className="stat-value" style={{ color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      <form onSubmit={handleSearch} className="card fade-in" style={{ padding: '16px 20px' }}>
        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}><Search size={14} /> Search & Filter</div>
        <div className="grid-3" style={{ gap: 12 }}>
          <input className="input" placeholder="Case ID or Title" value={filters.q} onChange={e => setFilters({...filters, q: e.target.value})} />
          <input className="input" placeholder="Sender Email" value={filters.sender} onChange={e => setFilters({...filters, sender: e.target.value})} />
          <input className="input" placeholder="Sender Domain" value={filters.domain} onChange={e => setFilters({...filters, domain: e.target.value})} />
          <input className="input" placeholder="IP Address" value={filters.ip} onChange={e => setFilters({...filters, ip: e.target.value})} />
          <input className="input" type="date" value={filters.date} onChange={e => setFilters({...filters, date: e.target.value})} />
          <select className="input" value={filters.classification} onChange={e => setFilters({...filters, classification: e.target.value})}>
            <option value="">Any Classification</option>
            <option value="legitimate">Legitimate</option>
            <option value="suspicious">Suspicious</option>
            <option value="impersonation">Impersonation</option>
            <option value="phishing">Phishing</option>
            <option value="bec_fraud">BEC Fraud</option>
          </select>
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12, gap: 8 }}>
          <button type="button" className="btn btn-ghost" onClick={handleClear}>Clear</button>
          <button type="submit" className="btn btn-primary" disabled={loading}>{loading ? 'Searching...' : 'Search'}</button>
        </div>
      </form>

      {showForm && (
        <div className="card fade-in" style={{ padding: '16px 20px' }}>
          <form onSubmit={handleCreate} style={{ display: 'flex', gap: 10 }}>
            <input id="input-case-title" autoFocus value={newTitle} onChange={e => setNewTitle(e.target.value)}
              placeholder="Case title (e.g. BEC Campaign Q3-2026)"
              style={{ flex: 1, padding: '10px 14px', borderRadius: 8, background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-primary)', fontSize: '0.85rem', outline: 'none' }} />
            <button type="submit" disabled={creating || !newTitle.trim()}
              style={{ padding: '10px 20px', borderRadius: 8, fontWeight: 700, background: 'var(--accent)', color: '#000', border: 'none', cursor: 'pointer', opacity: creating ? 0.6 : 1 }}>
              {creating ? 'Creating…' : 'Create'}
            </button>
            <button type="button" onClick={() => setShowForm(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}><X size={16} /></button>
          </form>
        </div>
      )}

      {error && (
        <div className="analysis-banner high fade-in" style={{ padding: '10px 14px', display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertTriangle size={16} /> {error}
          <button onClick={() => setError(null)} style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'inherit', cursor: 'pointer' }}>✕</button>
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          {loading ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading cases…</div>
          ) : cases.length === 0 ? (
            <div className="empty-state" style={{ padding: 40 }}>
              <div className="empty-state-icon">📂</div>
              <div className="empty-state-title">No cases found</div>
              <div className="empty-state-sub">Adjust your search filters or create a new case.</div>
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  {['Title', 'Status', 'Emails', 'Created', ''].map(h => (
                    <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {cases.map((c, i) => (
                  <tr key={c.id} onClick={() => setSelected(selected === c.id ? null : c.id)}
                    style={{ borderBottom: i < cases.length - 1 ? '1px solid var(--border-subtle)' : 'none', cursor: 'pointer', background: selected === c.id ? 'var(--accent-dim)' : 'transparent', transition: 'background 0.15s' }}>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
                        <FolderOpen size={13} color="var(--accent)" /> {c.title}
                      </div>
                      <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: 2 }}>{c.id.slice(0, 8)}…</div>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <span style={{ fontSize: '0.72rem', fontWeight: 700, padding: '3px 10px', borderRadius: 100, background: STATUS[c.status]?.bg, color: STATUS[c.status]?.color, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                        {c.status}
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><Mail size={12} /> {c.email_count}</span>
                    </td>
                    <td style={{ padding: '12px 16px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><Clock size={11} /> {new Date(c.created_at).toLocaleDateString()}</span>
                    </td>
                    <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                      <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end', alignItems: 'center' }}>
                        <button onClick={e => handleDelete(c.id, e)} title="Delete"
                          style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4, borderRadius: 4, transition: 'color 0.2s' }}
                          onMouseEnter={e => e.currentTarget.style.color = 'var(--critical)'}
                          onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}>
                          <Trash2 size={14} />
                        </button>
                        <ChevronRight size={16} color={selected === c.id ? 'var(--accent)' : 'var(--text-muted)'}
                          style={{ transform: selected === c.id ? 'rotate(90deg)' : 'none', transition: 'transform 0.2s' }} />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        {selected && <CaseDetail caseId={selected} onClose={() => setSelected(null)} />}
      </div>
    </div>
  )
}
