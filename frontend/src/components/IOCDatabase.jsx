import { useState, useEffect, useRef } from 'react'
import { listIocs, searchIocs, iocStats } from '../services/api'
import { AlertTriangle, Search, Copy, Check, Shield, Globe, Link, Mail, Paperclip, Server } from 'lucide-react'

const RISK_CONFIG = {
  critical: { bg: 'rgba(244,67,54,0.15)', color: 'var(--critical)', dot: '#f44336' },
  high:     { bg: 'rgba(255,152,0,0.15)', color: 'var(--high)',     dot: '#ff9800' },
  medium:   { bg: 'rgba(255,235,59,0.12)', color: 'var(--medium)',  dot: '#ffeb3b' },
  low:      { bg: 'rgba(76,175,80,0.12)', color: 'var(--low)',      dot: '#4caf50' },
}

const TYPE_ICONS = {
  url:         <Link size={13} />,
  domain:      <Globe size={13} />,
  ip:          <Server size={13} />,
  email_addr:  <Mail size={13} />,
  attachment:  <Paperclip size={13} />,
}

function RiskBadge({ level }) {
  const c = RISK_CONFIG[level] || RISK_CONFIG.low
  return (
    <span style={{ fontSize: '0.68rem', fontWeight: 700, padding: '2px 8px', borderRadius: 100, background: c.bg, color: c.color, textTransform: 'uppercase', letterSpacing: '0.06em', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: c.dot, display: 'inline-block' }} />
      {level}
    </span>
  )
}

function CopyBtn({ value }) {
  const [copied, setCopied] = useState(false)
  const copy = () => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500) }
  return (
    <button onClick={copy} title="Copy" style={{ background: 'none', border: 'none', color: copied ? 'var(--low)' : 'var(--text-muted)', cursor: 'pointer', padding: '2px 4px', borderRadius: 4, transition: 'color 0.2s' }}>
      {copied ? <Check size={13} /> : <Copy size={13} />}
    </button>
  )
}

export default function IOCDatabase() {
  const [iocs, setIocs] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')
  const [filterType, setFilterType] = useState('')
  const [filterRisk, setFilterRisk] = useState('')
  const [error, setError] = useState(null)
  const debounceRef = useRef(null)

  const loadIocs = async (q = '', type = '', risk = '') => {
    setLoading(true)
    try {
      let data
      if (q.length >= 2) {
        data = await searchIocs(q)
      } else {
        const params = {}
        if (type) params.ioc_type = type
        if (risk) params.risk_level = risk
        data = await listIocs(params)
      }
      setIocs(data)
    } catch { setError('Failed to load IOCs') }
    finally { setLoading(false) }
  }

  const loadStats = async () => { try { setStats(await iocStats()) } catch {} }

  useEffect(() => { loadStats(); loadIocs() }, [])

  const handleSearch = (val) => {
    setQuery(val)
    clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => loadIocs(val, filterType, filterRisk), 350)
  }

  const handleFilter = (type, risk) => {
    setFilterType(type); setFilterRisk(risk)
    loadIocs(query, type, risk)
  }

  const types = ['', 'url', 'domain', 'ip', 'email_addr', 'attachment']
  const risks = ['', 'critical', 'high', 'medium', 'low']

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div>
        <h2 style={{ margin: 0, fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertTriangle size={20} color="var(--high)" /> IOC Database
        </h2>
        <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          Persistent indicators of compromise extracted from all analyzed emails.
        </p>
      </div>

      {/* Stat cards */}
      {stats && (
        <div className="grid-4" style={{ gap: 12 }}>
          <div className="stat-card"><div className="stat-label">Total IOCs</div><div className="stat-value">{stats.total}</div></div>
          <div className="stat-card"><div className="stat-label">Critical</div><div className="stat-value" style={{ color: 'var(--critical)' }}>{stats.critical}</div></div>
          <div className="stat-card">
            <div className="stat-label">Top Type</div>
            <div className="stat-value" style={{ fontSize: '1rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              {stats.by_type?.[0]?.type || '—'}
            </div>
            <div className="stat-sub">{stats.by_type?.[0]?.count} indicators</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Unique Types</div>
            <div className="stat-value">{stats.by_type?.length || 0}</div>
          </div>
        </div>
      )}

      {/* Type breakdown mini-bar */}
      {stats?.by_type?.length > 0 && (
        <div className="card" style={{ padding: '14px 18px' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Distribution by Type</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {stats.by_type.map(t => (
              <div key={t.type} onClick={() => handleFilter(filterType === t.type ? '' : t.type, filterRisk)}
                style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', borderRadius: 8, background: filterType === t.type ? 'var(--accent-dim)' : 'var(--surface-2)', border: `1px solid ${filterType === t.type ? 'var(--accent)' : 'var(--border-subtle)'}`, cursor: 'pointer', transition: 'all 0.2s' }}>
                <span style={{ color: filterType === t.type ? 'var(--accent)' : 'var(--text-muted)' }}>{TYPE_ICONS[t.type]}</span>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>{t.type}</span>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{t.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Search + filter bar */}
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 200, position: 'relative', display: 'flex', alignItems: 'center' }}>
          <Search size={14} style={{ position: 'absolute', left: 12, color: 'var(--text-muted)' }} />
          <input id="ioc-search-input" value={query} onChange={e => handleSearch(e.target.value)}
            placeholder="Search IOC values…"
            style={{ width: '100%', padding: '9px 12px 9px 34px', borderRadius: 8, background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-primary)', fontSize: '0.85rem', outline: 'none', boxSizing: 'border-box' }} />
        </div>
        <select id="ioc-filter-risk" value={filterRisk} onChange={e => handleFilter(filterType, e.target.value)}
          style={{ padding: '9px 12px', borderRadius: 8, background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-secondary)', fontSize: '0.82rem', outline: 'none' }}>
          {risks.map(r => <option key={r} value={r}>{r ? `Risk: ${r}` : 'All risks'}</option>)}
        </select>
        <button onClick={() => { setQuery(''); setFilterType(''); setFilterRisk(''); loadIocs('', '', '') }}
          style={{ padding: '9px 14px', borderRadius: 8, background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.8rem' }}>
          Clear
        </button>
      </div>

      {error && (
        <div style={{ background: 'rgba(244,67,54,0.1)', border: '1px solid var(--critical)', borderRadius: 8, padding: '10px 14px', color: 'var(--critical)', fontSize: '0.82rem' }}>
          {error}
        </div>
      )}

      {/* IOC Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading indicators…</div>
        ) : iocs.length === 0 ? (
          <div className="empty-state" style={{ padding: 40 }}>
            <div className="empty-state-icon"><Shield size={32} /></div>
            <div className="empty-state-title">{query ? 'No matches found' : 'No IOCs yet'}</div>
            <div className="empty-state-sub">Analyze emails in the Analyzer tab to extract indicators of compromise.</div>
          </div>
        ) : (
          <>
            <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Showing {iocs.length} indicator{iocs.length !== 1 ? 's' : ''}</span>
            </div>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  {['Type', 'Value', 'Risk', 'Context', ''].map(h => (
                    <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc, i) => (
                  <tr key={ioc.id} style={{ borderBottom: i < iocs.length - 1 ? '1px solid var(--border-subtle)' : 'none' }}>
                    <td style={{ padding: '10px 16px', whiteSpace: 'nowrap' }}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                        <span style={{ color: 'var(--accent)' }}>{TYPE_ICONS[ioc.type]}</span>
                        {ioc.type}
                      </span>
                    </td>
                    <td style={{ padding: '10px 16px', maxWidth: 360 }}>
                      <code style={{ fontSize: '0.78rem', color: 'var(--text-primary)', wordBreak: 'break-all' }}>{ioc.value}</code>
                    </td>
                    <td style={{ padding: '10px 16px', whiteSpace: 'nowrap' }}><RiskBadge level={ioc.risk_level} /></td>
                    <td style={{ padding: '10px 16px', fontSize: '0.75rem', color: 'var(--text-muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {ioc.context || '—'}
                    </td>
                    <td style={{ padding: '10px 16px', textAlign: 'right' }}><CopyBtn value={ioc.value} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  )
}
