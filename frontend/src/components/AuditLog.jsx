import { useState, useEffect } from 'react'
import { listAudit, auditStats } from '../services/api'
import { BookOpen, RefreshCw, ChevronLeft, ChevronRight } from 'lucide-react'

const ACTION_CONFIG = {
  analyze_email:       { label: 'Email Analyzed',   color: 'var(--accent)',    icon: '🔍' },
  export_json_report:  { label: 'JSON Exported',    color: 'var(--low)',       icon: '📄' },
  export_pdf_report:   { label: 'PDF Exported',     color: 'var(--low)',       icon: '📑' },
  create_case:         { label: 'Case Created',     color: 'var(--medium)',    icon: '📂' },
  update_case_status:  { label: 'Status Updated',   color: 'var(--high)',      icon: '🔄' },
  delete_case:         { label: 'Case Deleted',     color: 'var(--critical)',  icon: '🗑' },
}

function getActionInfo(action) {
  return ACTION_CONFIG[action] || { label: action, color: 'var(--text-muted)', icon: '📋' }
}

function TimelineDot({ color }) {
  return (
    <div style={{ flexShrink: 0, width: 32, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}66`, marginTop: 4 }} />
    </div>
  )
}

const PAGE_SIZE = 25

export default function AuditLog() {
  const [logs, setLogs] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(0)
  const [hasMore, setHasMore] = useState(true)

  const load = async (p = 0) => {
    setLoading(true)
    try {
      const data = await listAudit({ skip: p * PAGE_SIZE, limit: PAGE_SIZE })
      setLogs(data)
      setHasMore(data.length === PAGE_SIZE)
      if (p === 0) {
        const s = await auditStats()
        setStats(s)
      }
    } catch {}
    finally { setLoading(false) }
  }

  useEffect(() => { load(0) }, [])

  const goPage = (p) => { setPage(p); load(p) }

  // Group by date
  const grouped = {}
  logs.forEach(l => {
    const day = l.timestamp ? new Date(l.timestamp).toLocaleDateString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }) : 'Unknown date'
    if (!grouped[day]) grouped[day] = []
    grouped[day].push(l)
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <BookOpen size={20} color="var(--accent)" /> Audit Log
          </h2>
          <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Immutable chain-of-custody log of all analyst actions.
          </p>
        </div>
        <button onClick={() => { setPage(0); load(0) }}
          style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px', borderRadius: 8, background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-secondary)', fontSize: '0.8rem', cursor: 'pointer' }}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* Stat cards */}
      {stats && (
        <div className="grid-4" style={{ gap: 12 }}>
          <div className="stat-card">
            <div className="stat-label">Total Events</div>
            <div className="stat-value">{stats.total}</div>
          </div>
          {stats.by_action?.slice(0, 3).map(a => {
            const info = getActionInfo(a.action)
            return (
              <div key={a.action} className="stat-card">
                <div className="stat-label">{info.label}</div>
                <div className="stat-value" style={{ color: info.color }}>{a.count}</div>
              </div>
            )
          })}
        </div>
      )}

      {/* Timeline */}
      <div className="card" style={{ padding: '16px 20px' }}>
        {loading ? (
          <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>Loading audit log…</div>
        ) : logs.length === 0 ? (
          <div className="empty-state" style={{ padding: 40 }}>
            <div className="empty-state-icon">📋</div>
            <div className="empty-state-title">No audit entries yet</div>
            <div className="empty-state-sub">Actions like email analysis and report exports will appear here.</div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            {Object.entries(grouped).map(([day, entries]) => (
              <div key={day}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 12, paddingLeft: 40, borderBottom: '1px solid var(--border-subtle)', paddingBottom: 6 }}>
                  {day}
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                  {entries.map((l, i) => {
                    const info = getActionInfo(l.action)
                    return (
                      <div key={l.id} style={{ display: 'flex', gap: 0, position: 'relative' }}>
                        {/* Vertical line */}
                        {i < entries.length - 1 && (
                          <div style={{ position: 'absolute', left: 15, top: 18, bottom: 0, width: 1, background: 'var(--border-subtle)' }} />
                        )}
                        <TimelineDot color={info.color} />
                        <div style={{ flex: 1, paddingBottom: 16, paddingLeft: 12 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                              {info.icon} {info.label}
                            </span>
                            {l.resource_type && (
                              <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', background: 'var(--surface-2)', padding: '1px 7px', borderRadius: 100 }}>
                                {l.resource_type}
                              </span>
                            )}
                          </div>
                          <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
                            {l.analyst_id && (
                              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                                👤 {l.analyst_id}
                              </span>
                            )}
                            {l.resource_id && (
                              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                                ID: {l.resource_id.slice(0, 8)}…
                              </span>
                            )}
                            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                              {l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : ''}
                            </span>
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Pagination */}
        {!loading && logs.length > 0 && (
          <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--border-subtle)' }}>
            <button disabled={page === 0} onClick={() => goPage(page - 1)}
              style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '6px 12px', borderRadius: 6, background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-secondary)', cursor: page === 0 ? 'not-allowed' : 'pointer', opacity: page === 0 ? 0.4 : 1, fontSize: '0.8rem' }}>
              <ChevronLeft size={13} /> Prev
            </button>
            <span style={{ padding: '6px 14px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Page {page + 1}
            </span>
            <button disabled={!hasMore} onClick={() => goPage(page + 1)}
              style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '6px 12px', borderRadius: 6, background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-secondary)', cursor: !hasMore ? 'not-allowed' : 'pointer', opacity: !hasMore ? 0.4 : 1, fontSize: '0.8rem' }}>
              Next <ChevronRight size={13} />
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
