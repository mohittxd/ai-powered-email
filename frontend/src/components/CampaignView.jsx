import { useState, useEffect } from 'react'
import { Network, RefreshCw, ChevronDown, ChevronRight, Mail, AlertTriangle, Shield } from 'lucide-react'
import api from '../services/api'

const THREAT_CONFIG = {
  critical: { bg: 'rgba(244,67,54,0.12)', color: '#f44336', border: 'rgba(244,67,54,0.3)', label: 'CRITICAL' },
  high:     { bg: 'rgba(255,152,0,0.12)', color: '#ff9800', border: 'rgba(255,152,0,0.3)',  label: 'HIGH' },
  medium:   { bg: 'rgba(255,235,59,0.08)',color: '#ffeb3b', border: 'rgba(255,235,59,0.25)',label: 'MEDIUM' },
  low:      { bg: 'rgba(76,175,80,0.1)',  color: '#4caf50', border: 'rgba(76,175,80,0.25)', label: 'LOW' },
}

function IOCPill({ value }) {
  const [type, ...rest] = value.split(':')
  const display = rest.join(':')
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 9px', borderRadius: 100, fontSize: '0.7rem',
      background: 'var(--surface-2)', border: '1px solid var(--border-subtle)',
      color: 'var(--text-secondary)', fontFamily: 'monospace', whiteSpace: 'nowrap',
    }}>
      <span style={{ color: 'var(--accent)', fontFamily: 'sans-serif', fontWeight: 700 }}>{type}</span>
      {display}
    </span>
  )
}

function CampaignCard({ campaign, index }) {
  const [expanded, setExpanded] = useState(false)
  const cfg = THREAT_CONFIG[campaign.threat_level] || THREAT_CONFIG.low

  return (
    <div style={{
      border: `1px solid ${cfg.border}`,
      borderRadius: 12, overflow: 'hidden',
      background: cfg.bg,
      transition: 'box-shadow 0.2s',
    }}>
      {/* Header */}
      <div
        onClick={() => setExpanded(v => !v)}
        style={{ padding: '14px 18px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 12 }}
      >
        <div style={{
          flexShrink: 0, width: 36, height: 36, borderRadius: 10,
          background: `${cfg.color}22`, display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: '1rem', fontWeight: 800, color: cfg.color,
        }}>
          {index + 1}
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--text-primary)' }}>
              Campaign #{campaign.id.slice(0, 8)}
            </span>
            <span style={{ fontSize: '0.68rem', fontWeight: 700, padding: '2px 8px', borderRadius: 100, background: `${cfg.color}22`, color: cfg.color, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              {cfg.label}
            </span>
          </div>
          <div style={{ display: 'flex', gap: 16, marginTop: 5, flexWrap: 'wrap' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.76rem', color: 'var(--text-muted)' }}>
              <Mail size={11} /> {campaign.email_count} emails
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.76rem', color: 'var(--text-muted)' }}>
              <Shield size={11} /> Avg score: <strong style={{ color: cfg.color }}>{campaign.avg_fraud_score}/100</strong>
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.76rem', color: 'var(--text-muted)' }}>
              <AlertTriangle size={11} /> {campaign.shared_indicators.length} shared IOCs
            </span>
          </div>
        </div>

        {expanded ? <ChevronDown size={16} color="var(--text-muted)" /> : <ChevronRight size={16} color="var(--text-muted)" />}
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ padding: '0 18px 18px', display: 'flex', flexDirection: 'column', gap: 14, borderTop: `1px solid ${cfg.border}` }}>
          {/* Shared IOCs */}
          {campaign.shared_indicators.length > 0 && (
            <div style={{ paddingTop: 14 }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8, fontWeight: 700 }}>
                Shared Indicators ({campaign.shared_indicators.length})
              </div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {campaign.shared_indicators.map((ioc, i) => <IOCPill key={i} value={ioc} />)}
              </div>
            </div>
          )}

          {/* Emails */}
          <div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8, fontWeight: 700 }}>
              Linked Emails
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {campaign.emails.map(e => {
                const sc = e.fraud_score >= 75 ? '#f44336' : e.fraud_score >= 50 ? '#ff9800' : e.fraud_score >= 25 ? '#ffeb3b' : '#4caf50'
                return (
                  <div key={e.id} style={{
                    display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px',
                    background: 'var(--surface-1)', borderRadius: 8, border: '1px solid var(--border-subtle)',
                  }}>
                    <Mail size={12} color="var(--accent)" style={{ flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {e.subject || '(no subject)'}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{e.from_address}</div>
                    </div>
                    <span style={{ fontFamily: 'monospace', fontSize: '0.72rem', fontWeight: 700, color: sc, background: `${sc}22`, padding: '2px 8px', borderRadius: 100, whiteSpace: 'nowrap' }}>
                      {e.fraud_score}/100
                    </span>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {e.analyzed_at ? new Date(e.analyzed_at).toLocaleDateString() : '—'}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default function CampaignView() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.get('/campaigns')
      setData(res.data)
    } catch { setError('Failed to load campaigns') }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const campaigns = data?.campaigns || []
  const critCount = campaigns.filter(c => c.threat_level === 'critical').length
  const highCount = campaigns.filter(c => c.threat_level === 'high').length

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Network size={20} color="var(--accent)" /> Campaign Correlation
          </h2>
          <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Emails grouped by shared high-risk IOCs (domains, IPs, URLs).
          </p>
        </div>
        <button onClick={load}
          style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px', borderRadius: 8, background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-secondary)', fontSize: '0.8rem', cursor: 'pointer' }}>
          <RefreshCw size={13} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} /> Refresh
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid-4" style={{ gap: 12 }}>
        <div className="stat-card"><div className="stat-label">Campaigns</div><div className="stat-value">{campaigns.length}</div></div>
        <div className="stat-card"><div className="stat-label">Critical</div><div className="stat-value" style={{ color: 'var(--critical)' }}>{critCount}</div></div>
        <div className="stat-card"><div className="stat-label">High</div><div className="stat-value" style={{ color: 'var(--high)' }}>{highCount}</div></div>
        <div className="stat-card">
          <div className="stat-label">Emails in Campaigns</div>
          <div className="stat-value">{campaigns.reduce((s, c) => s + c.email_count, 0)}</div>
        </div>
      </div>

      {/* Algorithm info */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 14px', borderRadius: 10, background: 'var(--accent-dim)', border: '1px solid rgba(0,230,118,0.2)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
        <span style={{ color: 'var(--accent)', fontSize: '1rem', flexShrink: 0 }}>🧠</span>
        <div>
          <strong style={{ color: 'var(--accent)' }}>Union-Find Clustering</strong> — emails sharing ≥1 high/critical-risk IOC (domain, IP, or URL) are automatically grouped into a campaign cluster.
          Only emails with 2+ members are shown. Re-run after analyzing more emails to discover new clusters.
        </div>
      </div>

      {error && (
        <div style={{ padding: '10px 14px', borderRadius: 8, background: 'rgba(244,67,54,0.1)', border: '1px solid var(--critical)', color: 'var(--critical)', fontSize: '0.82rem' }}>
          {error}
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-muted)' }}>
          <RefreshCw size={28} style={{ animation: 'spin 1s linear infinite', marginBottom: 12 }} />
          <div>Clustering emails…</div>
        </div>
      ) : campaigns.length === 0 ? (
        <div className="card">
          <div className="empty-state" style={{ padding: 40 }}>
            <div className="empty-state-icon">🔗</div>
            <div className="empty-state-title">No campaigns detected</div>
            <div className="empty-state-sub">
              Analyze multiple emails from the same phishing campaign — when they share high-risk IOCs, they'll be automatically clustered here.
            </div>
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {campaigns.map((c, i) => (
            <CampaignCard key={c.id} campaign={c} index={i} />
          ))}
        </div>
      )}

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
