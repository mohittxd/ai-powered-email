import { Network } from 'lucide-react'

const SEVERITY_CONFIG = {
  critical: { color: 'var(--critical)', bg: 'var(--critical-dim)' },
  high:     { color: 'var(--high)',     bg: 'var(--high-dim)' },
  medium:   { color: 'var(--medium)',   bg: 'var(--medium-dim)' },
  low:      { color: '#8ba3c7',         bg: 'rgba(139,163,199,0.1)' },
}

export default function HeaderAnalysis({ hops = [], anomalies = [] }) {
  const getHopClass = (hop) => {
    if (hop.is_private) return 'priv'
    if (hop.hop_index === 0) return 'origin'
    return 'relay'
  }

  return (
    <div className="card fade-in">
      <div className="card-header">
        <div className="card-title">
          <Network size={15} />
          Received Chain Analysis
        </div>
        {anomalies.length > 0 && (
          <span className="badge badge-high">{anomalies.length} anomal{anomalies.length === 1 ? 'y' : 'ies'}</span>
        )}
      </div>

      {/* Anomalies */}
      {anomalies.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 16 }}>
          {anomalies.map((a, i) => {
            const cfg = SEVERITY_CONFIG[a.severity] || SEVERITY_CONFIG.low
            return (
              <div key={i} style={{
                padding: '8px 12px',
                borderRadius: 8,
                background: cfg.bg,
                border: `1px solid ${cfg.color}30`,
                display: 'flex',
                gap: 10,
                alignItems: 'flex-start',
                fontSize: '0.82rem',
              }}>
                <span style={{ color: cfg.color, fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginTop: 2, flexShrink: 0 }}>
                  {a.severity}
                </span>
                <div>
                  <span style={{ color: cfg.color, fontWeight: 600 }}>{a.type.replace(/_/g, ' ')}</span>
                  <span style={{ color: 'var(--text-secondary)', marginLeft: 8 }}>{a.detail}</span>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Hop chain */}
      {hops.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">📡</div>
          <div className="empty-state-title">No Received headers</div>
          <div className="empty-state-sub">Could not parse routing chain</div>
        </div>
      ) : (
        <div className="hop-chain">
          {hops.map((hop, i) => {
            const cls = getHopClass(hop)
            const flags = hop.threat_flags || []
            const isLast = i === hops.length - 1
            return (
              <div key={i} className="hop-item">
                <div className="hop-connector">
                  <div className={`hop-dot ${cls}`}>{hop.hop_index}</div>
                  {!isLast && <div className="hop-line" />}
                </div>
                <div className="hop-content">
                  <div className="hop-ip">
                    {hop.ip_address || hop.from_host || `Hop ${hop.hop_index}`}
                    {hop.is_private && (
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: 8, fontFamily: 'inherit' }}>
                        (private/internal)
                      </span>
                    )}
                  </div>
                  <div className="hop-meta">
                    {hop.from_host && <span>from {hop.from_host}</span>}
                    {hop.by_host && <span style={{ marginLeft: 8 }}>→ via {hop.by_host}</span>}
                    {hop.city && <span style={{ marginLeft: 8, color: 'var(--accent)' }}>📍 {hop.city}, {hop.country}</span>}
                    {hop.isp && <span style={{ marginLeft: 8 }}>· {hop.isp}</span>}
                    {hop.timestamp && (
                      <span style={{ marginLeft: 8, color: 'var(--text-muted)' }}>
                        {new Date(hop.timestamp).toUTCString()}
                      </span>
                    )}
                  </div>
                  {flags.length > 0 && (
                    <div className="hop-flags">
                      {flags.map(f => (
                        <span key={f} className={`badge badge-${f.includes('tor') ? 'critical' : f.includes('vpn') ? 'high' : 'medium'}`} style={{ fontSize: '0.68rem' }}>
                          {f.replace(/_/g, ' ')}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
