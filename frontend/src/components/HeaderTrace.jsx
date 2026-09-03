import React from 'react'
import { Route, Globe, Server, AlertTriangle } from 'lucide-react'

export default function HeaderTrace({ forensics, geoip }) {
  if (!forensics || !forensics.received_chain) return (
    <div className="card fade-in">
      <div className="card-header"><div className="card-title"><Route size={16} /> Routing Trace & Header Forensics</div></div>
      <div className="empty-state" style={{ padding: 20 }}>
        <div className="empty-state-sub">Header forensics unavailable.</div>
      </div>
    </div>
  )

  const chain = forensics.received_chain || []
  const earliestIp = forensics.earliest_observed_public_sender_ip
  const anomalies = forensics.anomalies || []

  // Origin info resolution
  const country = geoip?.country || 'Unavailable'
  const city = geoip?.city || 'Unavailable'
  const isp = geoip?.isp || 'Unavailable'
  const asn = geoip?.asn || 'Unavailable'

  return (
    <div className="card fade-in">
      <div className="card-header">
        <div className="card-title">
          <Route size={16} />
          Origin Trace & Received Hops ({chain.length} Hops)
        </div>
      </div>

      {/* Origin Details Summary */}
      {earliestIp ? (
        <div className="analysis-banner medium" style={{ marginBottom: 16, background: 'rgba(79, 195, 247, 0.08)', borderColor: 'rgba(79, 195, 247, 0.25)', color: 'var(--text-primary)' }}>
          <Globe size={22} color="var(--accent)" style={{ flexShrink: 0 }} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700, color: 'var(--accent)', marginBottom: 4 }}>
              Earliest Observed Public Sender Origin
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 8, fontSize: '0.78rem' }}>
              <div><span style={{ color: 'var(--text-muted)' }}>Public IP: </span><strong className="mono" style={{ color: 'var(--text-primary)' }}>{earliestIp}</strong></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Country: </span><strong>{country}</strong></div>
              <div><span style={{ color: 'var(--text-muted)' }}>City: </span><strong>{city}</strong></div>
              <div><span style={{ color: 'var(--text-muted)' }}>ISP: </span><strong>{isp}</strong></div>
              <div><span style={{ color: 'var(--text-muted)' }}>ASN: </span><strong>{asn}</strong></div>
            </div>
          </div>
        </div>
      ) : (
        <div style={{ marginBottom: 16, padding: '10px 14px', background: 'var(--bg-surface)', borderRadius: 6, fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          Earliest observed public IP: <em>Internal or private network hop only</em>
        </div>
      )}

      {/* Header Anomalies List */}
      {anomalies.length > 0 && (
        <div style={{ marginBottom: 16, display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--critical)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <AlertTriangle size={12} /> Header Anomalies ({anomalies.length})
          </div>
          {anomalies.map((anom, idx) => (
            <div key={idx} style={{
              padding: '8px 12px',
              borderRadius: 6,
              background: 'var(--critical-dim)',
              border: '1px solid rgba(245,49,93,0.2)',
              fontSize: '0.78rem',
              color: '#ffc0cb',
              display: 'flex',
              alignItems: 'center',
              gap: 8
            }}>
              <span className="badge badge-critical" style={{ textTransform: 'uppercase', fontSize: '0.65rem' }}>{anom.type || 'ANOMALY'}</span>
              <span>{anom.detail || anom.description}</span>
            </div>
          ))}
        </div>
      )}

      {/* Hop Chain Timeline */}
      <div className="hop-chain">
        {chain.map((hop, idx) => {
          const isOrigin = hop.source_ip === earliestIp && earliestIp !== null
          const dotClass = isOrigin ? 'origin' : hop.source_ip ? 'relay' : 'priv'

          return (
            <div key={idx} className="hop-item">
              <div className="hop-connector">
                <div className={`hop-dot ${dotClass}`}>{chain.length - idx}</div>
                {idx < chain.length - 1 && <div className="hop-line" />}
              </div>
              <div className="hop-content">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div className="hop-ip">
                    {hop.source_ip || hop.source_host || hop.source_hostname || 'Internal Hop'}
                    {isOrigin && (
                      <span className="badge badge-critical" style={{ marginLeft: 8, fontSize: '0.62rem' }}>
                        EARLIEST PUBLIC SENDER
                      </span>
                    )}
                  </div>
                  <div className="hop-meta mono" style={{ fontSize: '0.72rem' }}>{hop.timestamp || 'Time unavailable'}</div>
                </div>

                <div className="hop-meta" style={{ marginTop: 4, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                  <div><strong style={{ color: 'var(--text-muted)' }}>From Host:</strong> {hop.source_host || hop.source_hostname || '-'}</div>
                  <div><strong style={{ color: 'var(--text-muted)' }}>By Host:</strong> {hop.dest_host || hop.receiving_hostname || '-'}</div>
                </div>

                {hop.protocol && (
                  <div className="hop-flags">
                    <span className="info-chip" style={{ fontSize: '0.65rem' }}>
                      <Server size={10} /> {hop.protocol}
                    </span>
                    {hop.is_public && <span className="badge badge-pass" style={{ fontSize: '0.62rem' }}>Public Route</span>}
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
