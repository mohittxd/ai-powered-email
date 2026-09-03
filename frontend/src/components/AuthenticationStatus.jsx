import React from 'react'
import { ShieldCheck, ShieldAlert, ShieldX, HelpCircle, Info } from 'lucide-react'

export default function AuthenticationStatus({ auth }) {
  if (!auth) return (
    <div className="card fade-in">
      <div className="card-header">
        <div className="card-title"><ShieldCheck size={16} /> Authentication Status</div>
      </div>
      <div className="empty-state" style={{ padding: 20 }}>
        <div className="empty-state-sub">Authentication analysis unavailable.</div>
      </div>
    </div>
  )

  const getStatusBadge = (protoData) => {
    if (!protoData) return { label: 'UNKNOWN', cls: 'badge-none', icon: <HelpCircle size={13} /> }
    const st = (protoData.mta_reported || protoData.status || 'UNKNOWN').toUpperCase()
    if (st === 'PASS') return { label: 'PASS', cls: 'badge-pass', icon: <ShieldCheck size={13} /> }
    if (['FAIL', 'SOFTFAIL', 'PERMERROR'].includes(st)) return { label: st, cls: 'badge-fail', icon: <ShieldX size={13} /> }
    if (['NEUTRAL', 'NONE', 'TEMPERROR'].includes(st)) return { label: st, cls: 'badge-warn', icon: <ShieldAlert size={13} /> }
    return { label: st, cls: 'badge-none', icon: <HelpCircle size={13} /> }
  }

  const protocols = [
    { key: 'spf', title: 'SPF (Sender Policy Framework)' },
    { key: 'dkim', title: 'DKIM (DomainKeys Identified Mail)' },
    { key: 'dmarc', title: 'DMARC (Domain Message Auth & Conformance)' }
  ]

  return (
    <div className="card fade-in" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div className="card-header">
        <div className="card-title">
          <ShieldCheck size={16} />
          Email Authentication Security
        </div>
        <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
          MTA & DNS Alignment Verification
        </span>
      </div>

      <div className="auth-grid">
        {protocols.map(({ key, title }) => {
          const protoData = auth[key]
          const badge = getStatusBadge(protoData)
          
          return (
            <div key={key} className="auth-item" style={{ background: 'var(--bg-surface)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="auth-item-label">{key.toUpperCase()}</span>
                <span className={`badge ${badge.cls}`}>
                  {badge.icon} {badge.label}
                </span>
              </div>

              <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: 4 }}>
                {title}
              </div>

              <div className="auth-item-detail" style={{ marginTop: 6, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                {protoData?.detail || protoData?.reason || 'No detailed header feedback reported.'}
              </div>

              {protoData?.domain && (
                <div style={{ marginTop: 6, fontSize: '0.68rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent)' }}>
                  Domain: {protoData.domain}
                </div>
              )}
            </div>
          )
        })}
      </div>

      {auth.summary && (
        <div style={{
          marginTop: 12,
          padding: '8px 12px',
          background: 'var(--bg-surface)',
          borderRadius: 6,
          border: '1px solid var(--border-subtle)',
          fontSize: '0.74rem',
          color: 'var(--text-secondary)',
          display: 'flex',
          alignItems: 'center',
          gap: 6
        }}>
          <Info size={13} color="var(--accent)" />
          <span>{auth.summary}</span>
        </div>
      )}
    </div>
  )
}
