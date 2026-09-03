import { ShieldCheck, ShieldX, AlertTriangle } from 'lucide-react'

const RESULT_CONFIG = {
  pass:     { cls: 'pass',  icon: <ShieldCheck size={14} />,  label: 'PASS' },
  fail:     { cls: 'fail',  icon: <ShieldX size={14} />,      label: 'FAIL' },
  softfail: { cls: 'warn',  icon: <AlertTriangle size={14} />,label: 'SOFTFAIL' },
  neutral:  { cls: 'warn',  icon: <AlertTriangle size={14} />,label: 'NEUTRAL' },
  none:     { cls: 'none',  icon: null,                        label: 'NONE' },
  error:    { cls: 'fail',  icon: <ShieldX size={14} />,      label: 'ERROR' },
}

function AuthRow({ label, data }) {
  const result = data?.result || 'none'
  const config = RESULT_CONFIG[result] || RESULT_CONFIG.none

  const bgMap = {
    pass: 'var(--pass-dim)',
    fail: 'var(--fail-dim)',
    warn: 'var(--warn-dim)',
    none: 'rgba(139,163,199,0.05)',
  }

  return (
    <div className="auth-item" style={{ background: bgMap[config.cls] || bgMap.none }}>
      <span className="auth-item-label">{label}</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span className={`badge badge-${config.cls}`} style={{ fontSize: '0.72rem' }}>
          {config.icon}
          {config.label}
        </span>
      </div>
      {data?.detail && (
        <span className="auth-item-detail">{data.detail}</span>
      )}
      {data?.record && (
        <code style={{ fontSize: '0.7rem', color: 'var(--text-muted)', wordBreak: 'break-all', display: 'block', marginTop: 4 }}>
          {data.record.length > 80 ? data.record.slice(0, 80) + '…' : data.record}
        </code>
      )}
    </div>
  )
}

export default function AuthPanel({ authentication, fromDomain }) {
  if (!authentication) return null
  const { spf, dkim, dmarc } = authentication

  return (
    <div className="card fade-in">
      <div className="card-header">
        <div className="card-title">
          <ShieldCheck size={15} />
          Authentication Results
        </div>
        {fromDomain && (
          <code style={{ fontSize: '0.78rem', color: 'var(--accent)', background: 'var(--accent-dim)', padding: '2px 10px', borderRadius: 4 }}>
            {fromDomain}
          </code>
        )}
      </div>
      <div className="auth-grid">
        <AuthRow label="SPF" data={spf} />
        <AuthRow label="DKIM" data={dkim} />
        <AuthRow label="DMARC" data={dmarc} />
      </div>
    </div>
  )
}
