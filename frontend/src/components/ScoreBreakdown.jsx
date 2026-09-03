import { BarChart3 } from 'lucide-react'

const BREAKDOWN_LABELS = {
  urgency:               'Urgency Language',
  credential_harvest:    'Credential Harvesting',
  payment_diversion:     'Payment Diversion',
  executive_impersonation: 'Executive Impersonation',
  url_risk:              'URL Risk Signals',
  display_name_mismatch: 'Display Name Mismatch',
  auth_failure:          'Auth Failures (SPF/DKIM)',
  geo_risk:              'Geo / Infra Risk',
  header_anomalies:      'Header Anomalies',
  attachment_risk:       'Risky Attachments',
}

const MAX_VALUES = {
  urgency: 15, credential_harvest: 20, payment_diversion: 20,
  executive_impersonation: 25, url_risk: 40, display_name_mismatch: 25,
  auth_failure: 32, geo_risk: 30, header_anomalies: 20, attachment_risk: 25,
}

function getBarColor(pct) {
  if (pct > 0.7) return '#ff4757'
  if (pct > 0.4) return '#ffa502'
  if (pct > 0.1) return '#ff6b35'
  return '#2ed573'
}

export default function ScoreBreakdown({ breakdown = {}, flags = [] }) {
  if (!breakdown || Object.keys(breakdown).length === 0) return null

  return (
    <div className="card fade-in">
      <div className="card-header">
        <div className="card-title">
          <BarChart3 size={15} />
          Score Breakdown
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {Object.entries(BREAKDOWN_LABELS).map(([key, label]) => {
          const val = breakdown[key] || 0
          const max = MAX_VALUES[key] || 25
          const pct = Math.min(val / max, 1)
          const color = getBarColor(pct)
          return (
            <div key={key} className="breakdown-row">
              <span className="breakdown-label">{label}</span>
              <div className="breakdown-bar-track">
                <div
                  className="breakdown-bar-fill"
                  style={{ width: `${pct * 100}%`, background: color }}
                />
              </div>
              <span className="breakdown-val" style={{ color: val > 0 ? color : 'var(--text-muted)' }}>
                {val}
              </span>
            </div>
          )
        })}
      </div>

      {flags.length > 0 && (
        <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--border-subtle)' }}>
          <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 8 }}>
            Active Threat Flags
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {flags.map((f, i) => (
              <span key={i} style={{
                fontSize: '0.72rem',
                padding: '2px 8px',
                borderRadius: 100,
                background: 'var(--critical-dim)',
                color: 'var(--critical)',
                border: '1px solid rgba(255,71,87,0.2)',
                fontFamily: 'monospace',
              }}>
                {f}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
