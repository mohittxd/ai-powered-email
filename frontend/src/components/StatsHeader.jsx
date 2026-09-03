import { useState, useEffect } from 'react'
import { statsOverview } from '../services/api'
import { Mail, Shield, AlertTriangle, TrendingUp, RefreshCw } from 'lucide-react'

export default function StatsHeader({ refreshKey }) {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const data = await statsOverview()
      setStats(data)
      setLastUpdated(new Date())
    } catch {}
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [refreshKey])

  const scoreColor = stats
    ? stats.avg_fraud_score >= 75 ? 'var(--critical)'
    : stats.avg_fraud_score >= 50 ? 'var(--high)'
    : stats.avg_fraud_score >= 25 ? 'var(--medium)'
    : 'var(--low)'
    : 'var(--text-muted)'

  const pills = stats ? [
    { icon: <Mail size={13} />,          label: 'Emails Analyzed',  value: stats.total_emails,  color: 'var(--accent)' },
    { icon: <AlertTriangle size={13} />, label: 'Total IOCs',        value: stats.total_iocs,    color: 'var(--high)' },
    { icon: <Shield size={13} />,        label: 'Critical IOCs',     value: stats.critical_iocs, color: 'var(--critical)' },
    { icon: <TrendingUp size={13} />,    label: 'Avg Fraud Score',   value: `${stats.avg_fraud_score}/100`, color: scoreColor },
  ] : []

  if (loading && !stats) return null

  return (
    <div style={{
      background: 'var(--surface-1)',
      border: '1px solid var(--border-subtle)',
      borderRadius: 12,
      padding: '10px 16px',
      display: 'flex',
      alignItems: 'center',
      gap: 12,
      flexWrap: 'wrap',
      marginBottom: 4,
    }}>
      <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
        Platform Stats
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', flex: 1 }}>
        {pills.map(p => (
          <div key={p.label} style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '4px 12px', borderRadius: 100,
            background: 'var(--surface-2)',
            border: '1px solid var(--border-subtle)',
            whiteSpace: 'nowrap',
          }}>
            <span style={{ color: p.color }}>{p.icon}</span>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{p.label}:</span>
            <span style={{ fontSize: '0.78rem', fontWeight: 700, color: p.color, fontFamily: 'monospace' }}>{p.value}</span>
          </div>
        ))}
      </div>

      {lastUpdated && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: '0.68rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
          <RefreshCw size={10} style={{ cursor: 'pointer' }} onClick={load} />
          {lastUpdated.toLocaleTimeString()}
        </div>
      )}
    </div>
  )
}
