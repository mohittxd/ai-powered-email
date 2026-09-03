import { useState } from 'react'
import { Bug, Copy, ChevronDown, ChevronRight } from 'lucide-react'

const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

const TYPE_ICON = {
  url:         '🔗',
  domain:      '🌐',
  ip:          '🖥️',
  attachment:  '📎',
  email_addr:  '📧',
}

export default function IOCTable({ iocs = [] }) {
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [copied, setCopied] = useState(null)

  const copyToClipboard = (val) => {
    navigator.clipboard.writeText(val).then(() => {
      setCopied(val)
      setTimeout(() => setCopied(null), 2000)
    })
  }

  const sorted = [...iocs]
    .sort((a, b) => (RISK_ORDER[a.risk_level] ?? 9) - (RISK_ORDER[b.risk_level] ?? 9))
    .filter(i => filter === 'all' || i.risk_level === filter || i.ioc_type === filter)
    .filter(i => !search || i.value.toLowerCase().includes(search.toLowerCase()))

  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  iocs.forEach(i => { if (counts[i.risk_level] !== undefined) counts[i.risk_level]++ })

  return (
    <div className="card fade-in">
      <div className="card-header">
        <div className="card-title">
          <Bug size={15} />
          Indicators of Compromise
          <span style={{ marginLeft: 6, background: 'var(--accent-dim)', color: 'var(--accent)', padding: '1px 8px', borderRadius: 100, fontSize: '0.72rem' }}>
            {iocs.length}
          </span>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {Object.entries(counts).map(([k, v]) => v > 0 && (
            <span key={k} className={`badge badge-${k}`} style={{ cursor: 'pointer' }}
              onClick={() => setFilter(filter === k ? 'all' : k)}>
              {v} {k}
            </span>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <input
          id="ioc-search"
          className="input"
          placeholder="Search IOCs..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ maxWidth: 280 }}
        />
        <select
          className="input"
          value={filter}
          onChange={e => setFilter(e.target.value)}
          style={{ maxWidth: 140, cursor: 'pointer' }}
        >
          <option value="all">All Types</option>
          <option value="url">URLs</option>
          <option value="domain">Domains</option>
          <option value="ip">IPs</option>
          <option value="attachment">Attachments</option>
          <option value="email_addr">Email Addresses</option>
        </select>
      </div>

      {sorted.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">🛡️</div>
          <div className="empty-state-title">No IOCs found</div>
          <div className="empty-state-sub">No indicators of compromise detected</div>
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Indicator</th>
                <th>Risk</th>
                <th>Context</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((ioc, i) => (
                <tr key={i}>
                  <td>
                    <span style={{ fontSize: '1rem' }}>{TYPE_ICON[ioc.ioc_type] || '❓'}</span>
                    {' '}
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{ioc.ioc_type}</span>
                  </td>
                  <td>
                    <code className="mono" style={{
                      maxWidth: 300,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      display: 'block',
                    }}>
                      {ioc.value}
                    </code>
                  </td>
                  <td>
                    <span className={`badge badge-${ioc.risk_level}`}>{ioc.risk_level}</span>
                  </td>
                  <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {ioc.context}
                  </td>
                  <td>
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() => copyToClipboard(ioc.value)}
                      title="Copy to clipboard"
                      style={{ padding: '4px 8px' }}
                    >
                      {copied === ioc.value ? '✓' : <Copy size={12} />}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
