import React, { useState } from 'react'
import { AlertTriangle, Link, Globe, Server, Mail, Paperclip } from 'lucide-react'

export default function IOCList({ iocs }) {
  const [activeTab, setActiveTab] = useState('all')

  if (!iocs) return (
    <div className="card fade-in">
      <div className="card-header"><div className="card-title"><AlertTriangle size={16} /> IOC Intelligence</div></div>
      <div className="empty-state" style={{ padding: 20 }}>
        <div className="empty-state-sub">IOC extraction data unavailable.</div>
      </div>
    </div>
  )

  const urls = iocs.urls || []
  const domains = iocs.domains || []
  const ips = iocs.ips || []
  const emails = iocs.email_addresses || []
  const attachments = iocs.attachments || []

  const flatIocs = [
    ...urls.map(item => ({ ...item, category: 'url', icon: <Link size={12} /> })),
    ...domains.map(item => ({ ...item, category: 'domain', icon: <Globe size={12} /> })),
    ...ips.map(item => ({ ...item, category: 'ip', icon: <Server size={12} /> })),
    ...emails.map(item => ({ ...item, category: 'email', icon: <Mail size={12} /> })),
    ...attachments.map(item => ({ ...item, category: 'attachment', icon: <Paperclip size={12} /> }))
  ]

  const getSeverityBadge = (severity) => {
    const s = (severity || 'low').toLowerCase()
    if (s === 'critical') return 'badge-critical'
    if (s === 'high') return 'badge-high'
    if (s === 'medium') return 'badge-medium'
    return 'badge-low'
  }

  const filteredIocs = activeTab === 'all' 
    ? flatIocs 
    : flatIocs.filter(ioc => ioc.category === activeTab)

  return (
    <div className="card fade-in">
      <div className="card-header">
        <div className="card-title">
          <AlertTriangle size={16} />
          Indicators of Compromise (IOC Intelligence)
        </div>

        <div className="tabs">
          <button className={`tab ${activeTab === 'all' ? 'active' : ''}`} onClick={() => setActiveTab('all')}>
            All ({flatIocs.length})
          </button>
          <button className={`tab ${activeTab === 'url' ? 'active' : ''}`} onClick={() => setActiveTab('url')}>
            URLs ({urls.length})
          </button>
          <button className={`tab ${activeTab === 'domain' ? 'active' : ''}`} onClick={() => setActiveTab('domain')}>
            Domains ({domains.length})
          </button>
          <button className={`tab ${activeTab === 'ip' ? 'active' : ''}`} onClick={() => setActiveTab('ip')}>
            IPs ({ips.length})
          </button>
          <button className={`tab ${activeTab === 'email' ? 'active' : ''}`} onClick={() => setActiveTab('email')}>
            Emails ({emails.length})
          </button>
        </div>
      </div>

      {iocs.summary && (
        <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 12 }}>
          {iocs.summary}
        </div>
      )}

      {filteredIocs.length === 0 ? (
        <div className="empty-state" style={{ padding: '24px' }}>
          <div className="empty-state-sub">No indicators detected for this category.</div>
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Indicator Value</th>
                <th>Severity</th>
                <th>Context / Tags</th>
              </tr>
            </thead>
            <tbody>
              {filteredIocs.map((ioc, idx) => (
                <tr key={idx}>
                  <td style={{ textTransform: 'uppercase', fontSize: '0.72rem', fontWeight: 700 }}>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                      {ioc.icon} {(ioc.type || ioc.category).toUpperCase()}
                    </span>
                  </td>
                  <td className="mono" style={{ wordBreak: 'break-all', fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                    {ioc.value || ioc.indicator}
                  </td>
                  <td>
                    <span className={`badge ${getSeverityBadge(ioc.severity)}`} style={{ textTransform: 'uppercase' }}>
                      {ioc.severity || 'LOW'}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {(ioc.tags || []).map(t => (
                        <span key={t} className="ioc-tag">
                          {t}
                        </span>
                      ))}
                      {ioc.source && <span className="ioc-tag" style={{ color: 'var(--accent)' }}>{ioc.source}</span>}
                    </div>
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
