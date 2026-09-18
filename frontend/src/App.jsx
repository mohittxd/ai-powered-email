import { useState, useEffect } from 'react'
import { Shield, LayoutDashboard, FolderOpen, AlertTriangle, Settings, BookOpen, Network, LogOut, Server } from 'lucide-react'
import { useToast } from './components/Toast'
import Dashboard from './components/Dashboard'
import CaseManager from './components/CaseManager'
import IOCDatabase from './components/IOCDatabase'
import AuditLog from './components/AuditLog'
import CampaignView from './components/CampaignView'
import StatsHeader from './components/StatsHeader'
import Login from './components/Login'

function Sidebar({ active, setActive, onLogout }) {
    const items = [
    { id: 'dashboard', label: 'Analyzer',       icon: <LayoutDashboard size={16} />, section: 'Analysis' },
    { id: 'campaigns', label: 'Campaigns',       icon: <Network size={16} />,         section: 'Analysis' },
    { id: 'cases',     label: 'Case Manager',   icon: <FolderOpen size={16} />,      section: 'Investigation' },
    { id: 'iocs',      label: 'IOC Database',   icon: <AlertTriangle size={16} />,   section: 'Investigation' },
    { id: 'audit',     label: 'Audit Log',      icon: <BookOpen size={16} />,        section: 'Investigation' },
    { id: 'settings',  label: 'Settings',       icon: <Settings size={16} />,        section: 'System' },
  ]
  const sections = ['Analysis', 'Investigation', 'System']

  return (
    <div className="sidebar">
      {sections.map(section => (
        <div key={section}>
          <div className="sidebar-section-label">{section}</div>
          {items.filter(i => i.section === section).map(i => (
            <button key={i.id} id={`nav-${i.id}`}
              className={`sidebar-item ${active === i.id ? 'active' : ''}`}
              onClick={() => setActive(i.id)}>
              {i.icon} {i.label}
            </button>
          ))}
        </div>
      ))}

      <div style={{ marginTop: 'auto', paddingTop: 16, borderTop: '1px solid var(--border-subtle)', padding: '12px 8px 0' }}>
        <button onClick={onLogout}
          style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 8, padding: '8px 10px', borderRadius: 8, background: 'none', border: '1px solid var(--border-subtle)', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.78rem', transition: 'all 0.2s' }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--critical)'; e.currentTarget.style.color = 'var(--critical)' }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-subtle)'; e.currentTarget.style.color = 'var(--text-muted)' }}>
          <LogOut size={13} /> Sign Out
        </button>
        <div style={{ marginTop: 10, fontSize: '0.7rem', color: 'var(--text-muted)' }}>
        </div>
      </div>
    </div>
  )
}

function SettingsPage({ user }) {
  const toast = useToast()

  const [gmailStatus, setGmailStatus] = useState({
    connected: false,
    google_email: null,
    last_sync_at: null,
    last_sync_stats: null,
    loading: true,
  })
  const [syncing, setSyncing] = useState(false)
  const [syncResult, setSyncResult] = useState(null)

  // Docker serves the UI and API from the same origin. Keep the explicit
  // backend URL only for the Vite development server.
  const API = import.meta.env.VITE_API_URL
    || (window.location.port === '5173' ? 'http://localhost:8001' : '')

  const getToken = () => localStorage.getItem('ef_token')

  const loadGmailStatus = async () => {
    try {
      const token = getToken()
      const res = await fetch(`${API}/api/integrations/gmail/status`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      })

      if (!res.ok) throw new Error('Unable to check Gmail status')

      const data = await res.json()

      setGmailStatus({
        connected: !!data.connected,
        google_email: data.google_email || null,
        last_sync_at: data.last_sync_at || null,
        last_sync_stats: data.last_sync_stats || null,
        loading: false,
      })
    } catch (err) {
      console.error('Gmail status error:', err)
      setGmailStatus(prev => ({ ...prev, loading: false }))
    }
  }

  useEffect(() => {
    loadGmailStatus()

    const params = new URLSearchParams(window.location.search)
    if (params.get('gmail') === 'connected') {
      toast.push('Gmail connected successfully!', 'success')
      window.history.replaceState({}, document.title, window.location.pathname)
      loadGmailStatus()
      setTimeout(() => syncGmail(), 0)
    } else if (params.get('gmail') === 'denied') {
      toast.push('Gmail permission was not granted. You are still signed in.', 'error')
      window.history.replaceState({}, document.title, window.location.pathname)
    }
  }, [])

  const connectGmail = async () => {
    try {
      const token = getToken()

      const res = await fetch(`${API}/api/integrations/gmail/connect`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      })

      if (!res.ok) {
        const text = await res.text()
        throw new Error(text || 'Unable to start Gmail connection')
      }

      const data = await res.json()

      if (data.authorization_url) {
        window.location.href = data.authorization_url
      } else {
        throw new Error('Google authorization URL was not returned')
      }
    } catch (err) {
      console.error('Gmail connect error:', err)
      toast.push(err.message || 'Unable to connect Gmail', 'error')
    }
  }

  const syncGmail = async () => {
    setSyncing(true)
    setSyncResult(null)

    try {
      const token = getToken()

      const res = await fetch(`${API}/api/integrations/gmail/sync?max_results=20`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
        },
      })

      const data = await res.json()

      if (!res.ok) {
        throw new Error(data.detail || data.message || 'Gmail sync failed')
      }

      setSyncResult(data)
      setGmailStatus(prev => ({
        ...prev,
        last_sync_at: new Date().toISOString(),
        last_sync_stats: data,
      }))

      toast.push(
        `Gmail sync complete: ${data.imported || 0} imported, ${data.skipped || 0} skipped.`,
        'success'
      )

      // Notify other UI parts (Dashboard) to refresh imported emails list
      try { window.dispatchEvent(new Event('gmailSynced')) } catch (e) { /* ignore */ }
    } catch (err) {
      console.error('Gmail sync error:', err)
      toast.push(err.message || 'Gmail sync failed', 'error')
    } finally {
      setSyncing(false)
    }

  }

  const disconnectGmail = async () => {
      try {
        const res = await fetch(`${API}/api/integrations/gmail/disconnect`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${getToken()}` },
        })
        if (!res.ok) throw new Error('Unable to disconnect Gmail')
        setGmailStatus({
          connected: false,
          google_email: null,
          last_sync_at: null,
          last_sync_stats: null,
          loading: false,
        })
        setSyncResult(null)
        toast.push('Gmail disconnected. Existing forensic records were preserved.', 'success')
      } catch (err) {
        toast.push(err.message || 'Unable to disconnect Gmail', 'error')
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div>
        <h2 style={{ margin: 0, fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <Settings size={20} color="var(--accent)" /> Settings
        </h2>
        <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          Platform configuration and session info.
        </p>
      </div>

      <div className="grid-2" style={{ gap: 16 }}>
        {[
          {
            title: 'Active Session',
            items: [
              ['User', user?.name || '—'],
              ['Email', user?.email || '—'],
              ['ID', user?.id || '—'],
            ],
          },
          {
            title: 'Backend API',
            items: [
              ['Endpoint', API],
              ['Version', 'v3.0.0'],
              ['Status', '✅ Operational'],
              ['Auth', 'JWT (8h TTL)'],
            ],
          },
          {
            title: 'Analysis Engine',
            items: [
              ['Classifier', 'Rule-based NLP (10-dim)'],
              ['Score Range', '0–100'],
              ['DB', 'PostgreSQL'],
              ['Clustering', 'Union-Find'],
            ],
          },
          {
            title: 'Integrations',
            items: [
              ['Geolocation', 'ipinfo.io'],
              ['DNS', 'dnspython'],
              ['PDF', 'reportlab'],
              ['Gmail', 'Google OAuth'],
            ],
          },
        ].map(group => (
          <div key={group.title} className="card" style={{ padding: '16px 20px' }}>
            <div style={{
              fontSize: '0.75rem',
              fontWeight: 700,
              color: 'var(--accent)',
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              marginBottom: 12
            }}>
              {group.title}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {group.items.map(([k, v]) => (
                <div key={k} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  fontSize: '0.82rem'
                }}>
                  <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                  <span style={{
                    color: 'var(--text-secondary)',
                    fontFamily: ['Endpoint', 'DB', 'ID'].includes(k) ? 'monospace' : 'inherit',
                    fontSize: ['Endpoint', 'ID'].includes(k) ? '0.73rem' : 'inherit'
                  }}>
                    {v}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Gmail Integration */}
      <div className="card" style={{ padding: '20px 24px' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 10,
          marginBottom: 6
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Server size={16} color="var(--accent)" />
            <div style={{
              fontSize: '0.75rem',
              fontWeight: 700,
              color: 'var(--accent)',
              letterSpacing: '0.08em',
              textTransform: 'uppercase'
            }}>
              Gmail Integration
            </div>

            <span style={{
              fontSize: '0.62rem',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: 100,
              background: gmailStatus.connected
                ? 'rgba(46, 204, 113, 0.12)'
                : 'rgba(255,165,2,0.12)',
              color: gmailStatus.connected ? '#2ecc71' : '#ffa502',
              border: `1px solid ${gmailStatus.connected ? 'rgba(46, 204, 113, 0.3)' : 'rgba(255,165,2,0.3)'}`,
              textTransform: 'uppercase',
              letterSpacing: '0.06em'
            }}>
              {gmailStatus.loading
                ? 'Checking'
                : gmailStatus.connected
                  ? 'Connected'
                  : 'Not Connected'}
            </span>
          </div>
        </div>

        <p style={{
          fontSize: '0.78rem',
          color: 'var(--text-muted)',
          marginBottom: 16
        }}>
          Connect Google Gmail using OAuth and securely ingest mailbox messages
          into the forensic analysis pipeline.
        </p>

        {gmailStatus.connected && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
            padding: '10px 12px',
            marginBottom: 14,
            borderRadius: 8,
            background: 'var(--accent-dim)',
            border: '1px solid var(--border-subtle)'
          }}>
            <div>
              <div style={{
                fontSize: '0.68rem',
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                marginBottom: 3
              }}>
                Connected Account
              </div>

              <div style={{
                fontSize: '0.85rem',
                color: 'var(--text-primary)',
                fontWeight: 600
              }}>
                {gmailStatus.google_email || 'Google account connected'}
              </div>
              {gmailStatus.last_sync_at && (
                <div style={{ marginTop: 4, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                  Last sync: {new Date(gmailStatus.last_sync_at).toLocaleString()}
                </div>
              )}
            </div>

            <button
              onClick={syncGmail}
              disabled={syncing}
              style={{
                padding: '9px 18px',
                borderRadius: 8,
                background: syncing ? 'var(--border-subtle)' : 'var(--accent)',
                border: '1px solid var(--accent)',
                color: syncing ? 'var(--text-muted)' : '#fff',
                fontWeight: 700,
                fontSize: '0.82rem',
                cursor: syncing ? 'not-allowed' : 'pointer',
                whiteSpace: 'nowrap'
              }}
            >
              {syncing ? 'Syncing Gmail…' : '↻ Sync Gmail'}
            </button>
            <button
              onClick={disconnectGmail}
              disabled={syncing}
              style={{
                padding: '9px 14px',
                borderRadius: 8,
                background: 'transparent',
                border: '1px solid var(--critical)',
                color: 'var(--critical)',
                fontWeight: 700,
                fontSize: '0.82rem',
                cursor: syncing ? 'not-allowed' : 'pointer',
              }}
            >
              Disconnect Gmail
            </button>
          </div>
        )}

        {!gmailStatus.connected && !gmailStatus.loading && (
          <button
            onClick={connectGmail}
            style={{
              padding: '10px 20px',
              borderRadius: 8,
              background: 'var(--accent-dim)',
              border: '1px solid var(--accent)',
              color: 'var(--accent)',
              fontWeight: 700,
              fontSize: '0.82rem',
              cursor: 'pointer'
            }}
          >
            Connect Gmail with Google
          </button>
        )}

        {syncResult && (
          <div style={{
            marginTop: 14,
            padding: 14,
            borderRadius: 8,
            background: 'rgba(46, 204, 113, 0.06)',
            border: '1px solid rgba(46, 204, 113, 0.2)'
          }}>
            <div style={{
              fontSize: '0.72rem',
              fontWeight: 700,
              color: 'var(--accent)',
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              marginBottom: 10
            }}>
              Last Sync
            </div>

            <div style={{
              display: 'flex',
              gap: 24,
              flexWrap: 'wrap',
              fontSize: '0.82rem'
            }}>
              <span><strong>{syncResult.imported ?? syncResult.imported_count ?? 0}</strong> Imported</span>
              <span><strong>{syncResult.skipped ?? syncResult.skipped_count ?? 0}</strong> Skipped</span>
              <span><strong>{syncResult.failed ?? syncResult.failed_count ?? 0}</strong> Failed</span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function App() {
  const [activePage, setActivePage] = useState('dashboard')
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem('ef_user') || 'null') } catch { return null }
  })
  const [statsKey, setStatsKey] = useState(0)
  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get('auth_token')
    const gmailConnected = new URLSearchParams(window.location.search).get('gmail') === 'connected'
    if (gmailConnected) setActivePage('settings')
    if (token) {
      localStorage.setItem('ef_token', token)
      window.history.replaceState({}, document.title, window.location.pathname)
      fetch('/api/v1/auth/me', { headers: { Authorization: `Bearer ${token}` } })
        .then(r => r.ok ? r.json() : null).then(data => data && (localStorage.setItem('ef_user', JSON.stringify(data)), setUser(data)))
    }
  }, [])

  const handleLogin = (userData) => setUser(userData)
  const handleLogout = () => {
    localStorage.removeItem('ef_token')
    localStorage.removeItem('ef_user')
    setUser(null)
  }

  // Bump statsKey after analysis to refresh StatsHeader
  const handlePageChange = (page) => {
    setActivePage(page)
    if (page === 'dashboard') setStatsKey(k => k + 1)
  }

  if (!user) return <Login onLogin={handleLogin} />

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard': return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <StatsHeader refreshKey={statsKey} />
          <Dashboard onAnalyzed={() => setStatsKey(k => k + 1)} />
        </div>
      )
      case 'campaigns': return <CampaignView />
      case 'cases':     return <CaseManager />
      case 'iocs':      return <IOCDatabase />
      case 'audit':     return <AuditLog />
      case 'settings':  return <SettingsPage user={user} />
      default:          return <Dashboard />
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-logo">
          <div className="logo-icon"><Shield size={16} color="#fff" /></div>
          Forensic AI
        </div>
        <div className="topbar-spacer" />
        <div className="topbar-status">
          <div className="status-dot" />
          System Operational
        </div>
        <div style={{ width: 1, height: 20, background: 'var(--border-subtle)', margin: '0 8px' }} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            <span style={{ color: 'var(--text-secondary)' }}>{user.name}</span>
          </div>
        </div>
      </header>

      <Sidebar active={activePage} setActive={handlePageChange} onLogout={handleLogout} />

      <main className="main-content">
        {renderPage()}
      </main>
    </div>
  )
}
