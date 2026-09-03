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

const ROLE_COLORS = {
  admin:        '#f44336',
  analyst:      'var(--accent)',
  investigator: '#ff9800',
}

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
          <div>EmailForensics v3.0.0</div>
          <div style={{ marginTop: 2, color: 'var(--critical)', fontSize: '0.65rem' }}>🔒 SOC · Legal · IR</div>
        </div>
      </div>
    </div>
  )
}

function SettingsPage({ user }) {
  const toast = useToast()
  const [imapHost, setImapHost] = useState('')
  const [imapUser, setImapUser] = useState('')
  const [imapPass, setImapPass] = useState('')

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div>
        <h2 style={{ margin: 0, fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <Settings size={20} color="var(--accent)" /> Settings
        </h2>
        <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Platform configuration and session info.</p>
      </div>
      <div className="grid-2" style={{ gap: 16 }}>
        {[
          { title: 'Active Session', items: [['User', user?.name || '—'], ['Email', user?.email || '—'], ['Role', user?.role || '—'], ['ID', user?.id || '—']] },
          { title: 'Backend API', items: [['Endpoint', 'http://localhost:8000'], ['Version', 'v3.0.0'], ['Status', '✅ Operational'], ['Auth', 'JWT (8h TTL)']] },
          { title: 'Analysis Engine', items: [['Classifier', 'Rule-based NLP (10-dim)'], ['Score Range', '0–100'], ['DB', 'SQLite'], ['Clustering', 'Union-Find']] },
          { title: 'Integrations', items: [['Geolocation', 'ipinfo.io'], ['DNS', 'dnspython'], ['PDF', 'reportlab (optional)'], ['IMAP', 'Phase 4']] },
        ].map(group => (
          <div key={group.title} className="card" style={{ padding: '16px 20px' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 12 }}>{group.title}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {group.items.map(([k, v]) => (
                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                  <span style={{ color: 'var(--text-secondary)', fontFamily: ['Endpoint', 'DB', 'ID'].includes(k) ? 'monospace' : 'inherit', fontSize: ['Endpoint', 'ID'].includes(k) ? '0.73rem' : 'inherit' }}>{v}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* IMAP Connector Card */}
      <div className="card" style={{ padding: '20px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          <Server size={16} color="var(--accent)" />
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>IMAP Connector</div>
          <span style={{ fontSize: '0.62rem', fontWeight: 700, padding: '2px 8px', borderRadius: 100, background: 'rgba(255,165,2,0.12)', color: '#ffa502', border: '1px solid rgba(255,165,2,0.3)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Phase 4</span>
        </div>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 16 }}>Connect a mailbox to automatically ingest and analyze incoming emails in real-time.</p>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: 10, alignItems: 'flex-end' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase' }}>IMAP Host</label>
            <input value={imapHost} onChange={e => setImapHost(e.target.value)}
              placeholder="imap.gmail.com" className="input" style={{ fontSize: '0.82rem' }} />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase' }}>Username</label>
            <input value={imapUser} onChange={e => setImapUser(e.target.value)}
              placeholder="analyst@company.com" className="input" style={{ fontSize: '0.82rem' }} />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase' }}>App Password</label>
            <input type="password" value={imapPass} onChange={e => setImapPass(e.target.value)}
              placeholder="•••••••••••••" className="input" style={{ fontSize: '0.82rem' }} />
          </div>
          <button onClick={() => toast.push('IMAP connector is coming in Phase 4 — stay tuned!', 'info')}
            style={{ padding: '9px 18px', borderRadius: 8, background: 'var(--accent-dim)', border: '1px solid var(--accent)', color: 'var(--accent)', fontWeight: 600, fontSize: '0.82rem', cursor: 'pointer', whiteSpace: 'nowrap' }}>
            Connect
          </button>
        </div>
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

  const roleColor = ROLE_COLORS[user.role] || 'var(--accent)'

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-logo">
          <div className="logo-icon"><Shield size={16} color="#fff" /></div>
          EmailForensics
        </div>
        <span className="topbar-badge">Defensive Only</span>
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
          <span style={{ fontSize: '0.65rem', fontWeight: 700, padding: '2px 8px', borderRadius: 100, background: `${roleColor}22`, color: roleColor, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            {user.role}
          </span>
        </div>
      </header>

      <Sidebar active={activePage} setActive={handlePageChange} onLogout={handleLogout} />

      <main className="main-content">
        {renderPage()}
      </main>
    </div>
  )
}
