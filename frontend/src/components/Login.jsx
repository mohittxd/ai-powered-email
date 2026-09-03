import { useState, useEffect } from 'react'
import { Shield, Eye, EyeOff, AlertCircle } from 'lucide-react'
import api from '../services/api'

const DEMO_ACCOUNTS = [
  { email: 'admin@forensics.local',       password: 'admin123',   role: 'Admin',        color: '#f44336' },
  { email: 'analyst@forensics.local',     password: 'analyst123', role: 'Analyst',      color: 'var(--accent)' },
  { email: 'investigator@forensics.local',password: 'ir2026',     role: 'Investigator', color: '#ff9800' },
]

export default function Login({ onLogin }) {
  const [email, setEmail] = useState('analyst@forensics.local')
  const [password, setPassword] = useState('analyst123')
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [particles] = useState(() =>
    Array.from({ length: 18 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: Math.random() * 3 + 1,
      dur: Math.random() * 8 + 6,
      delay: Math.random() * 4,
    }))
  )

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const res = await api.post('/auth/login', { email, password })
      const { access_token, user } = res.data
      localStorage.setItem('ef_token', access_token)
      localStorage.setItem('ef_user', JSON.stringify(user))
      onLogin(user)
    } catch (err) {
      setError(err.response?.data?.detail || 'Invalid credentials')
    } finally {
      setLoading(false)
    }
  }

  const fillDemo = (account) => {
    setEmail(account.email)
    setPassword(account.password)
    setError(null)
  }

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--bg-primary)', position: 'relative', overflow: 'hidden',
    }}>
      {/* Animated background particles */}
      {particles.map(p => (
        <div key={p.id} style={{
          position: 'absolute', left: `${p.x}%`, top: `${p.y}%`,
          width: p.size, height: p.size, borderRadius: '50%',
          background: 'var(--accent)', opacity: 0.15,
          animation: `float ${p.dur}s ease-in-out ${p.delay}s infinite alternate`,
        }} />
      ))}

      {/* Glow blobs */}
      <div style={{ position: 'absolute', top: '10%', left: '5%', width: 400, height: 400, borderRadius: '50%', background: 'radial-gradient(circle, rgba(0,230,118,0.06) 0%, transparent 70%)', pointerEvents: 'none' }} />
      <div style={{ position: 'absolute', bottom: '5%', right: '8%', width: 350, height: 350, borderRadius: '50%', background: 'radial-gradient(circle, rgba(244,67,54,0.05) 0%, transparent 70%)', pointerEvents: 'none' }} />

      <div style={{
        width: '100%', maxWidth: 420, padding: '0 20px', position: 'relative', zIndex: 1,
      }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            width: 56, height: 56, borderRadius: 16,
            background: 'linear-gradient(135deg, #00e676, #00b0ff)',
            marginBottom: 16, boxShadow: '0 0 30px rgba(0,230,118,0.3)',
          }}>
            <Shield size={28} color="#000" />
          </div>
          <h1 style={{ margin: 0, fontSize: '1.6rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
            EmailForensics
          </h1>
          <p style={{ margin: '6px 0 0', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            AI-Powered Threat Intelligence Platform
          </p>
        </div>

        {/* Card */}
        <div style={{
          background: 'var(--surface-1)',
          border: '1px solid var(--border)',
          borderRadius: 16,
          padding: '28px 28px 24px',
          backdropFilter: 'blur(20px)',
          boxShadow: '0 20px 60px rgba(0,0,0,0.4), 0 0 0 1px rgba(0,230,118,0.08)',
        }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 20, textAlign: 'center', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
            🔒 Authorized Personnel Only
          </div>

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Email Address
              </label>
              <input
                id="login-email"
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                autoFocus
                style={{
                  width: '100%', padding: '11px 14px', borderRadius: 10, boxSizing: 'border-box',
                  background: 'var(--surface-2)', border: '1px solid var(--border)',
                  color: 'var(--text-primary)', fontSize: '0.88rem', outline: 'none',
                  transition: 'border-color 0.2s',
                }}
                onFocus={e => e.target.style.borderColor = 'var(--accent)'}
                onBlur={e => e.target.style.borderColor = 'var(--border)'}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Password
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  id="login-password"
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  style={{
                    width: '100%', padding: '11px 42px 11px 14px', borderRadius: 10, boxSizing: 'border-box',
                    background: 'var(--surface-2)', border: '1px solid var(--border)',
                    color: 'var(--text-primary)', fontSize: '0.88rem', outline: 'none',
                    transition: 'border-color 0.2s',
                  }}
                  onFocus={e => e.target.style.borderColor = 'var(--accent)'}
                  onBlur={e => e.target.style.borderColor = 'var(--border)'}
                />
                <button type="button" onClick={() => setShowPw(v => !v)}
                  style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                  {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            {error && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 14px', borderRadius: 8, background: 'rgba(244,67,54,0.12)', border: '1px solid rgba(244,67,54,0.3)', color: 'var(--critical)', fontSize: '0.82rem' }}>
                <AlertCircle size={14} /> {error}
              </div>
            )}

            <button
              id="login-submit"
              type="submit"
              disabled={loading}
              style={{
                marginTop: 4, padding: '12px', borderRadius: 10, border: 'none',
                background: loading ? 'var(--surface-2)' : 'linear-gradient(135deg, #00e676, #00b0ff)',
                color: loading ? 'var(--text-muted)' : '#000',
                fontWeight: 800, fontSize: '0.9rem', cursor: loading ? 'not-allowed' : 'pointer',
                transition: 'all 0.2s', letterSpacing: '0.03em',
                boxShadow: loading ? 'none' : '0 4px 20px rgba(0,230,118,0.3)',
              }}
            >
              {loading ? 'Authenticating…' : '→ Sign In'}
            </button>
          </form>
        </div>

        {/* Demo accounts */}
        <div style={{ marginTop: 20 }}>
          <div style={{ textAlign: 'center', fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 12, letterSpacing: '0.06em', textTransform: 'uppercase' }}>
            Demo Accounts — click to fill
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {DEMO_ACCOUNTS.map(acc => (
              <button key={acc.email} onClick={() => fillDemo(acc)}
                style={{
                  padding: '10px 14px', borderRadius: 10, background: 'var(--surface-1)',
                  border: `1px solid var(--border)`, cursor: 'pointer',
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  transition: 'all 0.2s',
                }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = acc.color; e.currentTarget.style.background = 'var(--surface-2)' }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.background = 'var(--surface-1)' }}
              >
                <div style={{ textAlign: 'left' }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-primary)', fontWeight: 600 }}>{acc.email}</div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 2 }}>pw: {acc.password}</div>
                </div>
                <span style={{ fontSize: '0.7rem', fontWeight: 700, padding: '2px 10px', borderRadius: 100, background: `${acc.color}22`, color: acc.color, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  {acc.role}
                </span>
              </button>
            ))}
          </div>
        </div>

        <div style={{ textAlign: 'center', marginTop: 20, fontSize: '0.68rem', color: 'var(--text-muted)' }}>
          EmailForensics v3.0.0 · Defensive Use Only · SOC / Legal / IR
        </div>
      </div>

      <style>{`
        @keyframes float {
          from { transform: translateY(0px) scale(1); opacity: 0.12; }
          to   { transform: translateY(-20px) scale(1.3); opacity: 0.22; }
        }
      `}</style>
    </div>
  )
}
