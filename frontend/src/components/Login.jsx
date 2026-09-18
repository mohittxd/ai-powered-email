import { useState } from 'react'
import { Eye, EyeOff, Shield } from 'lucide-react'
import api from '../services/api'

export default function Login({ onLogin }) {
  const [isRegistering, setIsRegistering] = useState(false)
  const [googleLoading, setGoogleLoading] = useState(false)
  const [passwordLoading, setPasswordLoading] = useState(false)
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [fieldError, setFieldError] = useState('')

  const getErrorMessage = (err, fallback) =>
    err.response?.data?.detail || err.response?.data?.error || fallback
  const [error, setError] = useState('')

  const continueWithGoogle = async () => {
    setGoogleLoading(true)
    try {
      const { data } = await api.get('/auth/google')
      window.location.assign(data.authorization_url)
    } catch (err) {
      console.error('Google authentication unavailable', err)
      setError(getErrorMessage(err, 'Google authentication is unavailable.'))
      setGoogleLoading(false)
    }
  }

  const loginWithPassword = async (event) => {
    event.preventDefault()
    setPasswordLoading(true)
    setError('')
    setFieldError('')
    if (!email.trim() || !password) {
      setFieldError('Enter both your email address and password.')
      setPasswordLoading(false)
      return
    }
    try {
      const data = await api.post('/auth/login', { email, password }).then(res => res.data)
      localStorage.setItem('ef_token', data.access_token)
      onLogin(data.user)
    } catch (err) {
      setError(getErrorMessage(err, 'Unable to sign in. Please check your credentials and try again.'))
    } finally {
      setPasswordLoading(false)
    }
  }

  const submitRegistration = async (event) => {
    event.preventDefault()
    setPasswordLoading(true)
    setError('')
    setFieldError('')
    if (!name.trim() || !email.trim() || !password) {
      setFieldError('Enter your name, email address, and password.')
      setPasswordLoading(false)
      return
    }
    if (password.length < 8) {
      setFieldError('Password must be at least 8 characters.')
      setPasswordLoading(false)
      return
    }
    if (password !== confirmPassword) {
      setFieldError('Passwords do not match.')
      setPasswordLoading(false)
      return
    }
    try {
      const data = await api.post('/auth/register', { name, email, password }).then(res => res.data)
      localStorage.setItem('ef_token', data.access_token)
      onLogin(data.user)
    } catch (err) {
      setError(getErrorMessage(err, 'Unable to create your account.'))
    } finally {
      setPasswordLoading(false)
    }
  }

  const switchMode = (registering) => {
    setIsRegistering(registering)
    setError('')
    setFieldError('')
  }

  const clearFieldErrors = () => {
    setFieldError('')
    setError('')
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg-primary)',
      padding: 20,
    }}>
      <div style={{ width: '100%', maxWidth: 760 }}>
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 56,
            height: 56,
            borderRadius: 16,
            background: 'linear-gradient(135deg, #00e676, #00b0ff)',
            marginBottom: 16,
          }}>
            <Shield size={28} color="#000" />
          </div>
          <h1 style={{ margin: 0, color: 'var(--text-primary)', fontSize: '1.6rem' }}>
            Forensic AI
          </h1>
          <p style={{ margin: '8px 0 0', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            Email evidence and forensic intelligence
          </p>
        </div>

        <div className="card login-card" style={{ padding: 28 }}>
          <div className="login-options login-options-vertical">
            <form onSubmit={isRegistering ? submitRegistration : loginWithPassword}>
              <h2 className="login-option-title">{isRegistering ? 'Create your account' : 'Sign in with Email'}</h2>
              {isRegistering && (
                <>
                  <label className="login-label" htmlFor="register-name">Full name</label>
                  <input id="register-name" className="login-input" type="text" value={name}
                    onChange={(event) => { setName(event.target.value); clearFieldErrors() }}
                    placeholder="Your name" autoComplete="name" required />
                </>
              )}
              <label className="login-label" htmlFor="login-email">Email address</label>
              <input id="login-email" className="login-input" type="email" value={email}
                onChange={(event) => { setEmail(event.target.value); clearFieldErrors() }} placeholder="you@company.com"
                autoComplete="email" required />
              <label className="login-label" htmlFor="login-password">Password</label>
              <div className="password-field">
                <input id="login-password" className="login-input" type={showPassword ? 'text' : 'password'}
                  value={password} onChange={(event) => { setPassword(event.target.value); clearFieldErrors() }}
                  placeholder="Enter your password" autoComplete={isRegistering ? 'new-password' : 'current-password'} required />
                <button type="button" className="password-toggle" onClick={() => setShowPassword(value => !value)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}>
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              {isRegistering && (
                <>
                  <label className="login-label" htmlFor="register-confirm-password">Confirm password</label>
                  <input id="register-confirm-password" className="login-input" type={showPassword ? 'text' : 'password'}
                    value={confirmPassword} onChange={(event) => { setConfirmPassword(event.target.value); clearFieldErrors() }}
                    placeholder="Re-enter your password" autoComplete="new-password" required />
                </>
              )}
              {(fieldError || error) && <p className="login-error" role="alert">{fieldError || error}</p>}
              <button type="submit" disabled={passwordLoading || googleLoading} className="login-submit">
                {passwordLoading ? (isRegistering ? 'Creating account…' : 'Signing in…') : (isRegistering ? 'Create account' : 'Sign in')}
              </button>
            </form>
            {!isRegistering && (
              <button type="button" className="login-link" onClick={() => switchMode(true)}>
                Create account
              </button>
            )}
            <div className="login-divider" aria-hidden="true"><span>OR</span></div>
            <div className="google-option">
              <h2 className="login-option-title">Continue with Google</h2>
              <p className="login-option-copy">Use your verified Google identity. Gmail mailbox access is requested separately.</p>
              <button type="button" onClick={continueWithGoogle} disabled={googleLoading || passwordLoading} className="google-button">
                {googleLoading ? 'Redirecting…' : 'Continue with Google'}
              </button>
            </div>
            {isRegistering && (
              <p className="login-switch">
                Already registered?
                {' '}
                <button type="button" className="login-link login-switch-button" onClick={() => switchMode(false)}>
                  Sign in
                </button>
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
