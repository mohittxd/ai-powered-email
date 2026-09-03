import { createContext, useContext, useState, useCallback, useEffect } from 'react'
import { CheckCircle, XCircle, AlertTriangle, Info, X } from 'lucide-react'

const ToastContext = createContext(null)

const ICONS = {
  success: <CheckCircle size={16} />,
  error:   <XCircle size={16} />,
  warning: <AlertTriangle size={16} />,
  info:    <Info size={16} />,
}

const COLORS = {
  success: { bg: 'rgba(46,213,115,0.12)', border: 'rgba(46,213,115,0.3)',  color: '#2ed573' },
  error:   { bg: 'rgba(255,71,87,0.12)',  border: 'rgba(255,71,87,0.3)',   color: '#ff4757' },
  warning: { bg: 'rgba(255,165,2,0.12)',  border: 'rgba(255,165,2,0.3)',   color: '#ffa502' },
  info:    { bg: 'rgba(79,195,247,0.12)', border: 'rgba(79,195,247,0.3)',  color: '#4fc3f7' },
}

let _id = 0

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const push = useCallback((message, type = 'info', duration = 4000) => {
    const id = ++_id
    setToasts(t => [...t, { id, message, type, visible: true }])
    setTimeout(() => {
      setToasts(t => t.map(x => x.id === id ? { ...x, visible: false } : x))
      setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 350)
    }, duration)
    return id
  }, [])

  const dismiss = useCallback((id) => {
    setToasts(t => t.map(x => x.id === id ? { ...x, visible: false } : x))
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 350)
  }, [])

  return (
    <ToastContext.Provider value={{ push, dismiss }}>
      {children}
      <div style={{
        position: 'fixed', bottom: 24, right: 24,
        display: 'flex', flexDirection: 'column', gap: 10,
        zIndex: 9999, pointerEvents: 'none',
      }}>
        {toasts.map(t => {
          const c = COLORS[t.type] || COLORS.info
          return (
            <div key={t.id} style={{
              display: 'flex', alignItems: 'flex-start', gap: 12,
              padding: '12px 16px', borderRadius: 12,
              background: c.bg, border: `1px solid ${c.border}`,
              backdropFilter: 'blur(12px)',
              boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
              maxWidth: 360, minWidth: 260,
              pointerEvents: 'auto',
              transform: t.visible ? 'translateX(0)' : 'translateX(120%)',
              opacity: t.visible ? 1 : 0,
              transition: 'transform 0.3s cubic-bezier(0.4,0,0.2,1), opacity 0.3s ease',
            }}>
              <span style={{ color: c.color, flexShrink: 0, marginTop: 1 }}>
                {ICONS[t.type]}
              </span>
              <span style={{ fontSize: '0.85rem', color: 'var(--text-primary)', flex: 1, lineHeight: 1.5 }}>
                {t.message}
              </span>
              <button onClick={() => dismiss(t.id)} style={{
                background: 'none', border: 'none', color: 'var(--text-muted)',
                cursor: 'pointer', padding: 2, flexShrink: 0,
              }}>
                <X size={13} />
              </button>
            </div>
          )
        })}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}
