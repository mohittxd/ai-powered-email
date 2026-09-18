import { useState, useRef } from 'react'
import { Upload, FileText, X, Zap, AlertCircle, Info } from 'lucide-react'

export default function EmailUpload({ onAnalyze, loading }) {
  const [dragging, setDragging] = useState(false)
  const [file, setFile] = useState(null)
  const [mode, setMode] = useState('file') // 'file' | 'body'
  const [bodyText, setBodyText] = useState('')
  const fileRef = useRef()

  const handleFile = (f) => {
    if (!f) return
    const allowedExtensions = ['.eml', '.msg']
    const extension = f.name.slice(f.name.lastIndexOf('.')).toLowerCase()
    if (!allowedExtensions.includes(extension)) {
      alert('Please upload a valid .eml or .msg file')
      return
    }
    setFile(f)
  }

  const onDrop = (e) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) handleFile(f)
  }

  const onSubmit = () => {
    if (mode === 'file' && file) onAnalyze(file, null)
    else if (mode === 'body' && bodyText.trim()) onAnalyze(null, bodyText.trim())
  }

  const canSubmit = (mode === 'file' && file) || (mode === 'body' && bodyText.trim().length > 10)

  return (
    <div className="card">
      <div className="card-header" style={{ marginBottom: 10 }}>
        <div className="card-title">
          <Upload size={14} />
          Evidence Upload
        </div>
        <div className="tabs">
          <button className={`tab ${mode === 'file' ? 'active' : ''}`} onClick={() => setMode('file')}>
            Upload .EML
          </button>
          <button className={`tab ${mode === 'body' ? 'active' : ''}`} onClick={() => setMode('body')}>
            Paste Email
          </button>
        </div>
      </div>

      {/* Info banner explaining the two modes */}
      <div style={{
        display: 'flex', alignItems: 'flex-start', gap: 8,
        padding: '8px 12px', marginBottom: 12,
        background: 'var(--accent-dim)', border: '1px solid rgba(79,195,247,0.15)',
        borderRadius: 'var(--radius-sm)', fontSize: '0.72rem', color: 'var(--text-secondary)',
        lineHeight: 1.5,
      }}>
        <Info size={14} color="var(--accent)" style={{ flexShrink: 0, marginTop: 1 }} />
        <div>
          {mode === 'file' ? (
            <span><strong>Upload .EML</strong> — Provides full email evidence including headers, authentication results (SPF/DKIM/DMARC), network trace, and geolocation analysis.</span>
          ) : (
            <span><strong>Paste Email</strong> — Body-based analysis only. Headers, sender IP, authentication, and network evidence are unavailable when pasting raw text. The system will not fabricate missing forensic fields.</span>
          )}
        </div>
      </div>

      {mode === 'file' ? (
        <div
          className={`upload-zone ${dragging ? 'dragging' : ''}`}
          onClick={() => !file && fileRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
        >
          <input
            ref={fileRef}
            type="file"
            accept=".eml,.msg,message/rfc822,application/vnd.ms-outlook"
            style={{ display: 'none' }}
            onChange={e => handleFile(e.target.files?.[0])} />

          {file ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 48, height: 48, borderRadius: 12, background: 'var(--accent-dim)', border: '1px solid var(--border-accent)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <FileText size={22} color="var(--accent)" />
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>{file.name}</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 2 }}>{(file.size / 1024).toFixed(1)} KB</div>
              </div>
              <button className="btn btn-ghost btn-sm" onClick={e => { e.stopPropagation(); setFile(null) }}>
                <X size={13} /> Clear
              </button>
            </div>
          ) : (
            <>
              <span className="upload-icon">📧</span>
              <div className="upload-title">Drop .eml or .msg file here</div>
              <div className="upload-sub">or click to browse — max 10 MB</div>
            </>
          )}
        </div>
      ) : (
        <div>
          <textarea
            className="input"
            rows={8}
            placeholder={`Paste email body here...\n\nExample:\nSubject: Your account has been suspended\nFrom: security@example.com\n\nDear user, your account has been compromised...`}
            value={bodyText}
            onChange={e => setBodyText(e.target.value)}
            style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.78rem' }}
          />
          <div style={{ marginTop: 6, fontSize: '0.68rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <AlertCircle size={11} />
            Pasted content is sanitized before processing. HTML tags are stripped. No scripts or active content are executed.
          </div>
        </div>
      )}

      <div style={{ marginTop: 14, display: 'flex', gap: 10, alignItems: 'center' }}>
        <button
          className="btn btn-primary"
          disabled={!canSubmit || loading}
          onClick={onSubmit}
          style={{ opacity: (!canSubmit || loading) ? 0.5 : 1, cursor: (!canSubmit || loading) ? 'not-allowed' : 'pointer' }}
        >
          {loading ? (
            <><div className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Analyzing...</>
          ) : (
            <><Zap size={14} /> Analyze Evidence</>
          )}
        </button>

        {loading && (
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <AlertCircle size={13} /> Running forensic pipeline...
          </div>
        )}
      </div>
    </div>
  )
}
