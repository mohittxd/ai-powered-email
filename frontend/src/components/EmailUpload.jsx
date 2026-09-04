import { useState, useRef } from 'react'
import { Upload, FileText, X, Zap, AlertCircle } from 'lucide-react'

export default function EmailUpload({ onAnalyze, loading }) {
  const [dragging, setDragging] = useState(false)
  const [file, setFile] = useState(null)
  const [mode, setMode] = useState('file') // 'file' | 'paste'
  const [rawText, setRawText] = useState('')
  const fileRef = useRef()

  const handleFile = (f) => {
    if (!f) return
   const allowedExtensions = ['.eml', '.msg']

const extension = f.name
  .slice(f.name.lastIndexOf('.'))
  .toLowerCase()

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
    else if (mode === 'paste' && rawText.trim()) onAnalyze(null, rawText.trim())
  }

  const canSubmit = (mode === 'file' && file) || (mode === 'paste' && rawText.trim().length > 10)

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <Upload size={14} />
          Evidence Upload
        </div>
        <div className="tabs">
          <button className={`tab ${mode === 'file' ? 'active' : ''}`} onClick={() => setMode('file')}>
            .EML File
          </button>
          <button className={`tab ${mode === 'paste' ? 'active' : ''}`} onClick={() => setMode('paste')}>
            Paste Headers
          </button>
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
              <div className="upload-sub">or click to browse — .eml / .msg — max 10 MB</div>
            </>
          )}
        </div>
      ) : (
        <textarea className="input" rows={7} placeholder="Paste raw email headers or full .eml content here..."
          value={rawText} onChange={e => setRawText(e.target.value)}
          style={{ marginTop: 4 }} />
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
