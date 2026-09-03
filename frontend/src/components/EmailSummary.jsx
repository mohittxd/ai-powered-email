import React, { useState } from 'react'
import { Mail, Eye, Code, ArrowRightLeft } from 'lucide-react'

export default function EmailSummary({ email }) {
  const [showBody, setShowBody] = useState(false)

  if (!email) return (
    <div className="card fade-in">
      <div className="card-header"><div className="card-title"><Mail size={16} /> Email Details</div></div>
      <div className="empty-state" style={{ padding: 20 }}>
        <div className="empty-state-sub">Email metadata unavailable.</div>
      </div>
    </div>
  )

  const hasReplyToMismatch = email.reply_to && email.from && 
    email.reply_to.toLowerCase().split('@')[1] !== email.from.toLowerCase().split('@')[1]

  return (
    <div className="card fade-in" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div className="card-header">
        <div className="card-title">
          <Mail size={16} />
          Email Envelope Details
        </div>
        <button 
          className="btn btn-ghost btn-sm" 
          onClick={() => setShowBody(!showBody)}
          style={{ fontSize: '0.72rem' }}
        >
          {showBody ? <Code size={12} /> : <Eye size={12} />}
          {showBody ? 'Hide Body' : 'View Body Content'}
        </button>
      </div>

      {!showBody ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <div className="kv-row">
            <div className="kv-label">Subject</div>
            <div className="kv-value" style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.9rem' }}>
              {email.subject || '(No Subject)'}
            </div>
          </div>
          <div className="kv-row">
            <div className="kv-label">From</div>
            <div className="kv-value">
              {email.from_name ? <strong style={{ color: 'var(--text-primary)' }}>"{email.from_name}" </strong> : null}
              <span className="mono" style={{ color: 'var(--accent)' }}>&lt;{email.from || 'Unknown'}&gt;</span>
            </div>
          </div>
          <div className="kv-row">
            <div className="kv-label">To</div>
            <div className="kv-value mono" style={{ fontSize: '0.78rem' }}>{email.to || 'Unknown'}</div>
          </div>
          {email.cc && (
            <div className="kv-row">
              <div className="kv-label">CC</div>
              <div className="kv-value mono" style={{ fontSize: '0.78rem' }}>{email.cc}</div>
            </div>
          )}
          <div className="kv-row">
            <div className="kv-label">Reply-To</div>
            <div className="kv-value">
              {email.reply_to ? (
                <span className="mono" style={{ color: hasReplyToMismatch ? 'var(--critical)' : 'var(--text-secondary)' }}>
                  {email.reply_to}
                  {hasReplyToMismatch && (
                    <span className="badge badge-critical" style={{ marginLeft: 8, fontSize: '0.65rem' }}>
                      <ArrowRightLeft size={10} /> Domain Mismatch
                    </span>
                  )}
                </span>
              ) : (
                <span style={{ color: 'var(--text-muted)' }}>Not specified (same as From)</span>
              )}
            </div>
          </div>
          <div className="kv-row">
            <div className="kv-label">Date Sent</div>
            <div className="kv-value">{email.date || 'Unavailable'}</div>
          </div>
          <div className="kv-row">
            <div className="kv-label">Message-ID</div>
            <div className="kv-value mono" style={{ fontSize: '0.73rem', wordBreak: 'break-all' }}>
              {email.message_id || 'Unavailable'}
            </div>
          </div>
          {email.return_path && (
            <div className="kv-row">
              <div className="kv-label">Return-Path</div>
              <div className="kv-value mono" style={{ fontSize: '0.73rem' }}>{email.return_path}</div>
            </div>
          )}
        </div>
      ) : (
        <div style={{ marginTop: 8, flex: 1, display: 'flex', flexDirection: 'column' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 6 }}>
            Raw Body Text Preview ({email.content_type || 'text/plain'})
          </div>
          <pre style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 6,
            padding: 12,
            fontSize: '0.78rem',
            fontFamily: 'JetBrains Mono, monospace',
            color: 'var(--text-secondary)',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            maxHeight: 220,
            overflowY: 'auto'
          }}>
            {email.body_text || email.body_html || '(Body content is empty or unparseable)'}
          </pre>
        </div>
      )}
    </div>
  )
}
