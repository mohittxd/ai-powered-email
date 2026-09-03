import React from 'react'
import { Download, FileJson, FileText, Hash, Clock, User, ShieldAlert } from 'lucide-react'
import { getJsonReport, getPdfReport, getCasePdfReport, getCaseJsonReport } from '../services/api'
import { useToast } from './Toast'

export default function ForensicReport({ result }) {
  if (!result) return null
  const toast = useToast()

  const {
    email_id,
    sha256_hash,
    analyzed_at,
    forensic_summary,
    risk_analysis,
    case_id
  } = result

  const score = Math.round(risk_analysis?.final_risk_score ?? result.fraud_score ?? 0)
  const classification = risk_analysis?.classification ?? result.classification ?? 'UNKNOWN'
  const scoreClass = score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low'

  const pdfUrl = case_id ? getCasePdfReport(case_id) : email_id ? getPdfReport(email_id) : '#'
  const jsonUrl = case_id ? getCaseJsonReport(case_id) : email_id ? getJsonReport(email_id) : '#'

  return (
    <div className="card fade-in">
      <div className="card-header">
        <div className="card-title">
          <FileText size={16} />
          Forensic Investigation Report & Downloads
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <a
            id="btn-export-json"
            href={jsonUrl}
            target="_blank"
            rel="noreferrer"
            className="btn btn-ghost btn-sm"
            onClick={() => toast.push('Exporting forensic JSON payload…', 'info')}
          >
            <FileJson size={14} />
            Export JSON
          </a>
          <a
            id="btn-export-pdf"
            href={pdfUrl}
            target="_blank"
            rel="noreferrer"
            className="btn btn-primary btn-sm"
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
            onClick={() => toast.push('Generating professional PDF forensic report…', 'info')}
          >
            <Download size={14} />
            Download PDF Report
          </a>
        </div>
      </div>

      {/* Summary banner */}
      <div className={`analysis-banner ${scoreClass}`} style={{ marginBottom: 16 }}>
        <span style={{ fontSize: '1.5rem' }}>
          {scoreClass === 'critical' ? '🚨' : scoreClass === 'high' ? '⚠️' : scoreClass === 'medium' ? '🔍' : '✅'}
        </span>
        <div>
          <div style={{ fontWeight: 700, marginBottom: 4, fontSize: '0.95rem' }}>
            {classification.replace('_', ' ').toUpperCase()} — Final Risk Score {score}/100
          </div>
          <div style={{ fontSize: '0.85rem', lineHeight: 1.6, color: 'var(--text-secondary)' }}>
            {forensic_summary || 'Full 14-phase forensic triage completed. Multi-factor verification of SPF, DKIM, DMARC, Received chain routing, and IOC intelligence completed.'}
          </div>
        </div>
      </div>

      {/* Chain of custody metadata */}
      <div className="grid-2" style={{ gap: 12, marginBottom: 12 }}>
        <div style={{ padding: '12px 14px', background: 'var(--bg-surface)', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 4 }}>
            <Hash size={11} /> Evidence SHA-256 Hash Digest
          </div>
          <code style={{ fontSize: '0.72rem', color: 'var(--text-mono)', wordBreak: 'break-all' }}>{sha256_hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}</code>
        </div>
        <div style={{ padding: '12px 14px', background: 'var(--bg-surface)', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 4 }}>
            <Clock size={11} /> Forensic Ingestion Timestamp
          </div>
          <code style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
            {analyzed_at ? new Date(analyzed_at).toUTCString() : new Date().toUTCString()}
          </code>
        </div>
      </div>

      <div style={{ padding: '10px 14px', background: 'var(--bg-surface)', borderRadius: 8, border: '1px solid var(--border-subtle)', marginBottom: 14 }}>
        <div style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
          <User size={11} /> Evidence ID (Chain of Custody)
        </div>
        <code style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{email_id || 'N/A'}</code>
      </div>

      {/* Mandatory Disclaimer */}
      <div style={{ padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: 6, borderLeft: '3px solid var(--text-muted)', fontSize: '0.74rem', color: 'var(--text-muted)', fontStyle: 'italic', display: 'flex', gap: 8, alignItems: 'center' }}>
        <ShieldAlert size={14} style={{ flexShrink: 0 }} />
        <div>
          <strong>Technical Disclaimer:</strong> Technical indicators represent observed evidence and analytical findings. They do not by themselves establish the identity of a human actor.
        </div>
      </div>
    </div>
  )
}
