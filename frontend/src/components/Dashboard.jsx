import { useState, useEffect } from 'react'
import { analyzeEmail, getEmails, getEmail, analyzeExistingEmail } from '../services/api'
import EmailUpload from './EmailUpload'
import FraudScore from './FraudScore'
import RiskReasons from './RiskReasons'
import EmailSummary from './EmailSummary'
import AuthenticationStatus from './AuthenticationStatus'
import HeaderTrace from './HeaderTrace'
import InfrastructureMap from './InfrastructureMap'
import IOCList from './IOCList'
import AIAnalysisSection from './AIAnalysisSection'
import EvidenceInfo from './EvidenceInfo'
import ForensicReport from './ForensicReport'
import InvestigationTimeline from './InvestigationTimeline'
import {
  ShieldAlert,
  AlertTriangle,
  Globe,
  ShieldCheck,
  Zap,
  Layers,
  FileCode,
  FileText,
  Route,
  MapPin,
  Cpu,
  Mail,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Clock,
  Upload
} from 'lucide-react'

import { useToast } from './Toast'

function SkeletonCard() {
  return (
    <div className="stat-card" style={{ gap: 8 }}>
      <div className="skeleton" style={{ height: 12, width: '60%', borderRadius: 6 }} />
      <div className="skeleton" style={{ height: 28, width: '40%', borderRadius: 6 }} />
    </div>
  )
}

function EmailDetailModal({ emailDetails, onClose }) {
  const [viewMode, setViewMode] = useState('text')
  const hasHtml = !!(emailDetails.body_html && emailDetails.body_html.trim())
  const hasText = !!(emailDetails.body_text && emailDetails.body_text.trim())

  useEffect(() => {
    if (hasHtml && !hasText) setViewMode('html')
  }, [hasHtml, hasText])

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
    }} onClick={onClose}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border-accent)',
        borderRadius: 14, width: '90vw', maxWidth: 800, maxHeight: '85vh',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
        boxShadow: '0 8px 48px rgba(0,0,0,0.6)',
      }} onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
              Email Message
            </div>
            <h3 style={{ margin: 0, fontSize: '1.1rem', color: 'var(--text-primary)', lineHeight: 1.3 }}>
              {emailDetails.subject || '(No subject)'}
            </h3>
          </div>
          <button onClick={onClose} style={{
            background: 'transparent', border: '1px solid var(--border-subtle)',
            color: 'var(--text-muted)', borderRadius: 6, padding: '4px 10px',
            cursor: 'pointer', fontSize: '0.8rem', flexShrink: 0, marginLeft: 12,
          }}>Close</button>
        </div>

        {/* Metadata */}
        <div style={{ padding: '12px 20px', borderBottom: '1px solid var(--border-subtle)', fontSize: '0.82rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '80px 1fr', gap: '6px 12px', alignItems: 'baseline' }}>
            <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>From</span>
            <span style={{ color: 'var(--text-primary)' }}>
              {emailDetails.from_display_name ? `${emailDetails.from_display_name} <${emailDetails.from_address}>` : emailDetails.from_address || 'Unknown'}
            </span>
            {emailDetails.reply_to && (
              <>
                <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Reply-To</span>
                <span style={{ color: 'var(--text-secondary)' }}>{emailDetails.reply_to}</span>
              </>
            )}
            <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Date</span>
            <span style={{ color: 'var(--text-secondary)' }}>
              {emailDetails.date_sent ? new Date(emailDetails.date_sent).toLocaleString() : 'Unknown'}
            </span>
            {emailDetails.gmail_labels && emailDetails.gmail_labels.length > 0 && (
              <>
                <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Labels</span>
                <span style={{ color: 'var(--text-secondary)' }}>{emailDetails.gmail_labels.join(', ')}</span>
              </>
            )}
          </div>
        </div>

        {/* View mode toggle */}
        {hasText && hasHtml && (
          <div style={{ padding: '8px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', gap: 6 }}>
            <button className={`tab ${viewMode === 'text' ? 'active' : ''}`} onClick={() => setViewMode('text')} style={{ fontSize: '0.76rem' }}>Plain Text</button>
            <button className={`tab ${viewMode === 'html' ? 'active' : ''}`} onClick={() => setViewMode('html')} style={{ fontSize: '0.76rem' }}>HTML</button>
          </div>
        )}

        {/* Body */}
        <div style={{ flex: 1, overflow: 'auto', padding: '16px 20px' }}>
          {viewMode === 'html' && hasHtml ? (
            <div style={{
              background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)',
              borderRadius: 8, padding: 16, color: 'var(--text-primary)', fontSize: '0.88rem', lineHeight: 1.6,
            }}>
              <div
                style={{ color: 'var(--text-primary)' }}
                dangerouslySetInnerHTML={{ __html: emailDetails.body_html }}
              />
            </div>
          ) : hasText ? (
            <pre style={{
              margin: 0, padding: 16, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere',
              background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)',
              borderRadius: 8, color: 'var(--text-primary)', fontFamily: 'inherit',
              fontSize: '0.86rem', lineHeight: 1.6,
            }}>
              {emailDetails.body_text}
            </pre>
          ) : (
            <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)' }}>
              No message body available.
            </div>
          )}
        </div>

        {/* Footer with metadata */}
        <div style={{ padding: '10px 20px', borderTop: '1px solid var(--border-subtle)', display: 'flex', gap: 16, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
          {emailDetails.message_id && <span>Message-ID: {emailDetails.message_id}</span>}
          {emailDetails.sha256_hash && <span>SHA-256: {emailDetails.sha256_hash.substring(0, 16)}…</span>}
        </div>
      </div>
    </div>
  )
}

export default function Dashboard({ onAnalyzed }) {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [activeSection, setActiveSection] = useState('all')
  const toast = useToast()

  // Imported Gmail emails state
  const [emails, setEmails] = useState([])
  const [emailsLoading, setEmailsLoading] = useState(false)
  const [emailsError, setEmailsError] = useState(null)
  const [query, setQuery] = useState('')
  const [analyzingEmailId, setAnalyzingEmailId] = useState(null)
  const [readingEmailId, setReadingEmailId] = useState(null)
  const [emailDetails, setEmailDetails] = useState(null)

  const loadEmails = async (q = '') => {
    setEmailsLoading(true)
    setEmailsError(null)
    try {
      const params = { limit: 200 }
      if (q) params.q = q
      const data = await getEmails(params)
      setEmails(data.emails || [])
    } catch (err) {
      console.error('Failed to load emails', err)
      setEmailsError(err.response?.data?.detail || err.message || 'Unable to fetch emails')
    } finally {
      setEmailsLoading(false)
    }
  }

  useEffect(() => {
    loadEmails()

    const onGmailSynced = () => loadEmails()
    window.addEventListener('gmailSynced', onGmailSynced)
    return () => window.removeEventListener('gmailSynced', onGmailSynced)
  }, [])

  const handleSearch = (e) => {
    e.preventDefault()
    loadEmails(query)
  }

  const readEmail = async (email) => {
    setReadingEmailId(email.id)
    setEmailsError(null)
    try {
      setEmailDetails(await getEmail(email.id))
    } catch (err) {
      setEmailsError(err.response?.data?.detail || err.message || 'Unable to read this message.')
    } finally {
      setReadingEmailId(null)
    }
  }

  const analyzeExisting = async (email) => {
    setAnalyzingEmailId(email.id)
    setError(null)
    try {
      const data = await analyzeExistingEmail(email.id)
      setResult(data)
      onAnalyzed?.()
      setActiveSection('all')

      const score = Math.round(data.risk_analysis?.final_risk_score ?? data.risk_analysis?.risk_score ?? 0)
      const level = score >= 70 ? 'error' : score >= 25 ? 'warning' : 'success'
      toast.push(`Forensic analysis complete — Risk score: ${score}/100`, level)
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Analysis failed'
      toast.push(`Analysis failed: ${msg}`, 'error')
    } finally {
      setAnalyzingEmailId(null)
    }
  }

  const handleAnalyze = async (file, rawHeaders) => {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const user = JSON.parse(localStorage.getItem('ef_user') || 'null')
      const data = await analyzeEmail(file, rawHeaders, null, user?.id)
      setResult(data)
      onAnalyzed?.()

      const score = Math.round(data.risk_analysis?.final_risk_score ?? data.risk_analysis?.risk_score ?? 0)
      const level = score >= 70 ? 'error' : score >= 25 ? 'warning' : 'success'
      const modeNote = data.input_mode === 'pasted_body' ? ' (body-only analysis)' : ''
      toast.push(`Forensic analysis complete${modeNote} — Risk score: ${score}/100`, level)
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Analysis failed'
      setError(msg)
      toast.push(`Analysis failed: ${msg}`, 'error')
    } finally {
      setLoading(false)
    }
  }

  // Quick helper extractors for immediate display requirements
  const riskAnalysis = result?.risk_analysis || {}
  const riskScore = Math.round(riskAnalysis.final_risk_score ?? riskAnalysis.risk_score ?? 0)
  const classification = (riskAnalysis.classification || 'UNKNOWN').toUpperCase()
  const confidence = (riskAnalysis.confidence || 'LOW').toUpperCase()

  const auth = result?.authentication || {}
  const spfStatus = (auth.spf?.mta_reported || auth.spf?.status || 'UNKNOWN').toUpperCase()
  const dkimStatus = (auth.dkim?.mta_reported || auth.dkim?.status || 'UNKNOWN').toUpperCase()
  const dmarcStatus = (auth.dmarc?.mta_reported || auth.dmarc?.status || 'UNKNOWN').toUpperCase()

  const forensics = result?.header_forensics || {}
  const earliestIp = forensics.earliest_observed_public_sender_ip || 'Unavailable'

  // Prefer the origin_trace origin_hop when present, fall back to legacy ip_intelligence.geolocation
  const originTrace = result?.origin_trace || {}
  const originHop = originTrace?.origin_hop || result?.ip_intelligence?.geolocation || {}
  const originCountry = originHop.country || 'Unavailable'
  const originCity = originHop.city || 'Unavailable'
  const originIsp = originHop.isp || 'Unavailable'
  const originAsn = originHop.asn || 'Unavailable'
const buildTimelineFromResponse = (res) => {
    if (!res) return null;
    const baseTime = res.ingested_at || new Date().toISOString();
    const ev = res.evidence || {};
    const em = res.email || {};
    const authRes = res.authentication || {};
    const forensicsRes = res.header_forensics || {};
    const geoipRes = res.ip_intelligence?.geolocation || {};
    const threatRes = res.ip_intelligence?.threat_intel || {};
    const riskRes = res.risk_analysis || {};
    const iocRes = res.iocs || {};
    const chain = res.received_chain || [];

    const events = [
      {
        id: 'evt-01', step_number: 1, event_type: 'EMAIL_RECEIVED',
        title: 'Email Evidence Ingested', timestamp: em.date || baseTime,
        source: 'MTA Envelope / EML Ingestion', status: 'COMPLETED',
        summary: `Ingested message '${em.subject || 'No Subject'}' from ${em.from || 'Unknown'}`,
        relevant_evidence: { filename: ev.filename, sha256: ev.sha256, from: em.from, to: em.to, subject: em.subject, message_id: em.message_id }
      },
      {
        id: 'evt-02', step_number: 2, event_type: 'HEADER_HOP',
        title: 'Earliest Received Header Hop Identified', timestamp: baseTime,
        source: 'Received Header #1 (Earliest)', status: 'COMPLETED',
        summary: `Earliest public sender IP: ${forensicsRes.earliest_observed_public_sender_ip || 'Unavailable'}`,
        relevant_evidence: { earliest_ip: forensicsRes.earliest_observed_public_sender_ip, anomalies: forensicsRes.anomalies || [] }
      },
      {
        id: 'evt-03', step_number: 3, event_type: 'RELAY',
        title: 'MTA Relay Chain Traversal', timestamp: baseTime,
        source: 'Intermediate Received Headers', status: 'COMPLETED',
        summary: `Traversed ${chain.length} Received header hop(s)`,
        relevant_evidence: { total_hops: chain.length, hops: chain }
      },
      {
        id: 'evt-04', step_number: 4, event_type: 'ORIGIN_INFRASTRUCTURE',
        title: 'Originating Network Infrastructure Resolved', timestamp: baseTime,
        source: 'BGP / Public IP Resolution Engine', status: 'COMPLETED',
        summary: `Origin: ${geoipRes.ip || forensicsRes.earliest_observed_public_sender_ip || 'N/A'} (${geoipRes.country || 'Unknown'})`,
        relevant_evidence: { ip: geoipRes.ip, country: geoipRes.country, city: geoipRes.city, isp: geoipRes.isp, asn: geoipRes.asn }
      },
      {
        id: 'evt-05', step_number: 5, event_type: 'AUTHENTICATION_ANALYSIS',
        title: 'Email Authentication Verification (SPF / DKIM / DMARC)', timestamp: baseTime,
        source: 'DNS & Cryptographic Verification Engine',
        status: (authRes.spf?.status === 'FAIL' || authRes.dkim?.status === 'FAIL' || authRes.dmarc?.status === 'FAIL') ? 'WARNING' : 'COMPLETED',
        summary: `SPF: ${authRes.spf?.status || 'UNKNOWN'} | DKIM: ${authRes.dkim?.status || 'UNKNOWN'} | DMARC: ${authRes.dmarc?.status || 'UNKNOWN'}`,
        relevant_evidence: { spf: authRes.spf, dkim: authRes.dkim, dmarc: authRes.dmarc }
      },
      {
        id: 'evt-06', step_number: 6, event_type: 'IOC_EXTRACTION',
        title: 'Indicators of Compromise (IOC) Extracted', timestamp: baseTime,
        source: 'Lexical Parser & Body Extractor', status: 'COMPLETED',
        summary: `Extracted ${iocRes.urls?.length || 0} URL(s), ${iocRes.domains?.length || 0} domain(s), ${iocRes.ips?.length || 0} IP(s)`,
        relevant_evidence: iocRes
      },
      {
        id: 'evt-07', step_number: 7, event_type: 'GEOIP_LOOKUP',
        title: 'GeoIP Physical Location Mapping', timestamp: baseTime,
        source: 'MaxMind GeoIP2 Database', status: 'COMPLETED',
        summary: `Mapped location: ${geoipRes.city || 'N/A'}, ${geoipRes.country || 'N/A'}`,
        relevant_evidence: geoipRes
      },
      {
        id: 'evt-08', step_number: 8, event_type: 'THREAT_INTELLIGENCE',
        title: 'Threat Intelligence Reputation Query', timestamp: baseTime,
        source: 'AbuseIPDB API & Threat Feeds',
        status: threatRes.reputation === 'malicious' ? 'WARNING' : 'COMPLETED',
        summary: `Reputation: ${threatRes.reputation || 'clean'} (Abuse score: ${threatRes.abuse_score || 0}%)`,
        relevant_evidence: threatRes
      },
      {
        id: 'evt-09', step_number: 9, event_type: 'ML_ANALYSIS',
        title: 'AI/NLP Threat Feature Classification', timestamp: baseTime,
        source: 'Transformer NLP Pipeline & XGBoost Engine', status: 'COMPLETED',
        summary: `ML Score: ${riskRes.ml_score ?? 'N/A'} | Classification: ${riskRes.classification || 'LEGITIMATE'}`,
        relevant_evidence: { ml_score: riskRes.ml_score, rule_score: riskRes.rule_based_score, features: riskRes.features || [] }
      },
      {
        id: 'evt-10', step_number: 10, event_type: 'FINAL_RISK_ASSESSMENT',
        title: 'Ensemble Fraud Risk Assessment Calculated', timestamp: baseTime,
        source: 'ForensicAI Risk Engine',
        status: (riskRes.final_risk_score ?? riskRes.risk_score ?? 0) >= 50 ? 'WARNING' : 'COMPLETED',
        summary: `Final Risk Score: ${Math.round(riskRes.final_risk_score ?? riskRes.risk_score ?? 0)}/100 | Classification: ${riskRes.classification || 'LEGITIMATE'}`,
        relevant_evidence: { final_score: riskRes.final_risk_score, rule_score: riskRes.rule_based_score, ml_score: riskRes.ml_score, reasons: riskRes.reasons || [] }
      },
      {
        id: 'evt-11', step_number: 11, event_type: 'REPORT_GENERATED',
        title: 'Forensic Case Report Artifact Generated', timestamp: baseTime,
        source: 'ReportLab PDF & JSON Generator', status: 'COMPLETED',
        summary: `Generated forensic report artifact for case ID ${res.case_id || 'Standalone'}`,
        relevant_evidence: { email_id: res.email_id, case_id: res.case_id, sha256: ev.sha256 }
      }
    ];

    return { total_events: events.length, events };
  };

  const sections = [

    { id: 'all', label: 'All Sections' },
    { id: 'sec-overview', label: '1. Overview' },
    { id: 'sec-imported', label: '2. Gmail / Imported Emails' },
    { id: 'sec-upload', label: '3. Upload Evidence' },
    { id: 'sec-risk', label: '4. Risk Score' },
    { id: 'sec-email', label: '4. Email Details' },
    { id: 'sec-auth', label: '5. Authentication' },
    { id: 'sec-forensics', label: '6. Header Forensics' },
    { id: 'sec-trace', label: '7. Origin Trace' },
    { id: 'sec-map', label: '8. Geolocation Map' },
    { id: 'sec-iocs', label: '9. IOC Intelligence' },
    { id: 'sec-ai', label: '10. AI Analysis' },
    { id: 'sec-integrity', label: '11. Evidence Integrity' },
    { id: 'sec-report', label: '12. Forensic Report' },
    { id: 'sec-timeline', label: '13. Timeline' },
  ]


  const getStatusIcon = (st) => {
    if (st === 'PASS') return <CheckCircle2 size={13} color="var(--pass)" />
    if (['FAIL', 'SOFTFAIL'].includes(st)) return <XCircle size={13} color="var(--fail)" />
    return <HelpCircle size={13} color="var(--warn)" />
  }

  const getStatusBadge = (st) => {
    if (st === 'PASS') return 'badge-pass'
    if (['FAIL', 'SOFTFAIL'].includes(st)) return 'badge-fail'
    return 'badge-warn'
  }

  const isVisible = (secId) => activeSection === 'all' || activeSection === secId

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      
      {/* SIH Section Navigation Pills */}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', background: 'var(--bg-card)', padding: 8, borderRadius: 12, border: '1px solid var(--border-subtle)' }}>
        {sections.map(sec => (
          <button
            key={sec.id}
            onClick={() => setActiveSection(sec.id)}
            className={`tab ${activeSection === sec.id ? 'active' : ''}`}
            style={{ fontSize: '0.74rem', padding: '5px 11px' }}
          >
            {sec.label}
          </button>
        ))}
      </div>

      {/* 2. Imported Gmail Emails Section */}
      {isVisible('sec-imported') && (
        <section id="sec-imported">
          <div className="section-title">
            <Mail size={18} color="var(--accent)" /> Section 2: Gmail / Imported Emails
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
              <form onSubmit={handleSearch} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <input
                  placeholder="Search by sender or subject"
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  className="input"
                  style={{ padding: '8px 10px', fontSize: '0.88rem', borderRadius: 8 }}
                />
                <button className="btn" type="submit" style={{ padding: '8px 12px' }}>Search</button>
              </form>

              <button
                className="btn"
                onClick={() => loadEmails(query)}
                disabled={emailsLoading}
                style={{ padding: '8px 12px' }}
              >
                {emailsLoading ? 'Refreshing…' : 'Refresh Emails'}
              </button>
            </div>
          </div>

          <div style={{ marginTop: 12 }}>
            {emailsLoading && (
              <div className="card">
                <div style={{ padding: 12 }}>Loading imported emails…</div>
              </div>
            )}

            {emailsError && (
              <div className="card analysis-banner critical">
                <AlertTriangle /> <div style={{ marginLeft: 8 }}>Failed to load emails: {emailsError}</div>
              </div>
            )}

            {!emailsLoading && emails.length === 0 && !emailsError && (
              <div className="card">
                <div style={{ padding: 14 }}>
                  <div style={{ fontWeight: 700 }}>No imported emails found</div>
                  <div style={{ marginTop: 6, color: 'var(--text-muted)' }}>Use Settings → Gmail Integration to sync mailbox messages.</div>
                </div>
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {emails.map(email => (
                <div key={email.id} className="card" style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 12 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <div style={{ fontWeight: 700 }}>{email.from_display_name || email.from_address || 'Unknown Sender'}</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>{email.from_address}</div>
                      <div style={{ marginLeft: 'auto', color: 'var(--text-muted)' }}>{email.date_sent ? new Date(email.date_sent).toLocaleString() : 'Unknown Date'}</div>
                    </div>
                    <div style={{ marginTop: 6, fontSize: '0.95rem', color: 'var(--text-primary)' }}>{email.subject || '(No subject)'}</div>
                    <div style={{ marginTop: 8, display: 'flex', gap: 8, alignItems: 'center' }}>
                      <div className="badge" style={{ fontSize: '0.75rem' }}>Class: {email.classification || 'N/A'}</div>
                      <div className="badge" style={{ fontSize: '0.75rem' }}>Score: {typeof email.fraud_score === 'number' ? email.fraud_score : '—'}</div>
                      <div className={`badge ${getStatusBadge((email.spf_result || '').toUpperCase())}`} title={`SPF: ${email.spf_result || 'UNKNOWN'}`}>
                        SPF: {(email.spf_result || 'UNKNOWN').toUpperCase()}
                      </div>
                      <div className={`badge ${getStatusBadge((email.dkim_result || '').toUpperCase())}`} title={`DKIM: ${email.dkim_result || 'UNKNOWN'}`}>
                        DKIM: {(email.dkim_result || 'UNKNOWN').toUpperCase()}
                      </div>
                      <div className={`badge ${getStatusBadge((email.dmarc_result || '').toUpperCase())}`} title={`DMARC: ${email.dmarc_result || 'UNKNOWN'}`}>
                        DMARC: {(email.dmarc_result || 'UNKNOWN').toUpperCase()}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn" onClick={() => readEmail(email)} disabled={!!readingEmailId}>
                      {readingEmailId === email.id ? 'Opening…' : 'Read'}
                    </button>
                    <button className="btn" onClick={() => analyzeExisting(email)} disabled={!!analyzingEmailId}>
                      {analyzingEmailId === email.id ? 'Analyzing…' : 'Analyze'}
                    </button>
                    <a className="btn" href={`/api/v1/emails/${email.id}/report.json`} target="_blank" rel="noreferrer">Report</a>
                  </div>
                </div>
              ))}
            </div>
            {emailDetails && (
              <EmailDetailModal emailDetails={emailDetails} onClose={() => setEmailDetails(null)} />
            )}
          </div>
        </section>
      )}

      {/* 3. Upload Evidence Section */}
      {isVisible('sec-upload') && (
        <section id="sec-upload">
          <div className="section-title">
            <Upload size={18} color="var(--accent)" /> Section 3: Upload Evidence
          </div>
          <EmailUpload onAnalyze={handleAnalyze} loading={loading} />
        </section>
      )}

      {/* Loading Skeleton */}
      {loading && (
        <div className="grid-4 fade-in">
          <SkeletonCard /><SkeletonCard /><SkeletonCard /><SkeletonCard />
        </div>
      )}

      {/* Error Banner */}
      {error && (
        <div className="analysis-banner critical fade-in">
          <AlertTriangle size={20} />
          <div>
            <strong>Analysis Error Occurred</strong>
            <div>{error}</div>
          </div>
        </div>
      )}

      

      {/* Body-only analysis warning */}
      {result?.input_mode === 'pasted_body' && (
        <div className="analysis-banner medium fade-in">
          <AlertTriangle size={20} />
          <div>
            <strong>Body-Only Analysis</strong>
            <div>This analysis was performed on a pasted email body. Headers, sender IP, SPF/DKIM/DMARC authentication, MTA relay chain, and geolocation evidence are unavailable and have not been fabricated.</div>
          </div>
        </div>
      )}

      {/* Main Analysis Results Dashboard */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

          {/* 1. Overview Section (Main Executive Dashboard Hero Header) */}
          {isVisible('sec-overview') && (
            <section id="sec-overview" className="card fade-in" style={{ borderLeft: '4px solid var(--accent)' }}>
              <div className="section-title" style={{ marginBottom: 12 }}>
                <ShieldAlert size={20} color="var(--accent)" /> Section 1: Executive Overview & Immediate Triage
              </div>

              <div className="grid-3" style={{ alignItems: 'stretch', gap: 14 }}>
                {/* Immediate Risk Display */}
                <div style={{ background: 'var(--bg-surface)', padding: 14, borderRadius: 10, border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.68rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)' }}>
                    Risk Score & Classification
                  </div>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 4 }}>
                    <div style={{ fontSize: '2.4rem', fontWeight: 800, fontFamily: 'JetBrains Mono', color: riskScore >= 70 ? 'var(--critical)' : riskScore >= 25 ? 'var(--medium)' : 'var(--pass)' }}>
                      {riskScore}<span style={{ fontSize: '1rem', color: 'var(--text-muted)' }}>/100</span>
                    </div>
                    <span className="badge badge-critical" style={{ fontSize: '0.72rem' }}>
                      {classification}
                    </span>
                  </div>
                  <div style={{ marginTop: 6, fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                    Confidence Level: <strong style={{ color: 'var(--text-primary)' }}>{confidence}</strong>
                  </div>
                </div>

                {/* Immediate Authentication Display */}
                <div style={{ background: 'var(--bg-surface)', padding: 14, borderRadius: 10, border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.68rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 8 }}>
                    Authentication Safeguards
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem' }}>
                      <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>SPF</span>
                      <span className={`badge ${getStatusBadge(spfStatus)}`}>
                        {getStatusIcon(spfStatus)} {spfStatus}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem' }}>
                      <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>DKIM</span>
                      <span className={`badge ${getStatusBadge(dkimStatus)}`}>
                        {getStatusIcon(dkimStatus)} {dkimStatus}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem' }}>
                      <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>DMARC</span>
                      <span className={`badge ${getStatusBadge(dmarcStatus)}`}>
                        {getStatusIcon(dmarcStatus)} {dmarcStatus}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Immediate Origin Details Display */}
                <div style={{ background: 'var(--bg-surface)', padding: 14, borderRadius: 10, border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.68rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 6 }}>
                    Earliest Observed Origin
                  </div>
                  <div className="mono" style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--accent)', marginBottom: 4 }}>
                    {earliestIp}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <div><strong>Location:</strong> {originCity}, {originCountry}</div>
                    <div><strong>ISP / ASN:</strong> {originIsp} ({originAsn})</div>
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* 3. Risk Score Section */}
          {isVisible('sec-risk') && (
            <section id="sec-risk">
              <div className="section-title">
                <ShieldAlert size={18} color="var(--accent)" /> Section 3: Risk Score & Threat Indicators
              </div>
              <div className="grid-2" style={{ alignItems: 'stretch' }}>
                <FraudScore riskAnalysis={result.risk_analysis} />
                <RiskReasons reasons={result.risk_analysis?.reasons} />
              </div>
            </section>
          )}

          {/* 4. Email Details Section */}
          {isVisible('sec-email') && (
            <section id="sec-email">
              <div className="section-title">
                <Mail size={18} color="var(--accent)" /> Section 4: Email Envelope & Metadata
              </div>
              <EmailSummary email={result.email} />
            </section>
          )}

          {/* 5. Authentication Section */}
          {isVisible('sec-auth') && (
            <section id="sec-auth">
              <div className="section-title">
                <ShieldCheck size={18} color="var(--accent)" /> Section 5: Authentication Deep Dive (SPF / DKIM / DMARC)
              </div>
              <AuthenticationStatus auth={result.authentication} />
            </section>
          )}

          {/* 6. Header Forensics Section */}
          {isVisible('sec-forensics') && (
            <section id="sec-forensics">
              <div className="section-title">
                <Route size={18} color="var(--accent)" /> Section 6: Header Forensics & Anomalies
              </div>
              <HeaderTrace forensics={result.header_forensics} geoip={result.ip_intelligence?.geolocation} />
            </section>
          )}

          {/* 7. Origin Trace Section */}
          {isVisible('sec-trace') && (
            <section id="sec-trace">
              <div className="section-title">
                <Globe size={18} color="var(--accent)" /> Section 7: Origin Trace & Hop Chain
              </div>
              <div className="card fade-in">
                <div className="card-header">
                  <div className="card-title"><Globe size={15} /> Public Sender Origin Trace</div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
                  <div style={{ background: 'var(--bg-surface)', padding: 12, borderRadius: 8 }}>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Earliest Public Sender IP</div>
                    <div className="mono" style={{ fontWeight: 700, color: 'var(--accent)', marginTop: 2 }}>{earliestIp}</div>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', padding: 12, borderRadius: 8 }}>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Country</div>
                    <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>{originCountry}</div>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', padding: 12, borderRadius: 8 }}>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>City</div>
                    <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>{originCity}</div>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', padding: 12, borderRadius: 8 }}>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>ISP</div>
                    <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>{originIsp}</div>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', padding: 12, borderRadius: 8 }}>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>ASN</div>
                    <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>{originAsn}</div>
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* 8. Geolocation Map Section */}
          {isVisible('sec-map') && (
            <section id="sec-map">
              <div className="section-title">
                <MapPin size={18} color="var(--accent)" /> Section 8: Geolocation Trace Map
              </div>
              <InfrastructureMap forensics={result.header_forensics} />
            </section>
          )}

          {/* 9. IOC Intelligence Section */}
          {isVisible('sec-iocs') && (
            <section id="sec-iocs">
              <div className="section-title">
                <Layers size={18} color="var(--accent)" /> Section 9: Indicators of Compromise (IOC Intelligence)
              </div>
              <IOCList iocs={result.iocs} />
            </section>
          )}

          {/* 10. AI Analysis Section */}
          {isVisible('sec-ai') && (
            <section id="sec-ai">
              <div className="section-title">
                <Cpu size={18} color="var(--accent)" /> Section 10: AI & Machine Learning Classification
              </div>
              <AIAnalysisSection riskAnalysis={result.risk_analysis} />
            </section>
          )}

          {/* 11. Evidence Integrity Section */}
          {isVisible('sec-integrity') && (
            <section id="sec-integrity">
              <div className="section-title">
                <FileCode size={18} color="var(--accent)" /> Section 11: Evidence Integrity & Chain of Custody
              </div>
              <EvidenceInfo evidence={result.evidence} timestamp={result.ingested_at} />
            </section>
          )}

          {/* 12. Forensic Report Section */}
          {isVisible('sec-report') && (
            <section id="sec-report">
              <div className="section-title">
                <FileText size={18} color="var(--accent)" /> Section 12: Forensic Report & Export
              </div>
              <ForensicReport result={result} />
            </section>
          )}

          {/* 13. Investigation Timeline Section */}
          {isVisible('sec-timeline') && (
            <section id="sec-timeline">
              <div className="section-title">
                <Clock size={18} color="var(--accent)" /> Section 13: Interactive Investigation Timeline
              </div>
              <InvestigationTimeline timelineData={result?.timeline || buildTimelineFromResponse(result)} isAnalyzing={loading} />
            </section>
          )}


        </div>
      )}

    </div>
  )
}
