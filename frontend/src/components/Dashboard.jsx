import { useState } from 'react'
import { analyzeEmail } from '../services/api'
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
  Clock
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

export default function Dashboard({ onAnalyzed }) {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [activeSection, setActiveSection] = useState('all')
  const toast = useToast()

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
      toast.push(`Forensic analysis complete — Risk score: ${score}/100`, level)
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

  const geoip = result?.ip_intelligence?.geolocation || {}
const originCountry = geoip.country || 'Unavailable'
const originCity = geoip.city || 'Unavailable'
const originIsp = geoip.isp || 'Unavailable'
const originAsn = geoip.asn || 'Unavailable'
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
    { id: 'sec-upload', label: '2. Upload Evidence' },
    { id: 'sec-risk', label: '3. Risk Score' },
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

      {/* 2. Upload Evidence Section */}
      {isVisible('sec-upload') && (
        <section id="sec-upload">
          <div className="section-title">
            <Zap size={18} color="var(--accent)" /> Section 2: Upload Evidence
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

      {/* Empty State */}
      {!result && !loading && !error && (
        <div className="card fade-in">
          <div className="empty-state">
            <div className="empty-state-icon">🛡️</div>
            <div className="empty-state-title">SOC Forensic Intelligence Platform Ready</div>
            <div className="empty-state-sub">
              Upload a <code>.eml</code> file or paste raw email headers above to execute full 14-phase forensic analysis.
            </div>
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
