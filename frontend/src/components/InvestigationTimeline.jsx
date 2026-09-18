import React, { useState } from 'react';
import {
  Clock,
  ChevronDown,
  ChevronRight,
  Search,
  Shield,
  Server,
  Key,
  Globe,
  Brain,
  FileText,
  Radio,
  Zap,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';

const STEP_ICONS = {
  EMAIL_RECEIVED: MailIcon,
  HEADER_HOP: Server,
  RELAY: Radio,
  ORIGIN_INFRASTRUCTURE: Globe,
  AUTHENTICATION_ANALYSIS: Key,
  IOC_EXTRACTION: Search,
  GEOIP_LOOKUP: Globe,
  THREAT_INTELLIGENCE: Shield,
  ML_ANALYSIS: Brain,
  FINAL_RISK_ASSESSMENT: Zap,
  REPORT_GENERATED: FileText
};

function MailIcon(props) {
  return (
    <svg {...props} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
    </svg>
  );
}

export default function InvestigationTimeline({ timelineData, isAnalyzing }) {
  const [expandedEventId, setExpandedEventId] = useState(null);
  const [filterCategory, setFilterCategory] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  if (isAnalyzing) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: 32 }}>
        <div className="spinner" style={{ margin: '0 auto 12px', width: 28, height: 28, borderWidth: 2 }} />
        <div style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Constructing Investigation Timeline...</div>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>Tracing 11-step forensic evidence chain</div>
      </div>
    );
  }

  if (!timelineData || !timelineData.events || timelineData.events.length === 0) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: 32 }}>
        <Clock size={36} color="var(--text-muted)" style={{ margin: '0 auto 8px', opacity: 0.4 }} />
        <div style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>No Timeline Data Available</div>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>
          Upload and analyze an .eml evidence file to view its investigation timeline.
        </div>
      </div>
    );
  }

  const events = timelineData.events || [];

  const filteredEvents = events.filter((evt) => {
    const matchesSearch =
      evt.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      evt.summary.toLowerCase().includes(searchTerm.toLowerCase()) ||
      evt.source.toLowerCase().includes(searchTerm.toLowerCase());

    if (!matchesSearch) return false;

    if (filterCategory === 'ALL') return true;
    if (filterCategory === 'AUTH' && evt.event_type === 'AUTHENTICATION_ANALYSIS') return true;
    if (filterCategory === 'NETWORK' && ['HEADER_HOP', 'RELAY', 'ORIGIN_INFRASTRUCTURE', 'GEOIP_LOOKUP'].includes(evt.event_type)) return true;
    if (filterCategory === 'AI_ML' && evt.event_type === 'ML_ANALYSIS') return true;
    if (filterCategory === 'IOC' && evt.event_type === 'IOC_EXTRACTION') return true;
    return true;
  });

  const toggleExpand = (id) => {
    setExpandedEventId(expandedEventId === id ? null : id);
  };

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Clock size={16} color="var(--accent)" />
          <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '0.88rem' }}>Forensic Investigation Timeline</span>
          <span className="badge" style={{ fontSize: '0.65rem', background: 'var(--accent-dim)', color: 'var(--accent)', border: '1px solid rgba(79,195,247,0.2)' }}>
            {events.length} Steps
          </span>
        </div>

        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ position: 'relative' }}>
            <Search size={12} style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Filter..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="input"
              style={{ paddingLeft: 26, fontSize: '0.75rem', width: 160, padding: '5px 8px 5px 26px' }}
            />
          </div>

          <div style={{ display: 'flex', gap: 2, background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', padding: 2 }}>
            {['ALL', 'AUTH', 'NETWORK', 'AI_ML', 'IOC'].map((cat) => (
              <button
                key={cat}
                onClick={() => setFilterCategory(cat)}
                className={`tab ${filterCategory === cat ? 'active' : ''}`}
                style={{ fontSize: '0.65rem', padding: '3px 8px' }}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Timeline body */}
      <div style={{ padding: '12px 20px 16px' }}>
        {filteredEvents.map((evt, idx) => {
          const isExpanded = expandedEventId === evt.id;
          const IconComp = STEP_ICONS[evt.event_type] || Clock;

          const isWarning = evt.status === 'WARNING';
          const isFailed = evt.status === 'FAILED';
          const borderColor = isFailed ? 'var(--critical)' : isWarning ? 'var(--medium)' : 'var(--pass)';
          const bgColor = isFailed ? 'var(--critical-dim)' : isWarning ? 'var(--medium-dim)' : 'var(--pass-dim)';
          const textColor = isFailed ? 'var(--critical)' : isWarning ? 'var(--medium)' : 'var(--pass)';

          return (
            <div key={evt.id} style={{ marginBottom: idx < filteredEvents.length - 1 ? 6 : 0 }}>
              {/* Collapsed row — always visible */}
              <div
                onClick={() => toggleExpand(evt.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '8px 10px',
                  borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer',
                  background: isExpanded ? 'var(--bg-elevated)' : 'transparent',
                  border: `1px solid ${isExpanded ? 'var(--border-accent)' : 'transparent'}`,
                  transition: 'all 0.15s ease',
                }}
                onMouseEnter={e => { if (!isExpanded) e.currentTarget.style.background = 'var(--bg-card-hover)' }}
                onMouseLeave={e => { if (!isExpanded) e.currentTarget.style.background = 'transparent' }}
              >
                {/* Step icon */}
                <div style={{
                  width: 28, height: 28, borderRadius: '50%',
                  background: bgColor, border: `1.5px solid ${borderColor}`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}>
                  <IconComp size={13} color={textColor} />
                </div>

                {/* Step number */}
                <span style={{
                  fontSize: '0.62rem', fontWeight: 700, fontFamily: "'JetBrains Mono', monospace",
                  color: 'var(--text-muted)', background: 'var(--bg-surface)',
                  padding: '1px 5px', borderRadius: 3, border: '1px solid var(--border-subtle)',
                  flexShrink: 0,
                }}>
                  {evt.step_number}
                </span>

                {/* Title + Summary */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {evt.title}
                  </div>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginTop: 1 }}>
                    {evt.summary}
                  </div>
                </div>

                {/* Source — always visible */}
                <div style={{
                  fontSize: '0.62rem', color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace",
                  maxWidth: 180, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                  flexShrink: 0, display: 'none',
                }} className="timeline-source-desktop">
                  {evt.source}
                </div>

                {/* Status badge */}
                <span style={{
                  fontSize: '0.58rem', fontWeight: 700, padding: '2px 6px', borderRadius: 100,
                  background: bgColor, color: textColor,
                  border: `1px solid ${borderColor}33`,
                  textTransform: 'uppercase', letterSpacing: '0.04em', flexShrink: 0,
                }}>
                  {evt.status}
                </span>

                {/* Timestamp */}
                <span style={{
                  fontSize: '0.62rem', fontFamily: "'JetBrains Mono', monospace",
                  color: 'var(--text-muted)', flexShrink: 0,
                }}>
                  {new Date(evt.timestamp).toLocaleTimeString()}
                </span>

                {/* Chevron */}
                {isExpanded
                  ? <ChevronDown size={14} color="var(--accent)" style={{ flexShrink: 0 }} />
                  : <ChevronRight size={14} color="var(--text-muted)" style={{ flexShrink: 0 }} />
                }
              </div>

              {/* Expanded evidence drawer */}
              {isExpanded && (
                <div style={{
                  marginLeft: 48, marginRight: 10, marginTop: 4, marginBottom: 4,
                  padding: '10px 12px',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  animation: 'fadeIn 0.2s ease',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                      Source
                    </span>
                    <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>
                      {evt.source}
                    </span>
                  </div>
                  <div style={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    padding: 10,
                    overflowX: 'auto',
                  }}>
                    <pre style={{
                      margin: 0, fontSize: '0.68rem', fontFamily: "'JetBrains Mono', monospace",
                      color: 'var(--text-mono)', lineHeight: 1.5, whiteSpace: 'pre-wrap',
                    }}>
                      {JSON.stringify(evt.relevant_evidence, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Responsive: show source on wider screens */}
      <style>{`
        @media (min-width: 900px) {
          .timeline-source-desktop { display: block !important; }
        }
      `}</style>
    </div>
  );
}
