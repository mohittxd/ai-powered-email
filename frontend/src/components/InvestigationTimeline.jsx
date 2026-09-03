import React, { useState } from 'react';
import {
  Clock,
  CheckCircle2,
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronRight,
  Search,
  Filter,
  Shield,
  Server,
  Key,
  Globe,
  Brain,
  FileText,
  Radio,
  Zap
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
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 002-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
    </svg>
  );
}

export default function InvestigationTimeline({ timelineData, isAnalyzing }) {
  const [expandedEventId, setExpandedEventId] = useState(null);
  const [filterCategory, setFilterCategory] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  if (isAnalyzing) {
    return (
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-8 text-center backdrop-blur">
        <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400 mb-3"></div>
        <p className="text-slate-300 font-medium">Constructing Investigation Timeline...</p>
        <p className="text-slate-500 text-xs mt-1">Tracing 11-step forensic evidence chain</p>
      </div>
    );
  }

  if (!timelineData || !timelineData.events || timelineData.events.length === 0) {
    return (
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-8 text-center backdrop-blur">
        <Clock className="w-10 h-10 text-slate-600 mx-auto mb-2" />
        <h4 className="text-slate-300 font-medium">No Timeline Data Available</h4>
        <p className="text-slate-500 text-xs mt-1">Upload and analyze an .eml evidence file to view its investigation timeline.</p>
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
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-2xl backdrop-blur">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-5 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Clock className="w-5 h-5 text-cyan-400" />
            <h3 className="text-lg font-bold text-white tracking-wide">Forensic Investigation Timeline</h3>
            <span className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 text-xs px-2.5 py-0.5 rounded-full font-mono">
              {events.length} Steps Logged
            </span>
          </div>
          <p className="text-slate-400 text-xs mt-1">
            Chronological evidence sequence from email ingestion to final forensic report generation
          </p>
        </div>

        {/* Filter Bar */}
        <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-48">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Filter timeline..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-1">
            {['ALL', 'AUTH', 'NETWORK', 'AI_ML', 'IOC'].map((cat) => (
              <button
                key={cat}
                onClick={() => setFilterCategory(cat)}
                className={`px-2.5 py-1 text-[10px] font-semibold rounded-md transition-all ${
                  filterCategory === cat
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Interactive Timeline Body */}
      <div className="relative mt-6 pl-4 sm:pl-6">
        {/* Continuous Gradient Connector Line */}
        <div className="absolute left-[19px] sm:left-[27px] top-4 bottom-4 w-0.5 bg-gradient-to-b from-cyan-500 via-indigo-500 to-emerald-500 opacity-40"></div>

        <div className="space-y-6">
          {filteredEvents.map((evt, idx) => {
            const isExpanded = expandedEventId === evt.id;
            const IconComp = STEP_ICONS[evt.event_type] || Clock;

            let statusColor = 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400';
            let badgeBg = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';

            if (evt.status === 'WARNING') {
              statusColor = 'border-amber-500/40 bg-amber-500/10 text-amber-400';
              badgeBg = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
            } else if (evt.status === 'FAILED') {
              statusColor = 'border-rose-500/40 bg-rose-500/10 text-rose-400';
              badgeBg = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
            } else if (evt.status === 'INFO') {
              statusColor = 'border-blue-500/40 bg-blue-500/10 text-blue-400';
              badgeBg = 'bg-blue-500/10 text-blue-400 border-blue-500/30';
            }

            return (
              <div key={evt.id} className="relative flex items-start group">
                {/* Node Step Circle */}
                <div
                  onClick={() => toggleExpand(evt.id)}
                  className={`relative z-10 flex items-center justify-center w-8 h-8 sm:w-10 sm:h-10 rounded-full border-2 cursor-pointer transition-all duration-200 shadow-lg ${statusColor} group-hover:scale-110`}
                >
                  <IconComp className="w-4 h-4 sm:w-5 sm:h-5" />
                </div>

                {/* Event Content Card */}
                <div className="ml-4 sm:ml-6 flex-1 bg-slate-950/60 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition-all duration-200">
                  <div
                    onClick={() => toggleExpand(evt.id)}
                    className="flex flex-col sm:flex-row sm:items-center justify-between cursor-pointer gap-2"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-mono font-bold text-slate-400 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
                        STEP #{evt.step_number}
                      </span>
                      <h4 className="text-sm font-semibold text-slate-100 group-hover:text-cyan-400 transition-colors">
                        {evt.title}
                      </h4>
                    </div>

                    <div className="flex items-center gap-2 self-start sm:self-auto">
                      <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded-full border ${badgeBg}`}>
                        {evt.status}
                      </span>
                      <span className="text-[11px] font-mono text-slate-500 flex items-center gap-1">
                        <Clock className="w-3 h-3 text-slate-600" />
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </span>
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 text-cyan-400" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-slate-500" />
                      )}
                    </div>
                  </div>

                  {/* Summary & Source */}
                  <div className="mt-2 text-xs text-slate-300">
                    <p>{evt.summary}</p>
                    <div className="mt-1 flex items-center gap-2 text-[11px] text-slate-500 font-mono">
                      <span>Source: <span className="text-slate-400">{evt.source}</span></span>
                    </div>
                  </div>

                  {/* Interactive Evidence Drawer */}
                  {isExpanded && (
                    <div className="mt-4 pt-3 border-t border-slate-800/80 animate-fadeIn">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">
                          Relevant Evidence Payload
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono">JSON / Key-Value</span>
                      </div>

                      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 overflow-x-auto">
                        <pre className="text-[11px] font-mono text-cyan-300 leading-relaxed">
                          {JSON.stringify(evt.relevant_evidence, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
