import React from 'react'
import { Cpu, Zap, ShieldAlert, Layers, BarChart2 } from 'lucide-react'

export default function AIAnalysisSection({ riskAnalysis }) {
  if (!riskAnalysis) return (
    <div className="card fade-in">
      <div className="card-header"><div className="card-title"><Cpu size={16} /> AI & ML Classification Analysis</div></div>
      <div className="empty-state" style={{ padding: 20 }}>
        <div className="empty-state-sub">AI Analysis data unavailable.</div>
      </div>
    </div>
  )

  const {
    rule_based_score = 0,
    ml_score = null,
    final_risk_score = 0,
    nlp_features = {},
    feature_importance = [],
    calibration_note = '',
    ml_available = false
  } = riskAnalysis

  const nlpItems = [
    { label: 'Phishing Intent Vector', key: 'nlp_phishing_intent_score', val: nlp_features.nlp_phishing_intent_score ?? 0 },
    { label: 'Credential Harvesting', key: 'nlp_credential_harvest_score', val: nlp_features.nlp_credential_harvest_score ?? 0 },
    { label: 'Urgency & Coercion', key: 'nlp_urgency_score', val: nlp_features.nlp_urgency_score ?? 0 },
    { label: 'Social Engineering', key: 'nlp_social_eng_score', val: nlp_features.nlp_social_eng_score ?? 0 }
  ]

  return (
    <div className="card fade-in">
      <div className="card-header">
        <div className="card-title">
          <Cpu size={16} />
          AI & NLP Model Threat Analysis (Phase 14 Classifier)
        </div>
        <span className={`badge ${ml_available ? 'badge-pass' : 'badge-warn'}`}>
          {ml_available ? 'XGBoost + Transformer Active' : 'Fallback Engine Active'}
        </span>
      </div>

      {/* Dual Engine Score Comparison */}
      <div className="grid-3" style={{ marginBottom: 16 }}>
        <div className="stat-card" style={{ background: 'var(--bg-surface)' }}>
          <div className="stat-label" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <Zap size={12} color="#60a5fa" /> Rule Engine Baseline
          </div>
          <div className="stat-value" style={{ color: '#60a5fa' }}>{rule_based_score}</div>
          <div className="stat-sub">Deterministic Heuristics (0–100)</div>
        </div>

        <div className="stat-card" style={{ background: 'var(--bg-surface)' }}>
          <div className="stat-label" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <Cpu size={12} color="#c084fc" /> ML / NLP Model Score
          </div>
          <div className="stat-value" style={{ color: '#c084fc' }}>{ml_score !== null ? ml_score : 'N/A'}</div>
          <div className="stat-sub">Transformer Feature Index</div>
        </div>

        <div className="stat-card" style={{ background: 'var(--bg-surface)', borderColor: 'var(--accent-dim)' }}>
          <div className="stat-label" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <ShieldAlert size={12} color="var(--accent)" /> Final Risk Assessment
          </div>
          <div className="stat-value" style={{ color: 'var(--accent)' }}>{final_risk_score}</div>
          <div className="stat-sub">Auth Safeguard Ground Floor Enforced</div>
        </div>
      </div>

      {/* NLP Feature Vector Progress Bars */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 5 }}>
          <Layers size={13} /> Extracted NLP Semantic Feature Vectors
        </div>
        <div className="grid-2" style={{ gap: 12 }}>
          {nlpItems.map(({ label, val }) => {
            const pct = Math.min(Math.max(val * 100, 0), 100)
            const color = pct > 70 ? 'var(--critical)' : pct > 35 ? 'var(--medium)' : 'var(--pass)'
            return (
              <div key={label} style={{ background: 'var(--bg-surface)', padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.76rem', marginBottom: 4 }}>
                  <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
                  <span style={{ fontWeight: 700, color }} className="mono">{(val).toFixed(2)}</span>
                </div>
                <div style={{ height: 5, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${pct}%`, height: '100%', background: color, transition: 'width 0.6s ease' }} />
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Feature Importance Table */}
      {feature_importance.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 5 }}>
            <BarChart2 size={13} /> Model Feature Importance Contribution
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Feature Signal</th>
                  <th>Observed Value</th>
                  <th>Impact Points</th>
                </tr>
              </thead>
              <tbody>
                {feature_importance.map((item, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ fontSize: '0.78rem' }}>{item.feature}</td>
                    <td style={{ color: 'var(--text-primary)' }}>{String(item.value)}</td>
                    <td style={{ fontWeight: 700, color: 'var(--accent)' }}>+{item.impact} pts</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {calibration_note && (
        <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontStyle: 'italic', marginTop: 8 }}>
          * {calibration_note}
        </div>
      )}
    </div>
  )
}
