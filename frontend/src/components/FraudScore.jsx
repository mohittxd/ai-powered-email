import React from 'react';
import { Info, ShieldAlert, Cpu } from 'lucide-react';

export default function FraudScore({ riskAnalysis }) {
  if (!riskAnalysis) return null;
  const {
    risk_score = 0,
    final_risk_score = null,
    rule_based_score = null,
    ml_score = null,
    classification = 'UNKNOWN',
    confidence = 'low',
    calibration_note = 'The ML score is an uncalibrated heuristic feature model output, not a statistically validated probability.'
  } = riskAnalysis;

  const displayScore = final_risk_score ?? risk_score;
  const ruleScoreVal = rule_based_score ?? displayScore;
  const scoreColor = displayScore >= 85 ? 'var(--critical)' : displayScore >= 70 ? 'var(--high)' : displayScore >= 25 ? 'var(--medium)' : 'var(--pass)';

  return (
    <div className="card fade-in" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '24px 20px', height: '100%' }}>
      <div style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700, color: 'var(--accent)', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
        <ShieldAlert size={15} /> Risk Score Analysis
      </div>

      <div className="gauge-wrap" style={{ textAlign: 'center' }}>
        <div className="gauge-score" style={{ color: scoreColor, fontSize: '2.8rem', fontWeight: 800 }}>{displayScore}</div>
        <div className="gauge-label" style={{ background: scoreColor + '22', color: scoreColor, border: `1px solid ${scoreColor}55`, marginTop: 6 }}>
          {classification}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 10, fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          <Info size={14} /> Confidence: <strong style={{ color: 'var(--text-secondary)', textTransform: 'uppercase' }}>{confidence}</strong>
        </div>
      </div>

      {/* Phase 14 AI Score Breakdown Pills */}
      <div style={{
        marginTop: 16,
        paddingTop: 12,
        borderTop: '1px solid var(--border-subtle)',
        display: 'grid',
        gridTemplateColumns: '1fr 1fr 1fr',
        gap: 8,
        width: '100%',
        textAlign: 'center'
      }}>
        <div style={{ background: 'rgba(255,255,255,0.03)', padding: '6px 4px', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>Rule Score</div>
          <div style={{ fontWeight: 700, fontSize: '0.9rem', color: '#60a5fa' }}>{ruleScoreVal}</div>
        </div>
        <div style={{ background: 'rgba(255,255,255,0.03)', padding: '6px 4px', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.65rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 2 }}>
            <Cpu size={10} /> ML Score
          </div>
          <div style={{ fontWeight: 700, fontSize: '0.9rem', color: '#c084fc' }}>{ml_score !== null ? ml_score : 'N/A'}</div>
        </div>
        <div style={{ background: `${scoreColor}15`, padding: '6px 4px', borderRadius: 6, border: `1px solid ${scoreColor}44` }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>Final Score</div>
          <div style={{ fontWeight: 700, fontSize: '0.9rem', color: scoreColor }}>{displayScore}</div>
        </div>
      </div>

      {calibration_note && (
        <div style={{ marginTop: 12, fontSize: '0.65rem', color: 'var(--text-muted)', fontStyle: 'italic', textAlign: 'center', lineHeight: '1.2' }}>
          * {calibration_note}
        </div>
      )}
    </div>
  );
}
