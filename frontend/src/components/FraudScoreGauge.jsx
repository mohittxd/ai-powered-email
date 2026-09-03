import { useEffect, useRef, useState } from 'react'
import { ShieldAlert } from 'lucide-react'

const SCORE_COLORS = {
  legitimate: '#2ed573',
  suspicious: '#ffa502',
  impersonation: '#ff6b35',
  phishing: '#ff4757',
  bec_fraud: '#c0392b',
}

const LABELS = {
  legitimate: 'LEGITIMATE',
  suspicious: 'SUSPICIOUS',
  impersonation: 'IMPERSONATION',
  phishing: 'PHISHING',
  bec_fraud: 'BEC FRAUD',
}

function getColor(score) {
  if (score < 25) return '#2ed573'
  if (score < 50) return '#ffa502'
  if (score < 70) return '#ff6b35'
  return '#ff4757'
}

export default function FraudScoreGauge({
  score = 0,
  ruleBasedScore = null,
  mlScore = null,
  finalRiskScore = null,
  classification = 'legitimate',
  confidence = 0,
  calibrationNote = ''
}) {
  const displayScore = finalRiskScore ?? score
  const [displayed, setDisplayed] = useState(0)
  const animRef = useRef()

  useEffect(() => {
    let start = 0
    const target = displayScore
    const duration = 800
    const startTime = performance.now()

    const animate = (now) => {
      const elapsed = now - startTime
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplayed(Math.round(eased * target))
      if (progress < 1) animRef.current = requestAnimationFrame(animate)
    }

    animRef.current = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(animRef.current)
  }, [displayScore])

  // SVG arc parameters
  const cx = 90, cy = 90, r = 70
  const startAngle = 210, endAngle = 330 // total sweep = 300°
  const sweepDeg = (displayed / 100) * 300
  const toRad = (deg) => (deg * Math.PI) / 180

  const arcPath = (start, sweep) => {
    const end = start + sweep
    const x1 = cx + r * Math.cos(toRad(start - 90))
    const y1 = cy + r * Math.sin(toRad(start - 90))
    const x2 = cx + r * Math.cos(toRad(end - 90))
    const y2 = cy + r * Math.sin(toRad(end - 90))
    const large = sweep > 180 ? 1 : 0
    return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`
  }

  const color = SCORE_COLORS[classification] || getColor(displayed)

  return (
    <div className="card" style={{ textAlign: 'center' }}>
      <div className="card-header">
        <div className="card-title">
          <ShieldAlert size={15} />
          AI & Forensic Risk Score
        </div>
        <span className="badge" style={{ fontSize: '0.7rem', color: '#8ba3c7', background: 'transparent', border: '1px solid #1e2d45' }}>
          Confidence {Math.round((typeof confidence === 'number' ? confidence : 0.85) * 100)}%
        </span>
      </div>

      <div className="gauge-wrap">
        <svg width="180" height="160" className="gauge-svg" viewBox="0 0 180 180">
          {/* Track */}
          <path
            d={arcPath(startAngle, 300)}
            fill="none"
            stroke="rgba(255,255,255,0.05)"
            strokeWidth="10"
            strokeLinecap="round"
          />
          {/* Filled arc */}
          <path
            d={arcPath(startAngle, sweepDeg)}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 8px ${color}80)`, transition: 'all 0.1s' }}
          />
          {/* Tick marks */}
          {[0, 25, 50, 75, 100].map(tick => {
            const deg = startAngle + (tick / 100) * 300
            const inner = 56, outer = 64
            const x1 = cx + inner * Math.cos(toRad(deg - 90))
            const y1 = cy + inner * Math.sin(toRad(deg - 90))
            const x2 = cx + outer * Math.cos(toRad(deg - 90))
            const y2 = cy + outer * Math.sin(toRad(deg - 90))
            return <line key={tick} x1={x1} y1={y1} x2={x2} y2={y2} stroke="rgba(255,255,255,0.15)" strokeWidth="2" strokeLinecap="round" />
          })}
        </svg>

        <div style={{ marginTop: -100 }}>
          <div className="gauge-score" style={{ color }}>
            {displayed}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>/ 100 Final Risk</div>
        </div>

        <div style={{ marginTop: 8 }}>
          <span
            className="gauge-label"
            style={{ background: `${color}20`, color, border: `1px solid ${color}50` }}
          >
            {LABELS[classification] || classification?.toUpperCase()}
          </span>
        </div>
      </div>

      {/* Phase 14 AI & Rule-based Score Breakdown */}
      <div style={{
        marginTop: 16,
        paddingTop: 12,
        borderTop: '1px solid rgba(255,255,255,0.08)',
        display: 'grid',
        gridTemplateColumns: '1fr 1fr 1fr',
        gap: 6,
        fontSize: '0.72rem'
      }}>
        <div style={{ background: 'rgba(255,255,255,0.03)', padding: '6px 4px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.05)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>Rule Score</div>
          <div style={{ fontWeight: 700, fontSize: '0.9rem', color: '#60a5fa' }}>{ruleBasedScore ?? displayScore}</div>
        </div>
        <div style={{ background: 'rgba(255,255,255,0.03)', padding: '6px 4px', borderRadius: 6, border: '1px solid rgba(255,255,255,0.05)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>ML Score</div>
          <div style={{ fontWeight: 700, fontSize: '0.9rem', color: '#c084fc' }}>{mlScore !== null ? mlScore : 'N/A'}</div>
        </div>
        <div style={{ background: 'rgba(255,255,255,0.05)', padding: '6px 4px', borderRadius: 6, border: `1px solid ${color}40` }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>Final Score</div>
          <div style={{ fontWeight: 700, fontSize: '0.9rem', color }}>{displayed}</div>
        </div>
      </div>

      {calibrationNote && (
        <div style={{
          marginTop: 10,
          fontSize: '0.65rem',
          color: '#94a3b8',
          fontStyle: 'italic',
          lineHeight: '1.2'
        }}>
          * {calibrationNote}
        </div>
      )}
    </div>
  )
}
