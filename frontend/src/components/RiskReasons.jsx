import React from 'react';
import { AlertOctagon } from 'lucide-react';

export default function RiskReasons({ reasons }) {
  if (!reasons || reasons.length === 0) return null;

  return (
    <div className="card fade-in" style={{ height: '100%' }}>
      <div className="card-header">
        <div className="card-title"><AlertOctagon size={16} color="var(--high)" /> Risk Factors</div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {reasons.map((reason, idx) => (
          <div key={idx} style={{ padding: '10px 14px', background: 'var(--bg-surface)', borderLeft: '3px solid var(--high)', borderRadius: '0 4px 4px 0', fontSize: '0.85rem' }}>
            {reason}
          </div>
        ))}
      </div>
    </div>
  );
}
