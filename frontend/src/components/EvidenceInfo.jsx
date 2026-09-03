import React from 'react';
import { FileCode } from 'lucide-react';

export default function EvidenceInfo({ evidence, timestamp }) {
  if (!evidence) return null;
  return (
    <div className="card fade-in">
      <div className="card-header">
        <div className="card-title"><FileCode size={16} /> Evidence Information</div>
      </div>
      <div className="grid-2">
        <div className="auth-item">
          <div className="auth-item-label">Filename</div>
          <div className="auth-item-value mono" style={{ fontSize: '0.85rem', wordBreak: 'break-all' }}>{evidence.filename}</div>
        </div>
        <div className="auth-item">
          <div className="auth-item-label">SHA-256 Hash</div>
          <div className="auth-item-value mono" style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>{evidence.sha256}</div>
        </div>
        <div className="auth-item">
          <div className="auth-item-label">Size</div>
          <div className="auth-item-value">{(evidence.size / 1024).toFixed(2)} KB</div>
        </div>
        <div className="auth-item">
          <div className="auth-item-label">Analysis Timestamp</div>
          <div className="auth-item-value">{new Date(timestamp).toLocaleString()}</div>
        </div>
      </div>
    </div>
  );
}
