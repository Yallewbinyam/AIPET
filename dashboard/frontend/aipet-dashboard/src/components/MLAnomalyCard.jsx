import React, { useState } from 'react';

export default function MLAnomalyCard({ token }) {
  const [status, setStatus]     = useState('idle');
  const [metrics, setMetrics]   = useState(null);
  const [error, setError]       = useState('');

  const [hostIp, setHostIp]         = useState('');
  const [scanStatus, setScanStatus] = useState('idle');
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError]   = useState('');

  const handleTrain = async () => {
    setStatus('training');
    setError('');
    setMetrics(null);
    try {
      const res = await fetch('/api/ml/anomaly/train', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || 'Training failed'); setStatus('error'); return; }
      setMetrics({ version: data.version, ...data.metrics, samples: data.training_samples });
      setStatus('done');
    } catch {
      setError('Network error — is the backend running?');
      setStatus('error');
    }
  };

  const handleScanHost = async () => {
    if (!hostIp.trim()) { setScanError('Enter a host IP first'); return; }
    setScanStatus('loading');
    setScanError('');
    setScanResult(null);
    try {
      const res = await fetch('/api/ml/anomaly/predict_real', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ host_ip: hostIp.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setScanError(data.error || 'Prediction failed');
        setScanStatus('error');
        return;
      }
      setScanResult(data);
      setScanStatus('done');
    } catch {
      setScanError('Network error — is the backend running?');
      setScanStatus('error');
    }
  };

  const severityColor = (s) =>
    ({ critical: '#ff2d55', high: '#ff6b00', medium: '#ffd60a', low: '#4ade80' }[s] || '#94a3b8');

  return (
    <div style={styles.card}>
      <div style={styles.header}>
        <span style={styles.icon}>&#127760;</span>
        <div>
          <div style={styles.title}>ML Anomaly Detection</div>
          <div style={styles.subtitle}>Isolation Forest — unsupervised IoT behaviour scoring</div>
        </div>
      </div>

      <button
        style={{ ...styles.btn, opacity: status === 'training' ? 0.6 : 1 }}
        onClick={handleTrain}
        disabled={status === 'training'}
      >
        {status === 'training' ? 'Training…' : 'Train Model'}
      </button>

      {status === 'done' && metrics && (
        <div style={styles.results}>
          <div style={styles.resultRow}><span style={styles.label}>Version</span><span style={styles.value}>{metrics.version}</span></div>
          <div style={styles.resultRow}><span style={styles.label}>Precision</span><span style={styles.value}>{(metrics.precision * 100).toFixed(1)}%</span></div>
          <div style={styles.resultRow}><span style={styles.label}>Recall</span><span style={styles.value}>{(metrics.recall * 100).toFixed(1)}%</span></div>
          <div style={styles.resultRow}>
            <span style={styles.label}>F1 Score</span>
            <span style={{ ...styles.value, color: metrics.f1 >= 0.9 ? '#4ade80' : '#facc15' }}>
              {(metrics.f1 * 100).toFixed(1)}%
            </span>
          </div>
          <div style={styles.resultRow}><span style={styles.label}>Samples</span><span style={styles.value}>{metrics.samples.toLocaleString()}</span></div>
        </div>
      )}

      {status === 'error' && <div style={styles.errorBox}>{error}</div>}

      <div style={styles.divider} />

      <div style={styles.scanSection}>
        <div style={styles.sectionLabel}>Scan Host for Anomalies</div>
        <input
          style={styles.input}
          type="text"
          placeholder="Enter host IP address"
          value={hostIp}
          onChange={(e) => setHostIp(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleScanHost()}
        />
        <button
          style={{ ...styles.btn, ...styles.scanBtn, opacity: scanStatus === 'loading' ? 0.6 : 1 }}
          onClick={handleScanHost}
          disabled={scanStatus === 'loading'}
        >
          {scanStatus === 'loading' ? 'Analysing…' : 'Scan Host for Anomalies'}
        </button>

        {scanStatus === 'done' && scanResult && (
          <div style={styles.results}>
            <div style={styles.resultRow}>
              <span style={styles.label}>Host</span>
              <span style={styles.value}>{scanResult.target_ip}</span>
            </div>
            <div style={styles.resultRow}>
              <span style={styles.label}>Anomaly</span>
              <span style={{ ...styles.value, color: scanResult.is_anomaly ? '#ff6b00' : '#4ade80' }}>
                {scanResult.is_anomaly ? 'YES' : 'No'}
              </span>
            </div>
            <div style={styles.resultRow}>
              <span style={styles.label}>Score</span>
              <span style={styles.value}>{scanResult.anomaly_score.toFixed(4)}</span>
            </div>
            <div style={styles.resultRow}>
              <span style={styles.label}>Severity</span>
              <span style={{ ...styles.value, color: severityColor(scanResult.severity) }}>
                {scanResult.severity.toUpperCase()}
              </span>
            </div>
            {scanResult.explainer_type && (
              <div style={styles.resultRow}>
                <span style={styles.label}>Explainer</span>
                <span style={styles.badge}>SHAP-{scanResult.explainer_type}</span>
              </div>
            )}
            {scanResult.top_contributors && scanResult.top_contributors.length > 0 && (
              <div style={styles.contributors}>
                <div style={styles.contribLabel}>Top SHAP contributors</div>
                {scanResult.top_contributors.map((c) => {
                  const isAnomaly = c.direction === 'increases_anomaly';
                  const valStr = (c.shap_value >= 0 ? '+' : '') + c.shap_value.toFixed(4);
                  return (
                    <div key={c.feature} style={styles.contribRow}>
                      <span style={styles.contribFeature}>{c.feature}</span>
                      <span style={{ ...styles.contribScore, color: isAnomaly ? '#ff6b00' : '#4ade80' }}>
                        {valStr}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
            {scanResult.synthetic_fields && scanResult.synthetic_fields.length > 0 && (
              <div style={styles.syntheticNote}>
                Partial result — {scanResult.synthetic_fields.length} features use imputed values
                (watch agent telemetry not yet collected): {scanResult.synthetic_fields.slice(0, 4).join(', ')}
                {scanResult.synthetic_fields.length > 4 ? ', …' : ''}
              </div>
            )}
          </div>
        )}

        {scanStatus === 'error' && <div style={styles.errorBox}>{scanError}</div>}
      </div>
    </div>
  );
}

const styles = {
  card: { background: '#1e293b', border: '1px solid #334155', borderRadius: 8, padding: '20px 24px', minWidth: 280, maxWidth: 380 },
  header: { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 },
  icon: { fontSize: 28 },
  title: { color: '#f1f5f9', fontWeight: 600, fontSize: 15 },
  subtitle: { color: '#94a3b8', fontSize: 12, marginTop: 2 },
  btn: { background: '#3b82f6', color: '#fff', border: 'none', borderRadius: 6, padding: '8px 18px', fontSize: 13, fontWeight: 600, cursor: 'pointer', width: '100%' },
  scanBtn: { background: '#7c3aed', marginTop: 8 },
  results: { marginTop: 14, borderTop: '1px solid #334155', paddingTop: 12, display: 'flex', flexDirection: 'column', gap: 6 },
  resultRow: { display: 'flex', justifyContent: 'space-between', fontSize: 13 },
  label: { color: '#94a3b8' },
  value: { color: '#e2e8f0', fontWeight: 600 },
  errorBox: { marginTop: 10, background: '#450a0a', border: '1px solid #7f1d1d', borderRadius: 6, color: '#fca5a5', padding: '8px 12px', fontSize: 12 },
  divider: { borderTop: '1px solid #334155', margin: '16px 0' },
  scanSection: { display: 'flex', flexDirection: 'column', gap: 6 },
  sectionLabel: { color: '#94a3b8', fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' },
  input: { background: '#0f172a', border: '1px solid #334155', borderRadius: 6, color: '#f1f5f9', fontSize: 13, padding: '7px 10px', outline: 'none' },
  contributors: { marginTop: 6, padding: '8px 0 0' },
  contribLabel: { color: '#64748b', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 },
  contribRow: { display: 'flex', justifyContent: 'space-between', fontSize: 12, padding: '2px 0' },
  contribFeature: { color: '#94a3b8' },
  contribScore: { fontWeight: 600 },
  badge: { background: '#1e3a5f', color: '#93c5fd', border: '1px solid #1d4ed8', borderRadius: 4, fontSize: 11, padding: '1px 6px', fontWeight: 600 },
  syntheticNote: { marginTop: 8, background: '#1c1f26', border: '1px solid #334155', borderRadius: 4, color: '#64748b', fontSize: 11, padding: '6px 8px', lineHeight: 1.5 },
};
