import React, { useState } from 'react';

export default function MLAnomalyCard({ token }) {
  const [status, setStatus]   = useState('idle');   // idle | training | done | error
  const [metrics, setMetrics] = useState(null);
  const [error, setError]     = useState('');

  const handleTrain = async () => {
    setStatus('training');
    setError('');
    setMetrics(null);
    try {
      const res = await fetch('/api/ml/anomaly/train', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Training failed');
        setStatus('error');
        return;
      }
      setMetrics({ version: data.version, ...data.metrics, samples: data.training_samples });
      setStatus('done');
    } catch (err) {
      setError('Network error — is the backend running?');
      setStatus('error');
    }
  };

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
          <div style={styles.resultRow}>
            <span style={styles.label}>Version</span>
            <span style={styles.value}>{metrics.version}</span>
          </div>
          <div style={styles.resultRow}>
            <span style={styles.label}>Precision</span>
            <span style={styles.value}>{(metrics.precision * 100).toFixed(1)}%</span>
          </div>
          <div style={styles.resultRow}>
            <span style={styles.label}>Recall</span>
            <span style={styles.value}>{(metrics.recall * 100).toFixed(1)}%</span>
          </div>
          <div style={styles.resultRow}>
            <span style={styles.label}>F1 Score</span>
            <span style={{ ...styles.value, color: metrics.f1 >= 0.9 ? '#4ade80' : '#facc15' }}>
              {(metrics.f1 * 100).toFixed(1)}%
            </span>
          </div>
          <div style={styles.resultRow}>
            <span style={styles.label}>Samples</span>
            <span style={styles.value}>{metrics.samples.toLocaleString()}</span>
          </div>
        </div>
      )}

      {status === 'error' && (
        <div style={styles.errorBox}>{error}</div>
      )}
    </div>
  );
}

const styles = {
  card: {
    background: '#1e293b',
    border: '1px solid #334155',
    borderRadius: 8,
    padding: '20px 24px',
    minWidth: 280,
    maxWidth: 360,
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: 12,
    marginBottom: 16,
  },
  icon: { fontSize: 28 },
  title: {
    color: '#f1f5f9',
    fontWeight: 600,
    fontSize: 15,
  },
  subtitle: {
    color: '#94a3b8',
    fontSize: 12,
    marginTop: 2,
  },
  btn: {
    background: '#3b82f6',
    color: '#fff',
    border: 'none',
    borderRadius: 6,
    padding: '8px 18px',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer',
    width: '100%',
  },
  results: {
    marginTop: 14,
    borderTop: '1px solid #334155',
    paddingTop: 12,
    display: 'flex',
    flexDirection: 'column',
    gap: 6,
  },
  resultRow: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: 13,
  },
  label: { color: '#94a3b8' },
  value: { color: '#e2e8f0', fontWeight: 600 },
  errorBox: {
    marginTop: 10,
    background: '#450a0a',
    border: '1px solid #7f1d1d',
    borderRadius: 6,
    color: '#fca5a5',
    padding: '8px 12px',
    fontSize: 12,
  },
};
