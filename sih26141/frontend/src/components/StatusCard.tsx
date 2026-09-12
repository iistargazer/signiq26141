import type { ScenarioResult } from '../api'
import type { LiveScenario } from '../App'

interface Props {
  title: string
  progress?: LiveScenario
  result?: ScenarioResult
  streaming?: boolean
}

export function StatusCard({ title, progress, result, streaming }: Props) {
  const authentic = result?.is_authentic
  const stateClass = result ? (authentic ? 'card-green' : 'card-red') : streaming ? 'card-live' : ''
  const qber = result ? result.qber : progress?.qber ?? null
  const threshold = result ? result.dynamic_threshold : progress?.threshold ?? null

  return (
    <div className={`status-card ${stateClass}`}>
      <div className="card-head">
        <h3>{title}</h3>
        <span className={`chip ${result ? (authentic ? 'chip-green' : 'chip-red') : 'chip-gray'}`}>
          {result ? (authentic ? '✓ AUTHENTIC' : '✗ THREAT FLAGGED') : streaming ? 'streaming…' : 'idle'}
        </span>
      </div>

      {progress && !result && (
        <div className="card-progress">
          <div className="bar-track">
            <div
              className="bar-fill"
              style={{
                width: `${progress.total > 0 ? Math.round((progress.processed / progress.total) * 100) : 0}%`,
              }}
            />
          </div>
          <div className="card-progress-text">
            qubit {progress.processed.toLocaleString()} / {progress.total.toLocaleString()} ·{' '}
            {progress.sifted.toLocaleString()} sifted
          </div>
        </div>
      )}

      <div className="card-metrics">
        <div className="metric">
          <div className="metric-value">{qber === null ? '—' : `${(qber * 100).toFixed(2)}%`}</div>
          <div className="metric-label">Measured QBER</div>
        </div>
        <div className="metric">
          <div className="metric-value">{threshold === null ? '—' : `${(threshold * 100).toFixed(2)}%`}</div>
          <div className="metric-label">Dynamic threshold</div>
        </div>
        <div className="metric">
          <div className="metric-value">{result ? result.sifted_key_length.toLocaleString() : '—'}</div>
          <div className="metric-label">Sifted key bits</div>
        </div>
      </div>

      {result && !authentic && (
        <div className="card-alert">
          Eavesdropping detected — QBER exceeds the finite-key bound. Key distillation aborted.
        </div>
      )}
    </div>
  )
}
