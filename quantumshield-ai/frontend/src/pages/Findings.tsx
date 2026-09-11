import { useEffect, useState } from 'react'
import { AlertTriangle, Filter, ChevronDown, ChevronUp } from 'lucide-react'
import { scansApi, findingsApi } from '../api/client'

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']

export default function Findings() {
  const [allFindings, setAllFindings] = useState<any[]>([])
  const [scans, setScans] = useState<any[]>([])
  const [filter, setFilter] = useState({ severity: '', type: '', status: '' })
  const [expanded, setExpanded] = useState<string | null>(null)
  const [details, setDetails] = useState<Record<string, any>>({})
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const loadAll = async () => {
      setLoading(true)
      const sc = await scansApi.list()
      setScans(sc)
      const allF: any[] = []
      for (const scan of sc) {
        const findings = await scansApi.getFindings(scan.id)
        allF.push(...findings.map((f: any) => ({ ...f, scan_name: scan.name })))
      }
      setAllFindings(allF.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)))
      setLoading(false)
    }
    loadAll().catch(console.error)
  }, [])

  const toggleExpand = async (id: string) => {
    if (expanded === id) { setExpanded(null); return }
    setExpanded(id)
    if (!details[id]) {
      try {
        const d = await findingsApi.get(id)
        setDetails(prev => ({ ...prev, [id]: d }))
      } catch {}
    }
  }

  const markFixed = async (id: string) => {
    await findingsApi.updateStatus(id, 'FIXED')
    setAllFindings(prev => prev.map(f => f.id === id ? { ...f, status: 'FIXED' } : f))
  }

  const filtered = allFindings.filter(f =>
    (!filter.severity || f.severity === filter.severity) &&
    (!filter.type || f.finding_type === filter.type) &&
    (!filter.status || f.status === filter.status)
  )

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">
          Findings <span className="text-qs-text-dim text-lg font-normal">({filtered.length})</span>
        </h1>
        <div className="flex gap-3 items-center">
          <Filter size={16} className="text-qs-text-dim" />
          {[
            { key: 'severity', options: ['', ...SEVERITY_ORDER], label: 'Severity' },
            { key: 'type', options: ['', 'CLASSICAL', 'QUANTUM'], label: 'Type' },
            { key: 'status', options: ['', 'OPEN', 'CONFIRMED', 'FIXED', 'FALSE_POSITIVE'], label: 'Status' },
          ].map(({ key, options, label }) => (
            <select
              key={key}
              className="qs-input w-auto text-xs"
              value={(filter as any)[key]}
              onChange={e => setFilter(f => ({ ...f, [key]: e.target.value }))}
            >
              <option value="">{label}: All</option>
              {options.filter(Boolean).map(o => <option key={o} value={o}>{o}</option>)}
            </select>
          ))}
        </div>
      </div>

      <div className="space-y-2">
        {loading ? (
          <div className="text-center py-16 text-qs-text-dim">Loading findings...</div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-16 text-qs-text-dim">
            <AlertTriangle size={48} className="mx-auto mb-4 opacity-20" />
            <p>No findings match the current filter.</p>
          </div>
        ) : (
          filtered.map(f => (
            <div key={f.id} className="qs-card p-0 overflow-hidden">
              <button
                className="w-full flex items-center gap-4 p-4 text-left hover:bg-qs-border/10 transition-all"
                onClick={() => toggleExpand(f.id)}
              >
                <span className={`text-xs px-2 py-1 rounded font-medium flex-shrink-0 severity-${f.severity?.toLowerCase()}`}>
                  {f.severity}
                </span>
                {f.finding_type === 'QUANTUM' && (
                  <span className="quantum-badge flex-shrink-0">⚛ QUANTUM</span>
                )}
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-white text-sm">{f.title}</div>
                  <div className="text-xs text-qs-text-dim mt-0.5">
                    {f.endpoint} • {f.scan_name} • Risk: {f.risk_score?.toFixed(0) || 0}
                  </div>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    f.status === 'CONFIRMED' || f.status === 'OPEN' ? 'status-confirmed' :
                    f.status === 'FIXED' ? 'status-fixed' : 'status-false-positive'
                  }`}>{f.status}</span>
                  {expanded === f.id ? <ChevronUp size={14} className="text-qs-text-dim" /> : <ChevronDown size={14} className="text-qs-text-dim" />}
                </div>
              </button>

              {expanded === f.id && details[f.id] && (
                <div className="border-t border-qs-border p-4 space-y-4">
                  <p className="text-sm text-qs-text-dim">{details[f.id].description}</p>

                  {details[f.id].remediation && (
                    <div className="bg-qs-surface rounded-lg p-4 space-y-2">
                      <div className="text-xs font-semibold text-qs-green uppercase tracking-wider">Remediation</div>
                      <p className="text-sm text-qs-text-dim">{details[f.id].remediation.explanation}</p>
                      {details[f.id].remediation.recommended_fix && (
                        <pre className="text-xs bg-qs-bg rounded p-3 overflow-x-auto text-green-400 font-mono">
                          {details[f.id].remediation.recommended_fix}
                        </pre>
                      )}
                    </div>
                  )}

                  {details[f.id].evidence?.length > 0 && (
                    <div>
                      <div className="text-xs font-semibold text-qs-blue uppercase tracking-wider mb-2">Evidence</div>
                      <div className="text-xs font-mono text-qs-text-dim bg-qs-surface rounded p-3">
                        {details[f.id].evidence[0].observation}
                      </div>
                    </div>
                  )}

                  <div className="flex gap-3">
                    {f.status !== 'FIXED' && (
                      <button onClick={() => markFixed(f.id)} className="text-xs qs-btn-secondary">
                        ✓ Mark as Fixed
                      </button>
                    )}
                    {f.status === 'FIXED' && (
                      <button
                        onClick={() => findingsApi.runRegression(f.id).then(() => alert('Regression test scheduled'))}
                        className="text-xs qs-btn-secondary"
                      >
                        ↺ Run Regression Test
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  )
}
