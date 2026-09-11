import { useEffect, useState, useRef, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Activity, Shield, Atom, Clock, CheckCircle2, XCircle, AlertTriangle } from 'lucide-react'
import { scansApi, createScanWebSocket } from '../api/client'

interface ScanEvent {
  id?: string
  timestamp: string
  event_type: string
  agent?: string
  message: string
  state?: string
  result?: string
}

const STATE_COLORS: Record<string, string> = {
  OBSERVE: 'text-qs-cyan',
  ANALYZE: 'text-qs-blue',
  PLAN: 'text-qs-purple',
  POLICY_CHECK: 'text-yellow-400',
  EXECUTE: 'text-qs-orange',
  OBSERVE_RESULT: 'text-qs-cyan',
  UPDATE_STATE: 'text-qs-blue',
  VERIFY: 'text-qs-yellow',
  FINDING: 'text-qs-red',
  REMEDIATION: 'text-qs-green',
  REGRESSION: 'text-qs-purple',
  COMPLETE: 'text-qs-green',
  ERROR: 'text-qs-red',
}

const EVENT_ICONS: Record<string, any> = {
  finding_confirmed: AlertTriangle,
  scan_complete: CheckCircle2,
  error: XCircle,
  module_complete: CheckCircle2,
  quantum_complete: Atom,
  recon_complete: Shield,
}

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const [scan, setScan] = useState<any>(null)
  const [events, setEvents] = useState<ScanEvent[]>([])
  const [findings, setFindings] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const logRef = useRef<HTMLDivElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const loadScan = useCallback(async () => {
    if (!scanId) return
    try {
      const [s, evts, fnd] = await Promise.all([
        scansApi.get(scanId),
        scansApi.getEvents(scanId, 200),
        scansApi.getFindings(scanId),
      ])
      setScan(s)
      setEvents(evts)
      setFindings(fnd)
    } catch (e) {
      console.error(e)
    }
    setLoading(false)
  }, [scanId])

  useEffect(() => {
    loadScan()

    // WebSocket for live events
    if (scanId) {
      wsRef.current = createScanWebSocket(scanId, (data) => {
        if (data.type === 'agent_event') {
          setEvents(prev => [...prev, {
            timestamp: data.timestamp,
            event_type: data.event_type,
            agent: data.agent,
            message: data.message,
            state: data.state,
          }])
          // Also poll scan state
          scansApi.get(scanId).then(setScan).catch(() => {})
        }
      })

      // Polling fallback every 5s for scan status
      pollingRef.current = setInterval(loadScan, 5000)
    }

    return () => {
      wsRef.current?.close()
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [scanId, loadScan])

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [events])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="w-8 h-8 border-2 border-qs-blue border-t-transparent rounded-full spin" />
      </div>
    )
  }

  if (!scan) return <div className="p-6 text-qs-text-dim">Scan not found</div>

  const isRunning = scan.status === 'RUNNING'
  const progress = scan.total_tests > 0 ? (scan.completed_tests / scan.total_tests) * 100 : 0

  const severityCounts = findings.reduce((acc: any, f: any) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button onClick={() => navigate('/scans')} className="text-qs-text-dim hover:text-qs-text transition-colors">
          <ArrowLeft size={20} />
        </button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold text-white truncate">{scan.name}</h1>
            <span className={`px-2 py-0.5 rounded text-xs font-medium ${
              isRunning ? 'bg-qs-green/20 text-qs-green' :
              scan.status === 'COMPLETED' ? 'bg-qs-blue/20 text-qs-blue' :
              scan.status === 'FAILED' ? 'bg-qs-red/20 text-qs-red' :
              'bg-qs-text-dim/20 text-qs-text-dim'
            }`}>
              {isRunning && <span className="inline-block w-2 h-2 bg-qs-green rounded-full mr-1.5 animate-pulse" />}
              {scan.status}
            </span>
          </div>
          <p className="text-sm text-qs-text-dim">
            {scan.scan_type} scan • {scan.endpoints_discovered} endpoints • {scan.current_state && `State: ${scan.current_state}`}
          </p>
        </div>
      </div>

      {/* Progress bar */}
      {isRunning && (
        <div className="qs-card py-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-qs-text-dim">Scan Progress</span>
            <span className="text-sm font-mono text-qs-blue">{scan.completed_tests}/{scan.total_tests} tests</span>
          </div>
          <div className="h-2 bg-qs-border/30 rounded-full overflow-hidden">
            <div
              className="h-2 bg-gradient-to-r from-qs-blue to-qs-cyan rounded-full transition-all duration-500"
              style={{ width: `${Math.min(progress, 100)}%` }}
            />
          </div>
          <div className="flex items-center gap-2 mt-2">
            <Activity size={12} className="text-qs-green animate-pulse" />
            <span className="text-xs text-qs-text-dim">
              {events[events.length - 1]?.message || 'Initializing...'}
            </span>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Live Activity Log */}
        <div className="qs-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-white flex items-center gap-2">
              <Activity size={16} className="text-qs-green" />
              Live Agent Activity
            </h3>
            <span className="text-xs text-qs-text-dim font-mono">{events.length} events</span>
          </div>
          <div
            ref={logRef}
            className="h-96 overflow-y-auto space-y-1 font-mono text-xs pr-2"
          >
            {events.length === 0 ? (
              <div className="text-qs-text-dim text-center py-8">Waiting for events...</div>
            ) : (
              events.map((event, idx) => {
                const EventIcon = EVENT_ICONS[event.event_type] || Activity
                const stateColor = STATE_COLORS[event.state || ''] || 'text-qs-text-dim'
                const time = new Date(event.timestamp).toLocaleTimeString()
                return (
                  <div key={idx} className="flex gap-2 items-start hover:bg-qs-border/10 rounded px-1 py-0.5">
                    <span className="text-qs-text-dim flex-shrink-0 w-16">[{time.slice(0,8)}]</span>
                    <EventIcon size={10} className={`flex-shrink-0 mt-0.5 ${
                      event.event_type === 'finding_confirmed' ? 'text-qs-orange' :
                      event.event_type === 'scan_complete' ? 'text-qs-green' :
                      event.event_type === 'error' ? 'text-qs-red' :
                      'text-qs-text-dim'
                    }`} />
                    {event.state && (
                      <span className={`flex-shrink-0 ${stateColor}`}>[{event.state}]</span>
                    )}
                    <span className="text-qs-text leading-relaxed">{event.message}</span>
                  </div>
                )
              })
            )}
          </div>
        </div>

        {/* Findings */}
        <div className="qs-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-white flex items-center gap-2">
              <AlertTriangle size={16} className="text-qs-orange" />
              Findings ({findings.length})
            </h3>
            <div className="flex gap-2">
              {Object.entries(severityCounts).map(([sev, cnt]) => (
                <span key={sev} className={`text-xs px-1.5 py-0.5 rounded font-mono severity-${sev.toLowerCase()}`}>
                  {sev[0]}: {cnt as number}
                </span>
              ))}
            </div>
          </div>
          <div className="space-y-2 max-h-96 overflow-y-auto pr-2">
            {findings.length === 0 ? (
              <div className="text-center py-8 text-qs-text-dim">
                {isRunning ? 'Running tests...' : 'No findings'}
              </div>
            ) : (
              findings.map(f => (
                <div
                  key={f.id}
                  className="p-3 rounded-lg bg-qs-surface border border-qs-border hover:border-qs-border/60 transition-all cursor-pointer"
                  onClick={() => navigate(`/findings`)}
                >
                  <div className="flex items-start gap-3">
                    <span className={`text-xs px-1.5 py-0.5 rounded font-medium flex-shrink-0 severity-${f.severity?.toLowerCase()}`}>
                      {f.severity}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-qs-text truncate">{f.title}</div>
                      <div className="text-xs text-qs-text-dim truncate">{f.endpoint}</div>
                    </div>
                    {f.finding_type === 'QUANTUM' && (
                      <span className="quantum-badge flex-shrink-0">⚛ QUANTUM</span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Score Summary (when complete) */}
      {scan.status === 'COMPLETED' && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Security Score', value: scan.security_score, unit: '/100', color: 'text-qs-blue' },
            { label: 'Quantum Score', value: scan.quantum_score, unit: '/100', color: 'text-qs-purple' },
            { label: 'PQC Readiness', value: scan.pqc_readiness, unit: '%', color: 'text-qs-cyan' },
            { label: 'Crypto Assets', value: scan.quantum_assets_found, unit: '', color: 'text-qs-green' },
          ].map(({ label, value, unit, color }) => (
            <div key={label} className="qs-card text-center">
              <div className={`text-3xl font-bold font-mono ${color}`}>
                {value !== null && value !== undefined ? (typeof value === 'number' ? value.toFixed(0) : value) : '—'}
                <span className="text-sm text-qs-text-dim">{unit}</span>
              </div>
              <div className="text-xs text-qs-text-dim mt-1">{label}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
