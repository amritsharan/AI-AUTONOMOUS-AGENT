import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Atom, AlertTriangle, Activity, Server,
  TrendingUp, ChevronRight, Zap, Lock, Eye, Play
} from 'lucide-react'
import { RadialBarChart, RadialBar, ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts'
import { projectsApi, dashboardApi, scansApi } from '../api/client'

interface ScoreRingProps {
  score: number | null
  label: string
  color: string
  size?: number
}

function ScoreRing({ score, label, color, size = 120 }: ScoreRingProps) {
  const s = score ?? 0
  const r = (size / 2) - 10
  const circumference = 2 * Math.PI * r
  const offset = circumference - (s / 100) * circumference

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size}>
          <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
          <circle
            cx={size/2} cy={size/2} r={r} fill="none"
            stroke={color} strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            transform={`rotate(-90 ${size/2} ${size/2})`}
            style={{ transition: 'stroke-dashoffset 1s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-white">
            {score !== null ? Math.round(score) : '—'}
          </span>
          <span className="text-xs text-qs-text-dim">/100</span>
        </div>
      </div>
      <span className="text-xs text-qs-text-dim font-medium">{label}</span>
    </div>
  )
}

function SeverityBar({ label, count, color, max }: { label: string; count: number; color: string; max: number }) {
  const pct = max > 0 ? (count / max) * 100 : 0
  return (
    <div className="flex items-center gap-3">
      <span className={`text-xs font-medium w-20 ${color}`}>{label}</span>
      <div className="flex-1 bg-qs-border/30 rounded-full h-1.5">
        <div className="h-1.5 rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: color.replace('text-', '') }} />
      </div>
      <span className="text-xs font-mono text-qs-text-dim w-6 text-right">{count}</span>
    </div>
  )
}

export default function Dashboard() {
  const [projects, setProjects] = useState<any[]>([])
  const [selectedProject, setSelectedProject] = useState<any>(null)
  const [dashboard, setDashboard] = useState<any>(null)
  const [recentScans, setRecentScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      const projs = await projectsApi.list()
      setProjects(projs)
      if (projs.length > 0) {
        setSelectedProject(projs[0])
        const dash = await dashboardApi.getProjectDashboard(projs[0].id)
        setDashboard(dash)
      }
      const scans = await scansApi.list()
      setRecentScans(scans.slice(0, 5))
    } catch (e) {
      console.error('Dashboard load error:', e)
    }
    setLoading(false)
  }

  const classical = dashboard?.classical_security || {}
  const quantum = dashboard?.quantum_security || {}
  const stats = dashboard?.scan_statistics || {}
  const findings = classical.findings_by_severity || {}
  const maxFindings = Math.max(findings.critical || 0, findings.high || 0, findings.medium || 0, findings.low || 0, 1)

  const trendData = (dashboard?.finding_trends || []).map((t: any) => ({
    name: t.scan_name?.slice(0, 12) || '',
    classical: t.security_score || 0,
    quantum: t.quantum_score || 0,
  }))

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-qs-text-dim text-sm mt-1">
            {selectedProject ? `Project: ${selectedProject.name}` : 'No project selected'}
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => navigate('/scans')}
            className="qs-btn-primary"
          >
            <Play size={16} />
            New Scan
          </button>
          <button
            onClick={loadData}
            className="qs-btn-secondary"
          >
            <Activity size={16} />
            Refresh
          </button>
        </div>
      </div>

      {/* Quick setup banner if no project */}
      {!loading && projects.length === 0 && (
        <div className="qs-card border-qs-blue/30 bg-qs-blue/5">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-qs-blue/20 rounded-xl flex items-center justify-center">
              <Zap size={24} className="text-qs-blue" />
            </div>
            <div>
              <h3 className="font-semibold text-white">Get Started with QuantumShield AI</h3>
              <p className="text-qs-text-dim text-sm">Create a project and register the security lab target to begin scanning.</p>
            </div>
            <button onClick={() => navigate('/projects')} className="ml-auto qs-btn-primary">
              Create Project <ChevronRight size={16} />
            </button>
          </div>
        </div>
      )}

      {/* Score Cards Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Classical Security */}
        <div className="qs-card glow-blue hover:border-qs-blue/40 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="text-qs-text-dim text-xs uppercase tracking-wider">Classical Security</div>
              <div className="font-semibold text-white mt-1">Application Score</div>
            </div>
            <Shield size={24} className="text-qs-blue" />
          </div>
          <div className="flex justify-center my-4">
            <ScoreRing score={classical.score ?? null} label="Security Score" color="#3b82f6" />
          </div>
          <div className="space-y-2 mt-4">
            <SeverityBar label="Critical" count={findings.critical || 0} color="#ef4444" max={maxFindings} />
            <SeverityBar label="High" count={findings.high || 0} color="#f97316" max={maxFindings} />
            <SeverityBar label="Medium" count={findings.medium || 0} color="#f59e0b" max={maxFindings} />
            <SeverityBar label="Low" count={findings.low || 0} color="#3b82f6" max={maxFindings} />
          </div>
          <div className="mt-4 pt-4 border-t border-qs-border grid grid-cols-2 gap-3 text-center">
            <div>
              <div className="text-lg font-bold text-white">{classical.confirmed_findings || 0}</div>
              <div className="text-xs text-qs-text-dim">Confirmed</div>
            </div>
            <div>
              <div className="text-lg font-bold text-qs-green">{classical.detection_rate || 0}%</div>
              <div className="text-xs text-qs-text-dim">Detection Rate</div>
            </div>
          </div>
        </div>

        {/* Quantum Security */}
        <div className="qs-card glow-purple hover:border-qs-purple/40 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="text-qs-text-dim text-xs uppercase tracking-wider">Quantum Security</div>
              <div className="font-semibold text-white mt-1">Crypto Risk Assessment</div>
            </div>
            <Atom size={24} className="text-qs-purple" />
          </div>
          <div className="flex justify-center my-4">
            <ScoreRing score={quantum.score ?? null} label="Quantum Score" color="#8b5cf6" />
          </div>
          <div className="space-y-3 mt-4">
            <div className="flex justify-between items-center">
              <span className="text-xs text-qs-text-dim">PQC Readiness</span>
              <div className="flex items-center gap-2">
                <div className="w-24 h-1.5 bg-qs-border/30 rounded-full">
                  <div className="h-1.5 bg-qs-purple rounded-full" style={{ width: `${quantum.pqc_readiness || 0}%` }} />
                </div>
                <span className="text-xs font-mono text-qs-purple">{quantum.pqc_readiness?.toFixed(0) || 0}%</span>
              </div>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-xs text-qs-text-dim">Quantum Assets</span>
              <span className="text-xs font-mono text-qs-text">{quantum.quantum_assets_total || 0}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-xs text-qs-text-dim">Shor Vulnerable</span>
              <span className="text-xs font-mono text-qs-orange">{quantum.shor_vulnerable_assets || 0}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-xs text-qs-text-dim">Quantum Findings</span>
              <span className="text-xs font-mono text-qs-purple">{quantum.quantum_findings || 0}</span>
            </div>
          </div>
          <div className="mt-4">
            <button onClick={() => navigate('/quantum')} className="w-full qs-btn-secondary text-sm justify-center">
              <Atom size={14} />
              Open Quantum Center
            </button>
          </div>
        </div>

        {/* Scan Statistics */}
        <div className="qs-card hover:border-qs-border/60 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="text-qs-text-dim text-xs uppercase tracking-wider">Scan Statistics</div>
              <div className="font-semibold text-white mt-1">Latest Scan Metrics</div>
            </div>
            <Activity size={24} className="text-qs-cyan" />
          </div>
          <div className="space-y-4 mt-2">
            {[
              { label: 'Endpoints Discovered', value: stats.total_endpoints || 0, color: 'text-qs-cyan' },
              { label: 'Tests Executed', value: stats.total_tests || 0, color: 'text-qs-blue' },
              { label: 'Completed Tests', value: stats.completed_tests || 0, color: 'text-qs-green' },
              { label: 'Total Scans', value: stats.total_scans || 0, color: 'text-qs-text' },
              { label: 'Completed Scans', value: stats.completed_scans || 0, color: 'text-qs-green' },
            ].map(({ label, value, color }) => (
              <div key={label} className="flex justify-between items-center">
                <span className="text-xs text-qs-text-dim">{label}</span>
                <span className={`text-sm font-bold font-mono ${color}`}>{value}</span>
              </div>
            ))}
          </div>
          {dashboard?.latest_scan && (
            <div className="mt-4 pt-4 border-t border-qs-border">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${
                  dashboard.latest_scan.status === 'RUNNING' ? 'bg-qs-green animate-pulse' :
                  dashboard.latest_scan.status === 'COMPLETED' ? 'bg-qs-blue' : 'bg-qs-text-dim'
                }`} />
                <span className="text-xs text-qs-text-dim">
                  Latest: <span className="text-qs-text">{dashboard.latest_scan.status}</span>
                </span>
                {dashboard.latest_scan.duration && (
                  <span className="text-xs text-qs-text-dim ml-auto">{dashboard.latest_scan.duration}</span>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Trend Chart */}
      {trendData.length > 0 && (
        <div className="qs-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-white">Security Score Trends</h3>
            <TrendingUp size={18} className="text-qs-text-dim" />
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={trendData}>
              <defs>
                <linearGradient id="blueGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="purpleGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <YAxis domain={[0, 100]} tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1a2035', border: '1px solid #1e2d40', borderRadius: '8px' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Area type="monotone" dataKey="classical" stroke="#3b82f6" fill="url(#blueGrad)" strokeWidth={2} name="Classical" />
              <Area type="monotone" dataKey="quantum" stroke="#8b5cf6" fill="url(#purpleGrad)" strokeWidth={2} name="Quantum" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent Scans */}
      <div className="qs-card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold text-white">Recent Scans</h3>
          <button onClick={() => navigate('/scans')} className="text-xs text-qs-blue hover:text-qs-blue/80 flex items-center gap-1">
            View all <ChevronRight size={14} />
          </button>
        </div>
        {recentScans.length === 0 ? (
          <div className="text-center py-8 text-qs-text-dim">
            <Server size={32} className="mx-auto mb-2 opacity-30" />
            <p className="text-sm">No scans yet. Start your first scan!</p>
          </div>
        ) : (
          <div className="space-y-2">
            {recentScans.map(scan => (
              <button
                key={scan.id}
                onClick={() => navigate(`/scans/${scan.id}`)}
                className="w-full flex items-center gap-4 p-3 rounded-lg bg-qs-surface hover:bg-qs-border/20 transition-all group"
              >
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                  scan.status === 'RUNNING' ? 'bg-qs-green animate-pulse' :
                  scan.status === 'COMPLETED' ? 'bg-qs-blue' :
                  scan.status === 'FAILED' ? 'bg-qs-red' : 'bg-qs-text-dim'
                }`} />
                <div className="flex-1 text-left min-w-0">
                  <div className="text-sm font-medium text-qs-text truncate">{scan.name}</div>
                  <div className="text-xs text-qs-text-dim">{scan.scan_type} • {scan.endpoints_discovered} endpoints</div>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  {scan.security_score && (
                    <div className="text-xs font-mono">
                      <span className="text-qs-blue">{Math.round(scan.security_score)}</span>
                      <span className="text-qs-text-dim">/100</span>
                    </div>
                  )}
                  <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                    scan.status === 'COMPLETED' ? 'bg-qs-blue/20 text-qs-blue' :
                    scan.status === 'RUNNING' ? 'bg-qs-green/20 text-qs-green' :
                    scan.status === 'FAILED' ? 'bg-qs-red/20 text-qs-red' :
                    'bg-qs-text-dim/20 text-qs-text-dim'
                  }`}>{scan.status}</span>
                  <ChevronRight size={14} className="text-qs-text-dim group-hover:text-qs-text" />
                </div>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
