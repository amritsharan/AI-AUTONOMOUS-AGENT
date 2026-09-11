import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Play, Plus, Clock, CheckCircle2, XCircle } from 'lucide-react'
import { scansApi, projectsApi, targetsApi } from '../api/client'

export default function Scans() {
  const [scans, setScans] = useState<any[]>([])
  const [projects, setProjects] = useState<any[]>([])
  const [targets, setTargets] = useState<any[]>([])
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ project_id: '', target_id: '', name: '', scan_type: 'full' })
  const [creating, setCreating] = useState(false)
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const projectFilter = searchParams.get('project_id')

  useEffect(() => {
    Promise.all([
      scansApi.list(projectFilter || undefined).then(setScans),
      projectsApi.list().then(setProjects),
      targetsApi.list().then(setTargets),
    ]).catch(console.error)
  }, [projectFilter])

  const create = async () => {
    if (!form.project_id || !form.target_id || !form.name) return
    setCreating(true)
    try {
      const scan = await scansApi.create(form)
      navigate(`/scans/${scan.id}`)
    } catch (e) { console.error(e) }
    setCreating(false)
  }

  const startDemoScan = async () => {
    if (projects.length === 0 || targets.length === 0) {
      alert('Please create a project and register the lab target first.')
      return
    }
    setForm({
      project_id: projects[0].id,
      target_id: targets[0].id,
      name: `Demo Scan ${new Date().toLocaleTimeString()}`,
      scan_type: 'full',
    })
    setShowCreate(true)
  }

  const StatusIcon = ({ status }: { status: string }) => {
    if (status === 'RUNNING') return <Clock size={14} className="text-qs-green animate-pulse" />
    if (status === 'COMPLETED') return <CheckCircle2 size={14} className="text-qs-blue" />
    if (status === 'FAILED') return <XCircle size={14} className="text-qs-red" />
    return <Clock size={14} className="text-qs-text-dim" />
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Scans</h1>
        <div className="flex gap-3">
          <button onClick={startDemoScan} className="qs-btn-secondary">
            <Play size={16} className="text-qs-green" /> Demo Scan
          </button>
          <button onClick={() => setShowCreate(true)} className="qs-btn-primary">
            <Plus size={16} /> New Scan
          </button>
        </div>
      </div>

      {showCreate && (
        <div className="qs-card border-qs-blue/30">
          <h3 className="font-semibold text-white mb-4">Configure Scan</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-qs-text-dim mb-1 block">Project</label>
              <select className="qs-input" value={form.project_id} onChange={e => setForm(f => ({...f, project_id: e.target.value}))}>
                <option value="">Select project...</option>
                {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-qs-text-dim mb-1 block">Target</label>
              <select className="qs-input" value={form.target_id} onChange={e => setForm(f => ({...f, target_id: e.target.value}))}>
                <option value="">Select target...</option>
                {targets.map(t => <option key={t.id} value={t.id}>{t.name} ({t.url})</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-qs-text-dim mb-1 block">Scan Name</label>
              <input className="qs-input" placeholder="Full Security Scan 1" value={form.name} onChange={e => setForm(f => ({...f, name: e.target.value}))} />
            </div>
            <div>
              <label className="text-xs text-qs-text-dim mb-1 block">Scan Type</label>
              <select className="qs-input" value={form.scan_type} onChange={e => setForm(f => ({...f, scan_type: e.target.value}))}>
                <option value="full">Full (Classical + Quantum)</option>
                <option value="classical">Classical Only</option>
                <option value="quantum">Quantum Only</option>
              </select>
            </div>
          </div>
          <div className="flex gap-3 mt-4">
            <button onClick={create} disabled={creating} className="qs-btn-primary">
              <Play size={16} /> {creating ? 'Starting...' : 'Start Scan'}
            </button>
            <button onClick={() => setShowCreate(false)} className="qs-btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      <div className="qs-card p-0 overflow-hidden">
        <table className="w-full">
          <thead className="bg-qs-surface">
            <tr>
              {['Name', 'Type', 'Status', 'Endpoints', 'Findings', 'Security Score', 'Quantum Score', 'Duration'].map(h => (
                <th key={h} className="text-left px-4 py-3 text-xs text-qs-text-dim font-medium uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-qs-border">
            {scans.map(scan => {
              const duration = scan.started_at && scan.completed_at
                ? `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 60000)}m`
                : scan.status === 'RUNNING' ? 'Running...' : '—'
              return (
                <tr
                  key={scan.id}
                  className="hover:bg-qs-border/10 transition-colors cursor-pointer"
                  onClick={() => navigate(`/scans/${scan.id}`)}
                >
                  <td className="px-4 py-3 text-sm font-medium text-white">{scan.name}</td>
                  <td className="px-4 py-3 text-xs text-qs-text-dim uppercase">{scan.scan_type}</td>
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-1.5">
                      <StatusIcon status={scan.status} />
                      <span className="text-xs text-qs-text">{scan.status}</span>
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm font-mono text-qs-cyan">{scan.endpoints_discovered}</td>
                  <td className="px-4 py-3 text-sm font-mono text-qs-orange">—</td>
                  <td className="px-4 py-3 text-sm font-mono text-qs-blue">
                    {scan.security_score ? `${Math.round(scan.security_score)}/100` : '—'}
                  </td>
                  <td className="px-4 py-3 text-sm font-mono text-qs-purple">
                    {scan.quantum_score ? `${Math.round(scan.quantum_score)}/100` : '—'}
                  </td>
                  <td className="px-4 py-3 text-xs text-qs-text-dim font-mono">{duration}</td>
                </tr>
              )
            })}
            {scans.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-16 text-center text-qs-text-dim">
                  No scans yet. Start a demo scan to see it in action.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
