import { useEffect, useState } from 'react'
import { Plus, Target as TargetIcon, Globe, Shield } from 'lucide-react'
import { targetsApi, projectsApi } from '../api/client'

export default function Targets() {
  const [targets, setTargets] = useState<any[]>([])
  const [projects, setProjects] = useState<any[]>([])
  const [showCreate, setShowCreate] = useState(false)
  const [labDefault, setLabDefault] = useState<any>(null)
  const [form, setForm] = useState({
    project_id: '', name: '', url: '', environment: 'lab',
    max_requests_per_minute: 60, destructive_tests: false
  })
  const [creating, setCreating] = useState(false)

  useEffect(() => {
    Promise.all([
      targetsApi.list().then(setTargets),
      projectsApi.list().then(setProjects),
      targetsApi.getLabDefault().then(setLabDefault).catch(() => {})
    ]).catch(console.error)
  }, [])

  const create = async () => {
    setCreating(true)
    try {
      const t = await targetsApi.create(form)
      setTargets(prev => [t, ...prev])
      setShowCreate(false)
    } catch (e) { console.error(e) }
    setCreating(false)
  }

  const loadLabTarget = () => {
    if (!labDefault || projects.length === 0) return
    setForm(f => ({
      ...f,
      project_id: projects[0].id,
      name: 'Vulnerable Lab (QuantumShield Demo)',
      url: labDefault.url,
      environment: 'lab',
    }))
    setShowCreate(true)
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Targets</h1>
        <div className="flex gap-3">
          <button onClick={loadLabTarget} className="qs-btn-secondary">
            <Shield size={16} /> Load Lab Target
          </button>
          <button onClick={() => setShowCreate(true)} className="qs-btn-primary">
            <Plus size={16} /> Add Target
          </button>
        </div>
      </div>

      {labDefault && (
        <div className="qs-card border-green-500/30 bg-green-500/5">
          <div className="flex items-center gap-3">
            <Shield size={20} className="text-green-400" />
            <div>
              <div className="font-medium text-white">Security Lab Available</div>
              <div className="text-sm text-qs-text-dim">Lab URL: <span className="font-mono text-green-400">{labDefault.url}</span></div>
            </div>
            <button onClick={loadLabTarget} className="ml-auto text-xs text-green-400 hover:underline">
              Register Lab Target →
            </button>
          </div>
        </div>
      )}

      {showCreate && (
        <div className="qs-card border-qs-blue/30">
          <h3 className="font-semibold text-white mb-4">Register Target</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-qs-text-dim mb-1 block">Project</label>
              <select className="qs-input" value={form.project_id} onChange={e => setForm(f => ({...f, project_id: e.target.value}))}>
                <option value="">Select project...</option>
                {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-qs-text-dim mb-1 block">Target Name</label>
              <input className="qs-input" placeholder="My Lab App" value={form.name} onChange={e => setForm(f => ({...f, name: e.target.value}))} />
            </div>
            <div>
              <label className="text-xs text-qs-text-dim mb-1 block">Target URL</label>
              <input className="qs-input font-mono" placeholder="http://vulnerable-app:8080" value={form.url} onChange={e => setForm(f => ({...f, url: e.target.value}))} />
            </div>
            <div>
              <label className="text-xs text-qs-text-dim mb-1 block">Environment</label>
              <select className="qs-input" value={form.environment} onChange={e => setForm(f => ({...f, environment: e.target.value}))}>
                <option value="lab">Lab</option>
                <option value="staging">Staging</option>
              </select>
            </div>
          </div>
          <div className="flex gap-3 mt-4">
            <button onClick={create} disabled={creating} className="qs-btn-primary">
              {creating ? 'Registering...' : 'Register Target'}
            </button>
            <button onClick={() => setShowCreate(false)} className="qs-btn-secondary">Cancel</button>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {targets.map(t => (
          <div key={t.id} className="qs-card flex items-center gap-4 hover:border-qs-border/60 transition-all">
            <div className="w-10 h-10 bg-qs-cyan/10 rounded-lg flex items-center justify-center flex-shrink-0">
              <Globe size={20} className="text-qs-cyan" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="font-medium text-white">{t.name}</div>
              <div className="text-sm font-mono text-qs-text-dim truncate">{t.url}</div>
            </div>
            <div className="flex items-center gap-4 flex-shrink-0">
              <span className={`text-xs px-2 py-0.5 rounded ${
                t.environment === 'lab' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'
              }`}>{t.environment}</span>
              <span className={`text-xs px-2 py-0.5 rounded ${t.is_authorized ? 'bg-qs-blue/20 text-qs-blue' : 'bg-qs-red/20 text-qs-red'}`}>
                {t.is_authorized ? '✓ Authorized' : '✗ Unauthorized'}
              </span>
              <span className="text-xs text-qs-text-dim">{t.max_requests_per_minute} req/min</span>
            </div>
          </div>
        ))}
        {targets.length === 0 && (
          <div className="text-center py-16 text-qs-text-dim">
            <TargetIcon size={48} className="mx-auto mb-4 opacity-20" />
            <p>No targets registered. Register the lab target to begin scanning.</p>
          </div>
        )}
      </div>
    </div>
  )
}
