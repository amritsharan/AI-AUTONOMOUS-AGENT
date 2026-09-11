import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, FolderKanban, Trash2, ChevronRight } from 'lucide-react'
import { projectsApi } from '../api/client'

export default function Projects() {
  const [projects, setProjects] = useState<any[]>([])
  const [showCreate, setShowCreate] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [creating, setCreating] = useState(false)
  const navigate = useNavigate()

  useEffect(() => { projectsApi.list().then(setProjects).catch(console.error) }, [])

  const create = async () => {
    if (!name.trim()) return
    setCreating(true)
    try {
      const p = await projectsApi.create({ name, description })
      setProjects(prev => [p, ...prev])
      setShowCreate(false)
      setName(''); setDescription('')
    } catch (e) { console.error(e) }
    setCreating(false)
  }

  const del = async (id: string) => {
    if (!confirm('Delete this project? This cannot be undone.')) return
    await projectsApi.delete(id)
    setProjects(prev => prev.filter(p => p.id !== id))
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Projects</h1>
        <button onClick={() => setShowCreate(true)} className="qs-btn-primary">
          <Plus size={16} /> New Project
        </button>
      </div>

      {showCreate && (
        <div className="qs-card border-qs-blue/30">
          <h3 className="font-semibold text-white mb-4">Create New Project</h3>
          <div className="space-y-3">
            <input className="qs-input" placeholder="Project name" value={name} onChange={e => setName(e.target.value)} />
            <textarea className="qs-input resize-none h-20" placeholder="Description (optional)" value={description} onChange={e => setDescription(e.target.value)} />
            <div className="flex gap-3">
              <button onClick={create} disabled={creating} className="qs-btn-primary">
                {creating ? 'Creating...' : 'Create Project'}
              </button>
              <button onClick={() => setShowCreate(false)} className="qs-btn-secondary">Cancel</button>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {projects.map(p => (
          <div key={p.id} className="qs-card hover:border-qs-blue/30 transition-all group">
            <div className="flex items-start justify-between">
              <div className="w-10 h-10 bg-qs-blue/20 rounded-lg flex items-center justify-center">
                <FolderKanban size={20} className="text-qs-blue" />
              </div>
              <button onClick={() => del(p.id)} className="opacity-0 group-hover:opacity-100 text-qs-text-dim hover:text-qs-red transition-all">
                <Trash2 size={14} />
              </button>
            </div>
            <h3 className="font-semibold text-white mt-3">{p.name}</h3>
            <p className="text-sm text-qs-text-dim mt-1 line-clamp-2">{p.description || 'No description'}</p>
            <div className="flex items-center justify-between mt-4 pt-4 border-t border-qs-border">
              <span className="text-xs text-qs-text-dim">{new Date(p.created_at).toLocaleDateString()}</span>
              <button onClick={() => navigate(`/scans?project_id=${p.id}`)} className="flex items-center gap-1 text-xs text-qs-blue hover:underline">
                View Scans <ChevronRight size={12} />
              </button>
            </div>
          </div>
        ))}
        {projects.length === 0 && (
          <div className="col-span-3 text-center py-16 text-qs-text-dim">
            <FolderKanban size={48} className="mx-auto mb-4 opacity-20" />
            <p>No projects yet. Create your first project to get started.</p>
          </div>
        )}
      </div>
    </div>
  )
}
