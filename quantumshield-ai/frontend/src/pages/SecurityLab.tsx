import { useEffect, useState } from 'react'
import { FlaskConical, ExternalLink, Shield, Bug } from 'lucide-react'
import axios from 'axios'

const LAB_URL = 'http://localhost:8080'

export default function SecurityLab() {
  const [knownVulns, setKnownVulns] = useState<any[]>([])
  const [labStatus, setLabStatus] = useState<'online' | 'offline' | 'checking'>('checking')

  useEffect(() => {
    axios.get(`${LAB_URL}/api/known-vulnerabilities`, { timeout: 3000 })
      .then(r => { setKnownVulns(r.data); setLabStatus('online') })
      .catch(() => setLabStatus('offline'))
  }, [])

  const severityColor: Record<string, string> = {
    CRITICAL: 'text-red-400 bg-red-500/20',
    HIGH: 'text-orange-400 bg-orange-500/20',
    MEDIUM: 'text-yellow-400 bg-yellow-500/20',
    LOW: 'text-blue-400 bg-blue-500/20',
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <FlaskConical className="text-green-400" size={28} />
            Security Lab
          </h1>
          <p className="text-qs-text-dim text-sm mt-1">
            Intentionally vulnerable lab application — authorized target for testing only.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs ${
            labStatus === 'online' ? 'bg-green-500/20 text-green-400' :
            labStatus === 'offline' ? 'bg-red-500/20 text-red-400' :
            'bg-yellow-500/20 text-yellow-400'
          }`}>
            <div className={`w-2 h-2 rounded-full ${labStatus === 'online' ? 'bg-green-400 animate-pulse' : 'bg-qs-text-dim'}`} />
            Lab {labStatus === 'checking' ? 'Checking...' : labStatus}
          </div>
          <a
            href={LAB_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="qs-btn-secondary text-xs"
          >
            <ExternalLink size={14} /> Open Lab
          </a>
        </div>
      </div>

      <div className="qs-card border-red-500/30 bg-red-500/5">
        <div className="flex items-start gap-3">
          <Shield size={20} className="text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold text-red-400">Security Authorization Boundary</div>
            <div className="text-xs text-qs-text-dim mt-1">
              This lab is an intentionally vulnerable Docker application for authorized security testing ONLY. 
              It contains deliberate vulnerabilities including SQL injection, IDOR, XSS, and weak cryptography.
              Never use QuantumShield AI against unauthorized targets.
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="qs-card">
          <h3 className="font-semibold text-white mb-4 flex items-center gap-2">
            <Bug size={16} className="text-qs-orange" />
            Lab Endpoints
          </h3>
          <div className="space-y-2 text-xs font-mono">
            {[
              { path: '/api/products', method: 'GET', vuln: 'SQL Injection' },
              { path: '/api/search', method: 'GET', vuln: 'XSS + SSTI' },
              { path: '/api/auth/login', method: 'POST', vuln: 'Weak Auth' },
              { path: '/api/users/{id}', method: 'GET', vuln: 'IDOR' },
              { path: '/api/orders/{id}', method: 'GET', vuln: 'IDOR' },
              { path: '/api/admin/stats', method: 'GET', vuln: 'Missing AuthZ' },
              { path: '/api/users/me', method: 'PUT', vuln: 'Mass Assignment' },
              { path: '/api/crypto/config', method: 'GET', vuln: 'Crypto Disclosure' },
            ].map(({ path, method, vuln }) => (
              <div key={path} className="flex items-center gap-3 p-2 bg-qs-surface rounded">
                <span className={`w-12 text-center px-1 py-0.5 rounded text-xs font-bold ${
                  method === 'GET' ? 'bg-blue-500/20 text-blue-400' :
                  method === 'POST' ? 'bg-green-500/20 text-green-400' :
                  'bg-orange-500/20 text-orange-400'
                }`}>{method}</span>
                <span className="flex-1 text-qs-text">{path}</span>
                <span className="text-qs-text-dim text-xs">{vuln}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="qs-card">
          <h3 className="font-semibold text-white mb-4 flex items-center gap-2">
            <Shield size={16} className="text-qs-purple" />
            Known Vulnerabilities
            {labStatus === 'online' && <span className="text-xs text-qs-text-dim font-normal">({knownVulns.length} loaded from lab)</span>}
          </h3>
          {labStatus === 'offline' ? (
            <div className="text-center py-8 text-qs-text-dim">
              <div className="text-sm">Lab is offline. Start Docker Compose to load vulnerabilities.</div>
              <code className="block mt-3 text-xs bg-qs-surface p-2 rounded font-mono">docker-compose up -d</code>
            </div>
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto pr-2">
              {knownVulns.map((v: any) => (
                <div key={v.id} className="p-2 bg-qs-surface rounded">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-1.5 py-0.5 rounded ${severityColor[v.severity] || 'text-qs-text-dim'}`}>
                      {v.severity}
                    </span>
                    <span className="text-sm font-medium text-white">{v.type}</span>
                  </div>
                  <div className="text-xs text-qs-text-dim mt-1">{v.endpoint}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="qs-card">
        <h3 className="font-semibold text-white mb-3">Lab Test Credentials</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
          {[
            { user: 'alice', pass: 'Alice@123', role: 'Regular User' },
            { user: 'bob', pass: 'Bob@456', role: 'Regular User' },
            { user: 'charlie', pass: 'Charlie@789', role: 'Regular User' },
          ].map(({ user, pass, role }) => (
            <div key={user} className="bg-qs-surface rounded-lg p-3">
              <div className="text-qs-text-dim text-xs uppercase mb-2">{role}</div>
              <div className="text-qs-cyan">{user}</div>
              <div className="text-qs-text-dim">{pass}</div>
            </div>
          ))}
        </div>
        <p className="text-xs text-qs-text-dim mt-3">These credentials are only valid against the local lab application.</p>
      </div>
    </div>
  )
}
