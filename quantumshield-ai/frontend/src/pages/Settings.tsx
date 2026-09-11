import { Settings as SettingsIcon, Info, Shield } from 'lucide-react'

export default function Settings() {
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000'
  const wsUrl = import.meta.env.VITE_WS_URL || 'ws://localhost:8000'

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-white flex items-center gap-3">
        <SettingsIcon className="text-qs-text-dim" size={24} />
        Settings
      </h1>

      <div className="qs-card">
        <h3 className="font-semibold text-white mb-4">Platform Configuration</h3>
        <div className="space-y-4">
          {[
            { label: 'Backend API URL', value: apiUrl, mono: true },
            { label: 'WebSocket URL', value: wsUrl, mono: true },
            { label: 'Platform Version', value: 'QuantumShield AI v1.0.0' },
          ].map(({ label, value, mono }) => (
            <div key={label} className="flex justify-between items-center py-2 border-b border-qs-border last:border-0">
              <span className="text-sm text-qs-text-dim">{label}</span>
              <span className={`text-sm text-qs-text ${mono ? 'font-mono text-qs-cyan' : ''}`}>{value}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="qs-card border-qs-blue/30 bg-qs-blue/5">
        <div className="flex gap-3">
          <Info size={20} className="text-qs-blue flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="font-semibold text-white mb-2">Configuration via Environment Variables</h3>
            <p className="text-sm text-qs-text-dim mb-3">
              Configure API keys and settings through the <code className="text-qs-cyan font-mono">.env</code> file in the project root.
            </p>
            <pre className="text-xs font-mono text-green-400 bg-qs-bg rounded p-3">
{`# LLM Provider (openai | anthropic | google | none)
LLM_PROVIDER=none
LLM_API_KEY=your_key_here
LLM_MODEL=gpt-4o-mini

# Database
DATABASE_URL=postgresql+asyncpg://...

# Lab Target
LAB_TARGET_URL=http://vulnerable-app:8080`}
            </pre>
          </div>
        </div>
      </div>

      <div className="qs-card border-red-500/30 bg-red-500/5">
        <div className="flex gap-3">
          <Shield size={20} className="text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="font-semibold text-red-400 mb-1">Security Policy Enforcement</h3>
            <p className="text-xs text-qs-text-dim">
              The PolicyEngine enforces strict scope boundaries. All security tests must target explicitly registered, authorized targets only. 
              The system blocks any action outside the defined scope, enforces rate limits, and prevents destructive tests unless explicitly enabled per-target.
              Never configure unauthorized external targets.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
