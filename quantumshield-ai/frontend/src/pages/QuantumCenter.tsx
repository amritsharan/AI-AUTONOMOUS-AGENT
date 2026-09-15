import { useState, useEffect } from 'react'
import {
  Atom,
  Zap,
  Lock,
  Cpu,
  Shield,
  Activity,
  Key,
  Layers,
  ArrowRight,
  Info,
  CheckCircle2,
  AlertTriangle,
  Server,
  BarChart3,
  Sliders,
  ChevronRight,
  Radio,
  Share2,
  Eye,
  EyeOff,
  Hash,
  Gauge
} from 'lucide-react'
import { quantumApi } from '../api/client'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  Legend,
} from 'recharts'

export default function QuantumCenter() {
  const [activeTab, setActiveTab] = useState<
    'hardware-lab' | 'simon' | 'qpe' | 'qkd' | 'pqc-shield' | 'shor' | 'grover' | 'pqc' | 'algo'
  >('hardware-lab')

  // Hardware Lab State
  const [backends, setBackends] = useState<any[]>([])
  const [selectedBackend, setSelectedBackend] = useState<string>('ibm_brisbane')
  const [labAlgorithm, setLabAlgorithm] = useState<'shor' | 'grover'>('shor')
  const [shorN, setShorN] = useState<number>(15)
  const [shots, setShots] = useState<number>(4096)
  const [ibmToken, setIbmToken] = useState<string>('')
  const [hasIbmToken, setHasIbmToken] = useState<boolean>(false)
  const [showTokenModal, setShowTokenModal] = useState<boolean>(false)

  const [benchmarkLoading, setBenchmarkLoading] = useState<boolean>(false)
  const [benchmarkResult, setBenchmarkResult] = useState<any>(null)

  // Phase 2: Simon's Algorithm State
  const [simonString, setSimonString] = useState<string>('101')
  const [simonResult, setSimonResult] = useState<any>(null)
  const [simonLoading, setSimonLoading] = useState<boolean>(false)

  // Phase 2: QPE State
  const [qpeTheta, setQpeTheta] = useState<number>(0.375)
  const [qpePrecision, setQpePrecision] = useState<number>(4)
  const [qpeResult, setQpeResult] = useState<any>(null)
  const [qpeLoading, setQpeLoading] = useState<boolean>(false)

  // Phase 2: QKD State
  const [qkdMode, setQkdMode] = useState<'bb84' | 'e91'>('bb84')
  const [qkdPhotons, setQkdPhotons] = useState<number>(100)
  const [qkdEvePresent, setQkdEvePresent] = useState<boolean>(false)
  const [qkdEveIntercept, setQkdEveIntercept] = useState<number>(1.0)
  const [qkdNoise, setQkdNoise] = useState<number>(0.02)
  const [qkdBB84Result, setQkdBB84Result] = useState<any>(null)
  const [qkdE91Result, setQkdE91Result] = useState<any>(null)
  const [qkdLoading, setQkdLoading] = useState<boolean>(false)

  // Grover state
  const [groverSize, setGroverSize] = useState<number>(16)
  const [groverResult, setGroverResult] = useState<any>(null)
  const [groverLoading, setGroverLoading] = useState<boolean>(false)

  // PQC Shield State
  const [shieldMessage, setShieldMessage] = useState<string>('Confidential Corporate Financial Ledger & Auth Payload')
  const [shieldMode, setShieldMode] = useState<string>('hybrid')
  const [shieldResult, setShieldResult] = useState<any>(null)
  const [shieldLoading, setShieldLoading] = useState<boolean>(false)

  // Standards and Alg DB
  const [pqcStandards, setPqcStandards] = useState<any>(null)
  const [algoDb, setAlgoDb] = useState<any>(null)

  useEffect(() => {
    fetchBackends()
    quantumApi.getPQCStandards().then(setPqcStandards).catch(console.error)
    quantumApi.getAlgorithms().then(setAlgoDb).catch(console.error)
  }, [])

  const fetchBackends = async () => {
    try {
      const data = await quantumApi.getBackends()
      setBackends(data.backends || [])
      setHasIbmToken(data.has_ibm_token || false)
      if (data.backends && data.backends.length > 0) {
        setSelectedBackend(data.backends[0].name)
      }
    } catch (e) {
      console.error('Failed to fetch backends:', e)
    }
  }

  const handleSaveToken = async () => {
    try {
      const res = await quantumApi.setIbmToken(ibmToken)
      setHasIbmToken(res.has_ibm_token)
      setShowTokenModal(false)
      fetchBackends()
    } catch (e) {
      console.error(e)
    }
  }

  const runComparativeHardwareBenchmark = async () => {
    setBenchmarkLoading(true)
    try {
      const data = await quantumApi.compareModes(shorN, selectedBackend, shots)
      setBenchmarkResult(data)
    } catch (e) {
      console.error('Hardware benchmark failed:', e)
    }
    setBenchmarkLoading(false)
  }

  const runSimon = async () => {
    setSimonLoading(true)
    try {
      const data = await quantumApi.simonDemo(simonString)
      setSimonResult(data)
    } catch (e) {
      console.error(e)
    }
    setSimonLoading(false)
  }

  const runQPE = async () => {
    setQpeLoading(true)
    try {
      const data = await quantumApi.qpeDemo(qpeTheta, qpePrecision)
      setQpeResult(data)
    } catch (e) {
      console.error(e)
    }
    setQpeLoading(false)
  }

  const runQKD = async () => {
    setQkdLoading(true)
    try {
      if (qkdMode === 'bb84') {
        const data = await quantumApi.qkdBB84(qkdPhotons, qkdEvePresent, qkdEveIntercept, qkdNoise)
        setQkdBB84Result(data)
      } else {
        const data = await quantumApi.qkdE91(qkdPhotons * 2, qkdEvePresent)
        setQkdE91Result(data)
      }
    } catch (e) {
      console.error(e)
    }
    setQkdLoading(false)
  }

  const runGrover = async () => {
    setGroverLoading(true)
    try {
      const data = await quantumApi.groverDemo(groverSize)
      setGroverResult(data)
    } catch (e) {
      console.error(e)
    }
    setGroverLoading(false)
  }

  const runPQCShieldTest = async () => {
    setShieldLoading(true)
    try {
      const data = await quantumApi.testPQCShield(shieldMessage, shieldMode)
      setShieldResult(data)
    } catch (e) {
      console.error(e)
    }
    setShieldLoading(false)
  }

  const currentBackendInfo = backends.find(b => b.name === selectedBackend) || backends[0]

  const getComparativeChartData = () => {
    if (!benchmarkResult || !benchmarkResult.comparative_results) return []
    const ideal = benchmarkResult.comparative_results.ideal?.counts || {}
    const noisy = benchmarkResult.comparative_results.noisy?.counts || {}
    const realQpu = benchmarkResult.comparative_results.real_qpu?.counts || {}

    const allKeys = Array.from(new Set([...Object.keys(ideal), ...Object.keys(noisy), ...Object.keys(realQpu)])).sort()

    return allKeys.map(key => ({
      state: `|${key}⟩`,
      Ideal: ideal[key] || 0,
      Noisy: noisy[key] || 0,
      RealQPU: realQpu[key] || 0,
    })).slice(0, 8)
  }

  const comparativeChartData = getComparativeChartData()

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-qs-card via-qs-surface to-qs-card border border-qs-border rounded-xl p-6 shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-qs-purple/20 border border-qs-purple/40 rounded-lg text-qs-purple">
              <Cpu size={28} className="animate-pulse" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
                Quantum Hardware Lab & Security Engine
              </h1>
              <p className="text-qs-text-dim text-sm">
                Full quantum cryptanalysis suite: Real IBM QPU execution, Simon's algorithm, QPE primitives, QKD quantum channels, and NIST PQC migration.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-2 ${
            hasIbmToken ? 'bg-qs-green/10 border-qs-green/30 text-qs-green' : 'bg-yellow-500/10 border-yellow-500/30 text-yellow-300'
          }`}>
            <div className={`w-2 h-2 rounded-full ${hasIbmToken ? 'bg-qs-green animate-ping' : 'bg-yellow-400'}`} />
            {hasIbmToken ? 'IBM Quantum Cloud Active' : 'Calibrated QPU Emulation Mode'}
          </div>
          <button
            onClick={() => setShowTokenModal(true)}
            className="qs-btn-secondary text-xs flex items-center gap-1.5"
          >
            <Key size={14} />
            {hasIbmToken ? 'Update IBM Key' : 'Connect IBM Token'}
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-qs-border pb-3">
        {([
          { id: 'hardware-lab', label: 'Quantum Hardware Lab', icon: Cpu, badge: 'Flagship' },
          { id: 'simon', label: "Simon's Algorithm", icon: Hash, badge: 'Phase 2' },
          { id: 'qpe', label: 'QPE Primitive', icon: Gauge, badge: 'Phase 2' },
          { id: 'qkd', label: 'QKD Station (BB84 / E91)', icon: Radio, badge: 'Phase 2' },
          { id: 'pqc-shield', label: 'PQC Shield Benchmark', icon: Shield, badge: 'Interactive' },
          { id: 'shor', label: "Shor's Algorithm", icon: Zap, badge: undefined },
          { id: 'grover', label: "Grover's Search", icon: Atom, badge: undefined },
          { id: 'pqc', label: 'NIST Standards (FIPS 203/204)', icon: Lock, badge: undefined },
          { id: 'algo', label: 'Threat Database', icon: Info, badge: undefined },
        ] as const).map(({ id, label, icon: Icon, badge }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs md:text-sm font-medium transition-all ${
              activeTab === id
                ? 'bg-qs-purple/20 text-qs-purple border border-qs-purple/40 shadow-lg shadow-qs-purple/10'
                : 'text-qs-text-dim hover:text-qs-text hover:bg-qs-surface'
            }`}
          >
            <Icon size={15} />
            {label}
            {badge && (
              <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider ${
                activeTab === id ? 'bg-qs-purple text-white' : 'bg-qs-border/40 text-qs-text-dim'
              }`}>
                {badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* TAB 1: QUANTUM HARDWARE LAB */}
      {activeTab === 'hardware-lab' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Control Panel */}
            <div className="lg:col-span-2 qs-card space-y-5 border-qs-purple/30 bg-gradient-to-b from-qs-card to-qs-surface/50">
              <div className="flex items-center justify-between border-b border-qs-border pb-3">
                <div className="flex items-center gap-2">
                  <Sliders size={18} className="text-qs-purple" />
                  <h3 className="font-semibold text-white">Quantum Job Execution Setup</h3>
                </div>
                <span className="text-xs text-qs-text-dim">3-Tier Comparative Engine</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="text-xs font-semibold text-qs-text-dim mb-1.5 block">Target Algorithm</label>
                  <select
                    className="qs-input w-full"
                    value={labAlgorithm}
                    onChange={e => setLabAlgorithm(e.target.value as any)}
                  >
                    <option value="shor">Shor's Factoring (QPE + Period)</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs font-semibold text-qs-text-dim mb-1.5 block">Problem Integer (N)</label>
                  <select
                    className="qs-input w-full"
                    value={shorN}
                    onChange={e => setShorN(Number(e.target.value))}
                  >
                    <option value={15}>N = 15 (3 × 5, a=2, r=4)</option>
                    <option value={21}>N = 21 (3 × 7, a=2, r=6)</option>
                    <option value={35}>N = 35 (5 × 7, a=3, r=12)</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs font-semibold text-qs-text-dim mb-1.5 block">Target QPU / Noise Model</label>
                  <select
                    className="qs-input w-full font-mono text-xs"
                    value={selectedBackend}
                    onChange={e => setSelectedBackend(e.target.value)}
                  >
                    {backends.map(b => (
                      <option key={b.id} value={b.name}>
                        {b.display_name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <div className="flex items-center gap-3 text-xs text-qs-text-dim">
                  <span>Shots: <strong className="text-white font-mono">{shots}</strong></span>
                  <span>•</span>
                  <span>Execution: <strong className="text-qs-cyan">Ideal vs Noisy vs Real QPU</strong></span>
                </div>

                <button
                  onClick={runComparativeHardwareBenchmark}
                  disabled={benchmarkLoading}
                  className="qs-btn-primary px-6 py-2.5 text-sm flex items-center gap-2 shadow-lg shadow-qs-purple/20"
                >
                  <Zap size={16} className={benchmarkLoading ? 'animate-spin' : ''} />
                  {benchmarkLoading ? 'Submitting & Executing on QPU...' : 'Run 3-Tier Quantum Benchmark'}
                </button>
              </div>
            </div>

            {/* Hardware Telemetry Card */}
            <div className="qs-card space-y-4 border-qs-border bg-qs-card/80">
              <div className="flex items-center justify-between border-b border-qs-border pb-3">
                <div className="flex items-center gap-2">
                  <Server size={18} className="text-qs-cyan" />
                  <h3 className="font-semibold text-white">QPU Calibration Telemetry</h3>
                </div>
                <span className="text-xs px-2 py-0.5 rounded bg-green-500/20 text-green-400 font-mono">
                  {currentBackendInfo?.status || 'ONLINE'}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="bg-qs-surface p-2.5 rounded-lg">
                  <div className="text-qs-text-dim">Processor Type</div>
                  <div className="font-bold text-white font-mono mt-0.5">{currentBackendInfo?.processor_type || 'Eagle r3'}</div>
                </div>
                <div className="bg-qs-surface p-2.5 rounded-lg">
                  <div className="text-qs-text-dim">Physical Qubits</div>
                  <div className="font-bold text-qs-purple font-mono mt-0.5">{currentBackendInfo?.num_qubits || 127} Qubits</div>
                </div>
                <div className="bg-qs-surface p-2.5 rounded-lg">
                  <div className="text-qs-text-dim">Avg T₁ Relaxation</div>
                  <div className="font-bold text-qs-cyan font-mono mt-0.5">{currentBackendInfo?.avg_t1_us || 245.8} µs</div>
                </div>
                <div className="bg-qs-surface p-2.5 rounded-lg">
                  <div className="text-qs-text-dim">Avg T₂ Dephasing</div>
                  <div className="font-bold text-qs-cyan font-mono mt-0.5">{currentBackendInfo?.avg_t2_us || 138.4} µs</div>
                </div>
                <div className="bg-qs-surface p-2.5 rounded-lg">
                  <div className="text-qs-text-dim">2-Qubit Gate Error</div>
                  <div className="font-bold text-yellow-400 font-mono mt-0.5">{((currentBackendInfo?.avg_cnot_error || 0.0078) * 100).toFixed(2)}%</div>
                </div>
                <div className="bg-qs-surface p-2.5 rounded-lg">
                  <div className="text-qs-text-dim">Readout Fidelity</div>
                  <div className="font-bold text-qs-green font-mono mt-0.5">{(100 - (currentBackendInfo?.avg_readout_error || 0.015) * 100).toFixed(1)}%</div>
                </div>
              </div>
            </div>
          </div>

          {/* Benchmark Results */}
          {benchmarkResult && (
            <div className="space-y-6">
              <div className="qs-card border-qs-purple/40 bg-gradient-to-r from-qs-card via-qs-purple/10 to-qs-card">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-qs-border">
                  <div className="flex items-center gap-3">
                    <CheckCircle2 size={24} className="text-qs-green" />
                    <div>
                      <h4 className="text-lg font-bold text-white">
                        Shor Factorization Successful: N = {benchmarkResult.N} = {benchmarkResult.factors_found?.[0]} × {benchmarkResult.factors_found?.[1]}
                      </h4>
                      <p className="text-xs text-qs-text-dim font-mono mt-0.5">
                        {benchmarkResult.classical_verification}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 text-xs">
                    <span className="bg-qs-surface px-3 py-1.5 rounded font-mono text-qs-cyan">
                      Detected Period: <strong>r = {benchmarkResult.period_detected}</strong>
                    </span>
                    <span className="bg-qs-surface px-3 py-1.5 rounded font-mono text-qs-purple">
                      Circuit Depth: <strong>{benchmarkResult.circuit_depth}</strong>
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                  <div className="bg-qs-surface/80 p-4 rounded-lg border border-qs-border/40">
                    <div className="text-xs text-qs-text-dim mb-1">Ideal Simulation Peak Fidelity</div>
                    <div className="text-2xl font-bold text-qs-purple font-mono">
                      {benchmarkResult.comparative_results?.ideal?.peak_fidelity_percent}%
                    </div>
                    <p className="text-[11px] text-qs-text-dim mt-1">Zero decoherence; sharp constructive phase spikes.</p>
                  </div>

                  <div className="bg-qs-surface/80 p-4 rounded-lg border border-qs-border/40">
                    <div className="text-xs text-qs-text-dim mb-1">Noisy Simulation Fidelity</div>
                    <div className="text-2xl font-bold text-yellow-400 font-mono">
                      {benchmarkResult.comparative_results?.noisy?.peak_fidelity_percent}%
                    </div>
                    <p className="text-[11px] text-qs-text-dim mt-1">Thermal relaxation (T₁/T₂) flattens amplitude peaks.</p>
                  </div>

                  <div className="bg-qs-surface/80 p-4 rounded-lg border border-qs-border/40">
                    <div className="text-xs text-qs-text-dim mb-1">Real QPU Hardware Fidelity</div>
                    <div className="text-2xl font-bold text-qs-cyan font-mono">
                      {benchmarkResult.comparative_results?.real_qpu?.peak_fidelity_percent}%
                    </div>
                    <p className="text-[11px] text-qs-text-dim mt-1">Environmental crosstalk & measurement readout error.</p>
                  </div>
                </div>
              </div>

              {/* Side-by-Side 3-Tier Histogram Comparison */}
              <div className="qs-card space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-semibold text-white flex items-center gap-2">
                      <BarChart3 size={18} className="text-qs-purple" />
                      Measurement Distribution Comparison (Ideal vs. Noisy vs. Real QPU)
                    </h4>
                    <p className="text-xs text-qs-text-dim mt-0.5">
                      Notice how quantum noise channels disperse the sharp mathematical peaks into background states.
                    </p>
                  </div>
                </div>

                <div className="h-72 w-full pt-4">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={comparativeChartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                      <XAxis dataKey="state" tick={{ fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' }} />
                      <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
                      <Tooltip
                        contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px' }}
                        itemStyle={{ fontSize: '12px' }}
                      />
                      <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '10px' }} />
                      <Bar dataKey="Ideal" fill="#a855f7" radius={[4, 4, 0, 0]} />
                      <Bar dataKey="Noisy" fill="#eab308" radius={[4, 4, 0, 0]} />
                      <Bar dataKey="RealQPU" fill="#06b6d4" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Quantum Security Interpretation Card */}
              {benchmarkResult.quantum_security_interpretation && (
                <div className="qs-card border-red-500/30 bg-gradient-to-br from-red-500/5 via-qs-card to-qs-card space-y-4">
                  <div className="flex items-center gap-3 border-b border-qs-border pb-3">
                    <Shield size={22} className="text-red-400" />
                    <div>
                      <h4 className="font-bold text-white text-base">Quantum Security & Cryptanalytic Interpretation</h4>
                      <span className="text-xs text-red-400 font-mono">
                        Threat: {benchmarkResult.quantum_security_interpretation.threatened_algorithm}
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    <div className="bg-qs-surface p-4 rounded-lg space-y-2">
                      <div className="font-bold text-white uppercase tracking-wider text-[11px] text-qs-purple">
                        Mathematical Vulnerability
                      </div>
                      <p className="text-qs-text leading-relaxed">
                        {benchmarkResult.quantum_security_interpretation.underlying_vulnerability}
                      </p>
                      <div className="pt-2 text-qs-text-dim italic">
                        {benchmarkResult.quantum_security_interpretation.toy_vs_production_reality}
                      </div>
                    </div>

                    <div className="bg-qs-surface p-4 rounded-lg space-y-2">
                      <div className="font-bold text-white uppercase tracking-wider text-[11px] text-qs-cyan">
                        Harvest Now, Decrypt Later (HNDL) Threat
                      </div>
                      <p className="text-qs-text leading-relaxed">
                        {benchmarkResult.quantum_security_interpretation.threat_model}
                      </p>
                      <div className="pt-2 p-2.5 rounded bg-qs-purple/10 border border-qs-purple/30 text-qs-purple">
                        <strong>Migration Action:</strong> {benchmarkResult.quantum_security_interpretation.recommended_migration}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: SIMON'S ALGORITHM (PHASE 2) */}
      {activeTab === 'simon' && (
        <div className="space-y-6">
          <div className="qs-card space-y-4 border-qs-purple/30">
            <div className="flex items-center justify-between border-b border-qs-border pb-3">
              <div>
                <h3 className="font-semibold text-white flex items-center gap-2">
                  <Hash size={20} className="text-qs-purple" />
                  Simon's Algorithm — Symmetric Periodicity Attack
                </h3>
                <p className="text-xs text-qs-text-dim mt-0.5">
                  Demonstrates the exponential quantum speedup O(2^(n/2)) → O(n) used to attack Even-Mansour, GCM authentication tags, and Feistel ciphers.
                </p>
              </div>
              <span className="text-xs px-2.5 py-1 rounded bg-qs-purple/20 text-qs-purple font-mono font-bold">
                Exponential Speedup
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
              <div>
                <label className="text-xs text-qs-text-dim mb-1 block">Hidden Period String (s)</label>
                <select
                  className="qs-input w-full font-mono text-sm"
                  value={simonString}
                  onChange={e => setSimonString(e.target.value)}
                >
                  <option value="11">s = "11" (2 bits, 4 qubits)</option>
                  <option value="101">s = "101" (3 bits, 6 qubits)</option>
                  <option value="110">s = "110" (3 bits, 6 qubits)</option>
                  <option value="1100">s = "1100" (4 bits, 8 qubits)</option>
                </select>
              </div>

              <div className="md:col-span-2 flex justify-end">
                <button
                  onClick={runSimon}
                  disabled={simonLoading}
                  className="qs-btn-primary px-6 py-2.5 text-xs flex items-center gap-2"
                >
                  <Zap size={15} />
                  {simonLoading ? 'Executing Simon Circuit...' : "Run Simon's Algorithm"}
                </button>
              </div>
            </div>
          </div>

          {simonResult && (
            <div className="space-y-4">
              <div className="qs-card border-qs-purple/40 space-y-4">
                <div className="flex items-center justify-between border-b border-qs-border pb-3">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-green-500/20 text-green-400">
                      <CheckCircle2 size={22} />
                    </div>
                    <div>
                      <h4 className="font-bold text-white text-base">
                        Hidden Period Found: s = "{simonResult.hidden_string_found}" (Target: "{simonResult.hidden_string_target}")
                      </h4>
                      <p className="text-xs text-qs-green font-mono">
                        ✓ Quantum sampling solved linear system over GF(2)
                      </p>
                    </div>
                  </div>
                  <span className="text-xs text-qs-text-dim font-mono">{simonResult.execution_time_ms}ms</span>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                  <div className="bg-qs-surface p-3 rounded-lg">
                    <div className="text-qs-text-dim">Input Register Bits (n)</div>
                    <div className="font-bold text-white font-mono mt-1">{simonResult.n_bits} bits</div>
                  </div>
                  <div className="bg-qs-surface p-3 rounded-lg">
                    <div className="text-qs-text-dim">Total Qubits (2n)</div>
                    <div className="font-bold text-qs-purple font-mono mt-1">{simonResult.num_qubits} qubits</div>
                  </div>
                  <div className="bg-qs-surface p-3 rounded-lg">
                    <div className="text-qs-text-dim">Classical Query Complexity</div>
                    <div className="font-bold text-yellow-400 font-mono mt-1">O(2^(n/2))</div>
                  </div>
                  <div className="bg-qs-surface p-3 rounded-lg">
                    <div className="text-qs-text-dim">Quantum Query Complexity</div>
                    <div className="font-bold text-qs-green font-mono mt-1">O(n) Linear</div>
                  </div>
                </div>

                <div className="bg-qs-surface p-3.5 rounded-lg space-y-2">
                  <div className="text-xs font-semibold text-qs-cyan">Sample Measured Orthogonal Vectors (y · s = 0 mod 2):</div>
                  <div className="flex flex-wrap gap-2">
                    {simonResult.orthogonal_equations?.map((eq: string, idx: number) => (
                      <span key={idx} className="bg-qs-bg px-2.5 py-1 rounded font-mono text-xs text-white border border-qs-border">
                        {eq}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-300">
                  <strong>Cryptographic Threat Impact:</strong> {simonResult.cryptographic_impact}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: QPE PRIMITIVE PLAYGROUND (PHASE 2) */}
      {activeTab === 'qpe' && (
        <div className="space-y-6">
          <div className="qs-card space-y-4 border-qs-cyan/30">
            <div className="flex items-center justify-between border-b border-qs-border pb-3">
              <div>
                <h3 className="font-semibold text-white flex items-center gap-2">
                  <Gauge size={20} className="text-qs-cyan" />
                  Quantum Phase Estimation (QPE) Primitive Playground
                </h3>
                <p className="text-xs text-qs-text-dim mt-0.5">
                  Estimates the phase θ in U|ψ⟩ = e^(2πiθ)|ψ⟩. This is the master subroutine inside Shor's algorithm and Quantum HHL.
                </p>
              </div>
              <span className="text-xs px-2.5 py-1 rounded bg-qs-cyan/20 text-qs-cyan font-mono font-bold">
                Phase Kickback & IQFT
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
              <div>
                <label className="text-xs text-qs-text-dim mb-1 block">Target Phase θ</label>
                <select
                  className="qs-input w-full font-mono text-sm"
                  value={qpeTheta}
                  onChange={e => setQpeTheta(Number(e.target.value))}
                >
                  <option value={0.25}>θ = 0.2500 (1/4)</option>
                  <option value={0.125}>θ = 0.1250 (1/8)</option>
                  <option value={0.375}>θ = 0.3750 (3/8)</option>
                  <option value={0.3125}>θ = 0.3125 (5/16)</option>
                  <option value={0.625}>θ = 0.6250 (5/8)</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-qs-text-dim mb-1 block">Precision Counting Qubits (n)</label>
                <select
                  className="qs-input w-full font-mono text-sm"
                  value={qpePrecision}
                  onChange={e => setQpePrecision(Number(e.target.value))}
                >
                  <option value={3}>3 Qubits (Resolves 1/8 increments)</option>
                  <option value={4}>4 Qubits (Resolves 1/16 increments)</option>
                  <option value={5}>5 Qubits (Resolves 1/32 increments)</option>
                </select>
              </div>

              <div className="flex justify-end">
                <button
                  onClick={runQPE}
                  disabled={qpeLoading}
                  className="qs-btn-primary px-6 py-2.5 text-xs flex items-center gap-2"
                >
                  <Gauge size={15} />
                  {qpeLoading ? 'Estimating Eigenvalue...' : 'Run QPE Circuit'}
                </button>
              </div>
            </div>
          </div>

          {qpeResult && (
            <div className="qs-card border-qs-cyan/40 space-y-4">
              <div className="flex items-center justify-between border-b border-qs-border pb-3">
                <div className="flex items-center gap-3">
                  <CheckCircle2 size={22} className="text-qs-green" />
                  <div>
                    <h4 className="font-bold text-white text-base">
                      Estimated Phase: θ ≈ {qpeResult.estimated_phase_theta} ({qpeResult.estimated_phase_fraction})
                    </h4>
                    <p className="text-xs text-qs-text-dim font-mono">
                      Target θ = {qpeResult.target_phase_theta} ({qpeResult.target_phase_fraction}) • Absolute Error: {qpeResult.phase_error}
                    </p>
                  </div>
                </div>
                <span className="text-xs text-qs-text-dim font-mono">{qpeResult.execution_time_ms}ms</span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Measured Bitstring</div>
                  <div className="font-bold text-qs-cyan font-mono mt-1">|{qpeResult.most_probable_bitstring}⟩</div>
                </div>
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Counting Qubits</div>
                  <div className="font-bold text-white font-mono mt-1">{qpeResult.precision_qubits} qubits</div>
                </div>
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Circuit Depth</div>
                  <div className="font-bold text-qs-purple font-mono mt-1">{qpeResult.circuit_depth}</div>
                </div>
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Phase Accuracy</div>
                  <div className="font-bold text-qs-green font-mono mt-1">
                    {qpeResult.phase_error === 0 ? '100% Exact' : `${(100 - qpeResult.phase_error * 100).toFixed(1)}%`}
                  </div>
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-qs-surface border border-qs-border text-xs leading-relaxed text-qs-text">
                <strong>Subroutine Theory:</strong> {qpeResult.theoretical_explanation}
              </div>

              <div className="p-3.5 rounded-lg bg-qs-purple/10 border border-qs-purple/30 text-xs text-qs-purple leading-relaxed">
                <strong>Connection to Shor's RSA Cryptanalysis:</strong> {qpeResult.shor_connection}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: QKD STATION (BB84 / E91) (PHASE 2) */}
      {activeTab === 'qkd' && (
        <div className="space-y-6">
          <div className="qs-card space-y-5 border-qs-green/30">
            <div className="flex items-center justify-between border-b border-qs-border pb-3">
              <div>
                <h3 className="font-semibold text-white flex items-center gap-2">
                  <Radio size={20} className="text-qs-green" />
                  Quantum Key Distribution (QKD) Station
                </h3>
                <p className="text-xs text-qs-text-dim mt-0.5">
                  Simulate information-theoretically secure quantum key exchange protected by the laws of quantum mechanics.
                </p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => setQkdMode('bb84')}
                  className={`px-3 py-1.5 rounded text-xs font-mono font-bold transition-all ${
                    qkdMode === 'bb84' ? 'bg-qs-green text-black' : 'bg-qs-surface text-qs-text-dim'
                  }`}
                >
                  BB84 (Polarization)
                </button>
                <button
                  onClick={() => setQkdMode('e91')}
                  className={`px-3 py-1.5 rounded text-xs font-mono font-bold transition-all ${
                    qkdMode === 'e91' ? 'bg-qs-cyan text-black' : 'bg-qs-surface text-qs-text-dim'
                  }`}
                >
                  E91 (Entanglement)
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="text-xs text-qs-text-dim mb-1 block">
                  {qkdMode === 'bb84' ? 'Photon Pulse Count' : 'Entangled Bell Pairs'}
                </label>
                <select
                  className="qs-input w-full font-mono text-xs"
                  value={qkdPhotons}
                  onChange={e => setQkdPhotons(Number(e.target.value))}
                >
                  <option value={50}>50 Quantum Pulses</option>
                  <option value={100}>100 Quantum Pulses</option>
                  <option value={200}>200 Quantum Pulses</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-qs-text-dim mb-1 block">Eavesdropper (Eve) on Channel</label>
                <button
                  type="button"
                  onClick={() => setQkdEvePresent(!qkdEvePresent)}
                  className={`qs-input w-full flex items-center justify-between text-xs font-bold ${
                    qkdEvePresent ? 'bg-red-500/20 text-red-400 border-red-500/40' : 'bg-green-500/20 text-green-400 border-green-500/40'
                  }`}
                >
                  <span className="flex items-center gap-1.5">
                    {qkdEvePresent ? <Eye size={14} /> : <EyeOff size={14} />}
                    {qkdEvePresent ? 'Eve Active (Intercept-Resend)' : 'Clean Quantum Fiber (No Eve)'}
                  </span>
                  <span className="text-[10px] uppercase font-mono">{qkdEvePresent ? 'Attacking' : 'Secure'}</span>
                </button>
              </div>

              <div className="flex items-end justify-end">
                <button
                  onClick={runQKD}
                  disabled={qkdLoading}
                  className="qs-btn-primary px-6 py-2.5 text-xs flex items-center gap-2 w-full md:w-auto justify-center"
                >
                  <Radio size={14} />
                  {qkdLoading ? 'Transmitting Photons...' : `Simulate ${qkdMode.toUpperCase()} Exchange`}
                </button>
              </div>
            </div>
          </div>

          {/* BB84 Results */}
          {qkdMode === 'bb84' && qkdBB84Result && (
            <div className={`qs-card space-y-4 border ${qkdBB84Result.is_key_secure ? 'border-qs-green/40' : 'border-red-500/40'}`}>
              <div className="flex items-center justify-between border-b border-qs-border pb-3">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${qkdBB84Result.is_key_secure ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                    {qkdBB84Result.is_key_secure ? <CheckCircle2 size={22} /> : <AlertTriangle size={22} />}
                  </div>
                  <div>
                    <h4 className="font-bold text-white text-base">
                      {qkdBB84Result.is_key_secure ? '✓ Quantum Key Established Successfully' : '⚠️ Eavesdropper Detected — Protocol Aborted'}
                    </h4>
                    <p className="text-xs text-qs-text-dim">
                      Measured QBER: <strong className={qkdBB84Result.is_key_secure ? 'text-green-400' : 'text-red-400'}>{qkdBB84Result.qber}%</strong> (Maximum threshold: 11.0%)
                    </p>
                  </div>
                </div>
                <span className={`text-xs px-2.5 py-1 rounded font-mono font-bold ${
                  qkdBB84Result.is_key_secure ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                }`}>
                  {qkdBB84Result.status}
                </span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Transmitted Photons</div>
                  <div className="font-bold text-white font-mono mt-1">{qkdBB84Result.total_photons}</div>
                </div>
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Sifted Key Bits</div>
                  <div className="font-bold text-qs-cyan font-mono mt-1">{qkdBB84Result.sifted_key_length} bits</div>
                </div>
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Final Shared Key Bits</div>
                  <div className="font-bold text-qs-green font-mono mt-1">{qkdBB84Result.final_key_length} bits</div>
                </div>
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Quantum Bit Error Rate</div>
                  <div className={`font-bold font-mono mt-1 ${qkdBB84Result.is_key_secure ? 'text-green-400' : 'text-red-400'}`}>
                    {qkdBB84Result.qber}%
                  </div>
                </div>
              </div>

              {qkdBB84Result.is_key_secure && (
                <div className="p-3 bg-qs-surface rounded-lg">
                  <div className="text-xs text-qs-text-dim mb-1">Established Shared Secret Hex:</div>
                  <div className="font-mono text-xs text-qs-green bg-qs-bg p-2 rounded break-all border border-qs-green/30">
                    0x{qkdBB84Result.final_shared_key_hex}
                  </div>
                </div>
              )}

              <div className="p-3.5 rounded-lg bg-qs-surface border border-qs-border text-xs leading-relaxed text-qs-text">
                {qkdBB84Result.explanation}
              </div>
            </div>
          )}

          {/* E91 Results */}
          {qkdMode === 'e91' && qkdE91Result && (
            <div className={`qs-card space-y-4 border ${qkdE91Result.is_quantum_entangled ? 'border-qs-cyan/40' : 'border-red-500/40'}`}>
              <div className="flex items-center justify-between border-b border-qs-border pb-3">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${qkdE91Result.is_quantum_entangled ? 'bg-cyan-500/20 text-cyan-400' : 'bg-red-500/20 text-red-400'}`}>
                    {qkdE91Result.is_quantum_entangled ? <CheckCircle2 size={22} /> : <AlertTriangle size={22} />}
                  </div>
                  <div>
                    <h4 className="font-bold text-white text-base">
                      {qkdE91Result.is_quantum_entangled ? '✓ Bell Inequality Violated — Entanglement Verified' : '⚠️ Bell Inequality Preserved (S ≤ 2.0) — Eavesdropper Detected'}
                    </h4>
                    <p className="text-xs text-qs-text-dim">
                      CHSH Correlation Parameter: <strong className={qkdE91Result.is_quantum_entangled ? 'text-cyan-400' : 'text-red-400'}>S = {qkdE91Result.chsh_correlation_s}</strong> (Classical Limit ≤ 2.0, Tsirelson Max = 2.828)
                    </p>
                  </div>
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-qs-surface border border-qs-border text-xs leading-relaxed text-qs-text">
                {qkdE91Result.explanation}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 5: PQC SHIELD TEST */}
      {activeTab === 'pqc-shield' && (
        <div className="space-y-6">
          <div className="qs-card space-y-4 border-qs-purple/30">
            <h3 className="font-semibold text-white flex items-center gap-2">
              <Shield size={20} className="text-qs-purple" />
              Post-Quantum Cryptography (PQC) Shield Benchmark
            </h3>
            <p className="text-xs text-qs-text-dim">
              Compare classical RSA-2048 encryption against standardized NIST FIPS 203 (ML-KEM-768) and Hybrid dual-layer encapsulation.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="md:col-span-2">
                <label className="text-xs text-qs-text-dim mb-1 block">Payload Data to Encrypt</label>
                <input
                  type="text"
                  className="qs-input w-full"
                  value={shieldMessage}
                  onChange={e => setShieldMessage(e.target.value)}
                />
              </div>

              <div>
                <label className="text-xs text-qs-text-dim mb-1 block">Encryption Standard</label>
                <select
                  className="qs-input w-full"
                  value={shieldMode}
                  onChange={e => setShieldMode(e.target.value)}
                >
                  <option value="classical_rsa">Classical RSA-2048 (Shor Vulnerable)</option>
                  <option value="pqc_mlkem">NIST ML-KEM-768 (Lattice FIPS 203)</option>
                  <option value="hybrid">Hybrid (X25519 + ML-KEM-768)</option>
                  <option value="aes_256">AES-256-GCM (Grover Resistant)</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={runPQCShieldTest}
                disabled={shieldLoading}
                className="qs-btn-primary px-5 py-2 text-xs flex items-center gap-2"
              >
                <Lock size={14} />
                {shieldLoading ? 'Encrypting & Benchmarking...' : 'Run PQC Shield Test'}
              </button>
            </div>
          </div>

          {shieldResult && (
            <div className="qs-card space-y-4 border-qs-cyan/30">
              <div className="flex items-center justify-between border-b border-qs-border pb-3">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${
                    shieldResult.quantum_status.includes('SECURE') || shieldResult.quantum_status.includes('MAXIMUM')
                      ? 'bg-green-500/20 text-green-400'
                      : shieldResult.quantum_status.includes('GROVER')
                      ? 'bg-cyan-500/20 text-cyan-400'
                      : 'bg-red-500/20 text-red-400'
                  }`}>
                    <Shield size={20} />
                  </div>
                  <div>
                    <h4 className="font-bold text-white">{shieldResult.mode}</h4>
                    <p className="text-xs text-qs-text-dim">{shieldResult.standard}</p>
                  </div>
                </div>
                <div className="text-right">
                  <span className={`text-xs px-2.5 py-1 rounded font-bold font-mono ${
                    shieldResult.quantum_status === 'VULNERABLE' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                  }`}>
                    {shieldResult.quantum_status}
                  </span>
                  <div className="text-xs text-qs-text-dim mt-1 font-mono">{shieldResult.execution_time_ms}ms</div>
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Mathematical Hardness</div>
                  <div className="font-bold text-white font-mono mt-1">{shieldResult.mathematical_basis}</div>
                </div>
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Classical Security</div>
                  <div className="font-bold text-qs-cyan font-mono mt-1">{shieldResult.security_level_bits} bits</div>
                </div>
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Post-Quantum Security</div>
                  <div className={`font-bold font-mono mt-1 ${shieldResult.quantum_security_bits > 0 ? 'text-qs-green' : 'text-red-400'}`}>
                    {shieldResult.quantum_security_bits} bits
                  </div>
                </div>
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Time to Break on CRQC</div>
                  <div className="font-bold text-yellow-400 font-mono mt-1">{shieldResult.estimated_quantum_break_time}</div>
                </div>
              </div>

              <div className="p-3 bg-qs-surface rounded-lg">
                <div className="text-xs text-qs-text-dim mb-1">Encapsulated Ciphertext Sample</div>
                <div className="font-mono text-xs text-qs-cyan bg-qs-bg p-2 rounded break-all">
                  {shieldResult.ciphertext_sample}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-qs-purple/10 border border-qs-purple/30 text-xs text-qs-purple">
                <strong>Migration Advisory:</strong> {shieldResult.recommendation}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 6: SHOR'S EDUCATIONAL EXPLORER */}
      {activeTab === 'shor' && (
        <div className="qs-card space-y-4">
          <h3 className="font-semibold text-white">Shor's Algorithm Educational Details</h3>
          <p className="text-xs text-qs-text-dim leading-relaxed">
            Shor's Algorithm demonstrates how a quantum computer converts the exponential integer factorization problem into a polynomial period-finding problem using Quantum Phase Estimation (QPE) and the Inverse Quantum Fourier Transform (IQFT).
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs pt-2">
            <div className="bg-qs-surface p-4 rounded-lg space-y-1">
              <div className="font-bold text-white">1. Classical Reduction</div>
              <p className="text-qs-text-dim">Given composite N, pick random a &lt; N. If gcd(a, N) &gt; 1, factors are found. Otherwise, evaluate periodic function f(x) = a^x mod N.</p>
            </div>
            <div className="bg-qs-surface p-4 rounded-lg space-y-1">
              <div className="font-bold text-qs-purple">2. Quantum Period Finding</div>
              <p className="text-qs-text-dim">Initialize superposition, apply modular exponentiation oracle, and run IQFT to cause constructive interference at multiples of 1/r.</p>
            </div>
            <div className="bg-qs-surface p-4 rounded-lg space-y-1">
              <div className="font-bold text-qs-green">3. Factor Extraction</div>
              <p className="text-qs-text-dim">If period r is even, calculate gcd(a^(r/2) ± 1, N) to extract non-trivial prime factors in polynomial time.</p>
            </div>
          </div>
        </div>
      )}

      {/* TAB 7: GROVER'S ALGORITHM */}
      {activeTab === 'grover' && (
        <div className="space-y-6">
          <div className="qs-card space-y-4">
            <h3 className="font-semibold text-white">Grover's Algorithm Search Space Demo</h3>
            <p className="text-xs text-qs-text-dim">
              Demonstrate quadratic speedup O(√N) on unstructured key search spaces.
            </p>
            <div className="flex items-center gap-4">
              <div>
                <label className="text-xs text-qs-text-dim mb-1 block">Key Space</label>
                <select
                  className="qs-input w-44"
                  value={groverSize}
                  onChange={e => setGroverSize(Number(e.target.value))}
                >
                  {[4, 8, 16, 32, 64].map(n => (
                    <option key={n} value={n}>{n} items ({Math.ceil(Math.log2(n))} Qubits)</option>
                  ))}
                </select>
              </div>
              <button
                onClick={runGrover}
                disabled={groverLoading}
                className="qs-btn-primary mt-4 text-xs flex items-center gap-2"
              >
                <Atom size={14} />
                {groverLoading ? 'Searching Amplitude...' : 'Run Grover Search'}
              </button>
            </div>
          </div>

          {groverResult && (
            <div className="qs-card border-qs-cyan/30 space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="font-bold text-white">
                  ✓ Marked Item Target Found at #{groverResult.found_item}
                </h4>
                <span className="text-xs font-mono text-qs-cyan">{groverResult.execution_time_ms}ms</span>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Space Size</div>
                  <div className="font-bold text-white font-mono">{groverResult.search_space_size}</div>
                </div>
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Qubits Used</div>
                  <div className="font-bold text-qs-cyan font-mono">{groverResult.num_qubits}</div>
                </div>
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Optimal Iterations</div>
                  <div className="font-bold text-qs-purple font-mono">{groverResult.optimal_iterations}</div>
                </div>
                <div className="bg-qs-surface p-3 rounded-lg">
                  <div className="text-qs-text-dim">Speedup Factor</div>
                  <div className="font-bold text-qs-green font-mono">{groverResult.speedup_factor}</div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 8: NIST STANDARDS */}
      {activeTab === 'pqc' && pqcStandards && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {Object.entries(pqcStandards.standards || {}).map(([name, std]: [string, any]) => (
            <div key={name} className="qs-card space-y-3 hover:border-qs-purple/50 transition-all">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-bold text-lg text-qs-purple">{std.name}</h4>
                  <span className="text-xs text-qs-text-dim font-mono">{std.nist_standard}</span>
                </div>
                <span className="text-xs px-2 py-0.5 rounded bg-green-500/20 text-green-400 font-mono">
                  {std.maturity}
                </span>
              </div>
              <p className="text-xs text-qs-text-dim leading-relaxed">{std.description}</p>
              <div className="text-xs space-y-1.5 pt-2 border-t border-qs-border">
                <div className="flex justify-between">
                  <span className="text-qs-text-dim">Category:</span>
                  <span className="text-white font-mono">{std.category}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-qs-text-dim">Performance:</span>
                  <span className="text-qs-green font-mono">{std.performance}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-qs-text-dim">Replaces:</span>
                  <span className="text-qs-cyan font-mono">{std.replaces?.join(', ')}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 9: ALGORITHM THREAT DATABASE */}
      {activeTab === 'algo' && algoDb && (
        <div className="space-y-3">
          {Object.entries(algoDb.algorithms || {}).map(([name, info]: [string, any]) => (
            <div key={name} className="qs-card flex items-center justify-between gap-4">
              <div>
                <div className="font-bold text-white font-mono">{name}</div>
                <p className="text-xs text-qs-text-dim mt-0.5">{info.reason}</p>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-xs px-2 py-0.5 rounded font-mono ${
                  info.quantum_attack === 'shor' ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400'
                }`}>
                  Attack: {info.quantum_attack?.toUpperCase()}
                </span>
                <span className={`text-xs px-2 py-0.5 rounded font-bold ${
                  info.quantum_security === 'VULNERABLE' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                }`}>
                  {info.quantum_security}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Modal for configuring IBM Quantum API Token */}
      {showTokenModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="qs-card max-w-md w-full space-y-4 border-qs-purple/40 bg-qs-card shadow-2xl">
            <div className="flex items-center justify-between border-b border-qs-border pb-3">
              <h3 className="font-bold text-white flex items-center gap-2">
                <Key size={18} className="text-qs-purple" />
                IBM Quantum Platform API Token
              </h3>
              <button
                onClick={() => setShowTokenModal(false)}
                className="text-qs-text-dim hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-qs-text-dim leading-relaxed">
              Connect your official IBM Quantum Platform API token (from <a href="https://quantum.ibm.com" target="_blank" rel="noreferrer" className="text-qs-cyan underline">quantum.ibm.com</a>) to dispatch live quantum circuits to IBM QPU backends like <strong className="text-white">ibm_brisbane</strong> and <strong className="text-white">ibm_kyoto</strong>.
            </p>

            <div>
              <label className="text-xs text-qs-text-dim mb-1 block">API Token</label>
              <input
                type="password"
                className="qs-input w-full font-mono text-xs"
                placeholder="Enter IBM Quantum API Token..."
                value={ibmToken}
                onChange={e => setIbmToken(e.target.value)}
              />
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setShowTokenModal(false)}
                className="qs-btn-secondary text-xs px-4 py-2"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveToken}
                className="qs-btn-primary text-xs px-4 py-2"
              >
                Save & Authenticate
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
