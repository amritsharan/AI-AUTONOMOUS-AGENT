import { useState, useEffect } from 'react'
import { Atom, Zap, Lock, ChevronRight, Info } from 'lucide-react'
import { quantumApi } from '../api/client'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

export default function QuantumCenter() {
  const [shorN, setShorN] = useState(15)
  const [shorResult, setShorResult] = useState<any>(null)
  const [shorLoading, setShorLoading] = useState(false)

  const [groverSize, setGroverSize] = useState(16)
  const [groverResult, setGroverResult] = useState<any>(null)
  const [groverLoading, setGroverLoading] = useState(false)

  const [pqcStandards, setPqcStandards] = useState<any>(null)
  const [algoDb, setAlgoDb] = useState<any>(null)
  const [activeTab, setActiveTab] = useState<'shor' | 'grover' | 'pqc' | 'algo'>('shor')

  useEffect(() => {
    quantumApi.getPQCStandards().then(setPqcStandards).catch(console.error)
    quantumApi.getAlgorithms().then(setAlgoDb).catch(console.error)
  }, [])

  const runShor = async () => {
    setShorLoading(true)
    try { setShorResult(await quantumApi.shorDemo(shorN)) }
    catch (e) { console.error(e) }
    setShorLoading(false)
  }

  const runGrover = async () => {
    setGroverLoading(true)
    try { setGroverResult(await quantumApi.groverDemo(groverSize)) }
    catch (e) { console.error(e) }
    setGroverLoading(false)
  }

  const groverChartData = groverResult ? Object.entries(groverResult.measurement_results || {}).map(([k, v]) => ({
    state: k, count: v as number,
    isMarked: parseInt(k, 2) === groverResult.marked_item,
  })).sort((a, b) => b.count - a.count).slice(0, 10) : []

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <Atom className="text-qs-purple" size={28} />
          Quantum Center
        </h1>
        <p className="text-qs-text-dim text-sm mt-1">
          Educational quantum algorithm demonstrations and post-quantum cryptography readiness assessment.
        </p>
        <div className="mt-2 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-xs text-yellow-300">
          <strong>⚠️ Educational Note:</strong> These demonstrations run on classical simulators and small toy problems. A Cryptographically Relevant Quantum Computer (CRQC) does not exist today. Quantum threats to RSA/ECC are theoretical and estimated 10-20+ years away.
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 border-b border-qs-border pb-4">
        {([
          { id: 'shor', label: "Shor's Algorithm", icon: Zap },
          { id: 'grover', label: "Grover's Algorithm", icon: Atom },
          { id: 'pqc', label: 'PQC Standards', icon: Lock },
          { id: 'algo', label: 'Algorithm DB', icon: Info },
        ] as const).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === id
                ? 'bg-qs-purple/20 text-qs-purple border border-qs-purple/30'
                : 'text-qs-text-dim hover:text-qs-text hover:bg-qs-card'
            }`}
          >
            <Icon size={15} />
            {label}
          </button>
        ))}
      </div>

      {/* Shor's Demo */}
      {activeTab === 'shor' && (
        <div className="space-y-6">
          <div className="qs-card">
            <h3 className="font-semibold text-white mb-2">Shor's Algorithm — Toy Factoring Demo</h3>
            <p className="text-xs text-qs-text-dim mb-4">
              Run Shor's algorithm on small numbers (N=15, 21, 35) using a quantum circuit simulator. 
              This demonstrates the mathematical structure without threatening any real cryptography.
            </p>
            <div className="flex items-center gap-4">
              <div>
                <label className="text-xs text-qs-text-dim mb-1 block">N to factor</label>
                <select className="qs-input w-32" value={shorN} onChange={e => setShorN(Number(e.target.value))}>
                  {[15, 21, 35].map(n => <option key={n} value={n}>N = {n}</option>)}
                </select>
              </div>
              <button onClick={runShor} disabled={shorLoading} className="qs-btn-primary mt-4">
                <Zap size={16} /> {shorLoading ? 'Running...' : 'Run Shor Demo'}
              </button>
            </div>
          </div>

          {shorResult && (
            <div className="space-y-4">
              <div className="qs-card border-qs-purple/30">
                <div className="flex items-center gap-3 mb-4">
                  <div className={`w-3 h-3 rounded-full ${shorResult.success ? 'bg-qs-green' : 'bg-qs-red'}`} />
                  <h3 className="font-semibold text-white">
                    {shorResult.success ? `✓ N = ${shorResult.N} = ${shorResult.factors_found?.[0]} × ${shorResult.factors_found?.[1]}` : 'Demo Failed'}
                  </h3>
                  <span className="ml-auto text-xs text-qs-text-dim">{shorResult.execution_time_ms?.toFixed(1)}ms</span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center mb-4">
                  {[
                    { label: 'Qubits Used', value: shorResult.num_qubits },
                    { label: 'Simulator', value: shorResult.simulator?.split(' ')[0] },
                    { label: 'Shots', value: shorResult.shots },
                    { label: 'Success', value: shorResult.success ? '✓ Yes' : '✗ No' },
                  ].map(({ label, value }) => (
                    <div key={label} className="bg-qs-surface rounded-lg p-3">
                      <div className="text-lg font-bold text-qs-purple font-mono">{value}</div>
                      <div className="text-xs text-qs-text-dim">{label}</div>
                    </div>
                  ))}
                </div>
                <div className="bg-qs-surface rounded-lg p-3 mb-3">
                  <div className="text-xs text-qs-text-dim mb-2">Circuit Description</div>
                  <p className="text-xs text-qs-text font-mono">{shorResult.circuit_description}</p>
                </div>
                {shorResult.measurement_results && (
                  <div className="bg-qs-surface rounded-lg p-3">
                    <div className="text-xs text-qs-text-dim mb-2">Top Measurement Results</div>
                    <div className="grid grid-cols-3 gap-2">
                      {Object.entries(shorResult.measurement_results).map(([state, count]) => (
                        <div key={state} className="flex justify-between text-xs font-mono bg-qs-bg rounded p-2">
                          <span className="text-qs-cyan">|{state}⟩</span>
                          <span className="text-qs-purple">{count as number}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                <p className="text-xs text-qs-text-dim mt-3 italic">{shorResult.note}</p>
              </div>

              {/* RSA Threat Context */}
              <div className="qs-card border-qs-border/40">
                <h4 className="font-semibold text-white mb-3">Real RSA-2048 Shor Assessment</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div className="bg-qs-surface rounded-lg p-3">
                    <div className="text-xs text-qs-text-dim mb-1">Classical Complexity</div>
                    <div className="text-qs-text font-mono text-xs">Sub-exponential (GNFS)</div>
                  </div>
                  <div className="bg-qs-surface rounded-lg p-3">
                    <div className="text-xs text-qs-text-dim mb-1">Quantum Complexity</div>
                    <div className="text-qs-purple font-mono text-xs">O(log²N) — Polynomial</div>
                  </div>
                  <div className="bg-qs-surface rounded-lg p-3">
                    <div className="text-xs text-qs-text-dim mb-1">Qubits Required</div>
                    <div className="text-qs-orange font-mono text-xs">~4,000-20,000 logical</div>
                  </div>
                </div>
                <div className="mt-3 p-3 bg-green-500/10 border border-green-500/30 rounded text-xs text-green-300">
                  <strong>Current Risk: LOW.</strong> No CRQC exists. RSA-2048 is safe today. Plan PQC migration for 2028-2030.
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Grover's Demo */}
      {activeTab === 'grover' && (
        <div className="space-y-6">
          <div className="qs-card">
            <h3 className="font-semibold text-white mb-2">Grover's Algorithm — Search Space Demo</h3>
            <p className="text-xs text-qs-text-dim mb-4">
              Demonstrate Grover's quadratic speedup on a small unsorted search space. 
              Shows how quantum computers can search N items in O(√N) instead of classical O(N).
            </p>
            <div className="flex items-center gap-4">
              <div>
                <label className="text-xs text-qs-text-dim mb-1 block">Search Space Size</label>
                <select className="qs-input w-40" value={groverSize} onChange={e => setGroverSize(Number(e.target.value))}>
                  {[4, 8, 16, 32, 64].map(n => <option key={n} value={n}>{n} items ({Math.ceil(Math.log2(n))} qubits)</option>)}
                </select>
              </div>
              <button onClick={runGrover} disabled={groverLoading} className="qs-btn-primary mt-4">
                <Atom size={16} /> {groverLoading ? 'Running...' : 'Run Grover Demo'}
              </button>
            </div>
          </div>

          {groverResult && (
            <div className="space-y-4">
              <div className="qs-card border-qs-cyan/30">
                <div className="flex items-center gap-3 mb-4">
                  <div className={`w-3 h-3 rounded-full ${groverResult.item_found ? 'bg-qs-green' : 'bg-qs-orange'}`} />
                  <h3 className="font-semibold text-white">
                    {groverResult.item_found
                      ? `✓ Found item #${groverResult.found_item} in ${groverResult.search_space_size}-item space`
                      : 'Demo Complete'}
                  </h3>
                  <span className="ml-auto text-xs text-qs-text-dim">{groverResult.execution_time_ms?.toFixed(1)}ms</span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center mb-4">
                  {[
                    { label: 'Search Space', value: groverResult.search_space_size },
                    { label: 'Qubits', value: groverResult.num_qubits },
                    { label: 'Grover Iterations', value: groverResult.optimal_iterations },
                    { label: 'Speedup', value: groverResult.speedup_factor?.split(' ')[0] },
                  ].map(({ label, value }) => (
                    <div key={label} className="bg-qs-surface rounded-lg p-3">
                      <div className="text-lg font-bold text-qs-cyan font-mono">{value}</div>
                      <div className="text-xs text-qs-text-dim">{label}</div>
                    </div>
                  ))}
                </div>

                <div className="grid grid-cols-2 gap-4 mb-4">
                  <div className="bg-qs-surface rounded-lg p-3">
                    <div className="text-xs text-qs-text-dim mb-1">Classical Complexity</div>
                    <div className="text-qs-text font-mono text-xs">{groverResult.classical_complexity}</div>
                  </div>
                  <div className="bg-qs-surface rounded-lg p-3">
                    <div className="text-xs text-qs-text-dim mb-1">Quantum Complexity</div>
                    <div className="text-qs-cyan font-mono text-xs">{groverResult.quantum_complexity}</div>
                  </div>
                </div>

                {groverChartData.length > 0 && (
                  <div>
                    <div className="text-xs text-qs-text-dim mb-2">Measurement Distribution (marked item amplified)</div>
                    <ResponsiveContainer width="100%" height={160}>
                      <BarChart data={groverChartData}>
                        <XAxis dataKey="state" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                        <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} />
                        <Tooltip contentStyle={{ backgroundColor: '#1a2035', border: '1px solid #1e2d40' }} />
                        <Bar dataKey="count" radius={[3,3,0,0]}>
                          {groverChartData.map((entry, idx) => (
                            <Cell key={idx} fill={entry.isMarked ? '#06b6d4' : '#1e2d40'} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
                <p className="text-xs text-qs-text-dim mt-3 italic">{groverResult.note}</p>
              </div>

              {/* AES Impact */}
              <div className="qs-card border-qs-border/40">
                <h4 className="font-semibold text-white mb-3">Grover's Impact on Symmetric Cryptography</h4>
                <div className="space-y-3">
                  {[
                    { algo: 'AES-128', bits: 128, quantum_bits: 64, safe: false },
                    { algo: 'AES-192', bits: 192, quantum_bits: 96, safe: true },
                    { algo: 'AES-256', bits: 256, quantum_bits: 128, safe: true },
                  ].map(({ algo, bits, quantum_bits, safe }) => (
                    <div key={algo} className="flex items-center gap-4 p-3 bg-qs-surface rounded-lg">
                      <span className="font-mono text-sm text-white w-20">{algo}</span>
                      <div className="flex-1">
                        <div className="flex justify-between text-xs mb-1">
                          <span className="text-qs-text-dim">Classical: {bits} bits</span>
                          <span className={safe ? 'text-qs-green' : 'text-qs-orange'}>Quantum: ~{quantum_bits} bits</span>
                        </div>
                        <div className="h-1.5 bg-qs-border/30 rounded-full">
                          <div className="h-1.5 rounded-full" style={{
                            width: `${(quantum_bits / 128) * 100}%`,
                            backgroundColor: safe ? '#10b981' : '#f97316'
                          }} />
                        </div>
                      </div>
                      <span className={`text-xs px-2 py-0.5 rounded ${safe ? 'bg-green-500/20 text-green-400' : 'bg-orange-500/20 text-orange-400'}`}>
                        {safe ? '✓ Safe' : '⚠ Marginal'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* PQC Standards */}
      {activeTab === 'pqc' && pqcStandards && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {Object.entries(pqcStandards.standards || {}).map(([name, std]: [string, any]) => (
            <div key={name} className="qs-card hover:border-qs-purple/40 transition-all">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="text-lg font-bold text-gradient-purple">{std.name}</div>
                  <div className="text-xs text-qs-text-dim">{std.nist_standard}</div>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded ${
                  std.maturity === 'STANDARDIZED' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'
                }`}>{std.maturity}</span>
              </div>
              <div className="text-xs text-qs-text-dim mb-3">{std.description?.slice(0, 200)}...</div>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-qs-text-dim">Category</span>
                  <span className="text-qs-text font-mono">{std.category}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-qs-text-dim">Performance</span>
                  <span className={`font-mono ${std.performance === 'FAST' ? 'text-qs-green' : std.performance === 'MODERATE' ? 'text-yellow-400' : 'text-qs-orange'}`}>
                    {std.performance}
                  </span>
                </div>
                <div>
                  <span className="text-qs-text-dim">Replaces</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {std.replaces?.map((r: string) => (
                      <span key={r} className="bg-qs-surface px-1.5 py-0.5 rounded text-qs-text">{r}</span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Algorithm DB */}
      {activeTab === 'algo' && algoDb && (
        <div className="space-y-3">
          {Object.entries(algoDb.algorithms || {}).map(([name, info]: [string, any]) => (
            <div key={name} className="qs-card flex items-start gap-4">
              <div className="w-20 flex-shrink-0">
                <div className="font-mono text-sm font-bold text-white">{name}</div>
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-xs text-qs-text-dim line-clamp-2">{info.reason || 'N/A'}</div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <span className={`text-xs px-2 py-0.5 rounded font-mono ${
                  info.quantum_attack === 'shor' ? 'bg-red-500/20 text-red-400' :
                  info.quantum_attack === 'grover' ? 'bg-orange-500/20 text-orange-400' :
                  'bg-green-500/20 text-green-400'
                }`}>{info.quantum_attack || 'none'}</span>
                <span className={`text-xs px-2 py-0.5 rounded ${
                  info.quantum_security === 'VULNERABLE' ? 'bg-red-500/10 text-red-400' :
                  info.quantum_security === 'RESISTANT' ? 'bg-green-500/10 text-green-400' :
                  'bg-yellow-500/10 text-yellow-400'
                }`}>{info.quantum_security}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
