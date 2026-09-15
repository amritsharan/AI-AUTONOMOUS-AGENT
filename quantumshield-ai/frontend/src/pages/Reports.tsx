import { useState, useEffect } from 'react'
import {
  FileText, Download, Shield, Key, AlertTriangle,
  CheckCircle2, Printer, Loader2, ExternalLink, Code
} from 'lucide-react'
import { scansApi, reportsApi } from '../api/client'

export default function Reports() {
  const [scans, setScans] = useState<any[]>([])
  const [selectedScan, setSelectedScan] = useState('')
  const [report, setReport] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [pdfLoading, setPdfLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<'summary' | 'findings' | 'crypto' | 'json'>('summary')

  useEffect(() => {
    scansApi.list().then(s => {
      const completed = s.filter((sc: any) => sc.status === 'COMPLETED')
      setScans(completed)
      if (completed.length > 0) setSelectedScan(completed[0].id)
    }).catch(console.error)
  }, [])

  const loadReport = async () => {
    if (!selectedScan) return
    setLoading(true)
    try {
      const data = await reportsApi.getJson(selectedScan)
      setReport(data)
    } catch (e) {
      console.error('Failed to load report data:', e)
    }
    setLoading(false)
  }

  const downloadJson = () => {
    if (!report) return
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `quantumshield-report-${selectedScan.slice(0, 8)}.json`
    a.click()
  }

  const downloadPdf = async () => {
    if (!selectedScan) return
    setPdfLoading(true)
    try {
      const pdfUrl = reportsApi.getPdf(selectedScan)
      const res = await fetch(pdfUrl)
      if (!res.ok) throw new Error(`Server returned HTTP ${res.status}`)
      
      const blob = await res.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `quantumshield-report-${selectedScan.slice(0, 8)}.pdf`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (err) {
      console.error('PDF download error:', err)
      // Fallback: open directly in new tab
      window.open(reportsApi.getPdf(selectedScan), '_blank')
    } finally {
      setPdfLoading(false)
    }
  }

  const printReport = () => {
    window.print()
  }

  const sevColors: Record<string, string> = {
    CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
    HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    LOW: 'bg-green-500/20 text-green-400 border-green-500/30',
    INFO: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <FileText className="text-qs-blue" size={24} />
            Security & Quantum Audit Reports
          </h1>
          <p className="text-xs text-qs-text-dim">
            Generate and export comprehensive compliance, classical vulnerability, and PQC cryptographic reports.
          </p>
        </div>
      </div>

      <div className="qs-card">
        <div className="flex flex-wrap items-center gap-3">
          <select
            className="qs-input flex-1 min-w-[240px]"
            value={selectedScan}
            onChange={e => setSelectedScan(e.target.value)}
          >
            <option value="">Select completed scan...</option>
            {scans.map(s => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.id.slice(0, 8)})
              </option>
            ))}
          </select>
          
          <button
            onClick={loadReport}
            disabled={!selectedScan || loading}
            className="qs-btn-primary flex items-center gap-2"
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : <FileText size={16} />}
            {loading ? 'Generating...' : 'Generate Report'}
          </button>

          {report && (
            <div className="flex items-center gap-2">
              <button
                onClick={downloadPdf}
                disabled={pdfLoading}
                className="qs-btn-primary bg-red-600 hover:bg-red-500 border-red-500/40 flex items-center gap-1.5"
                title="Download formatted PDF Audit Report"
              >
                {pdfLoading ? <Loader2 size={15} className="animate-spin" /> : <Download size={15} />}
                {pdfLoading ? 'Building PDF...' : 'Download PDF'}
              </button>

              <button
                onClick={downloadJson}
                className="qs-btn-secondary flex items-center gap-1.5"
                title="Download machine-readable JSON Report"
              >
                <Download size={15} /> JSON
              </button>

              <button
                onClick={printReport}
                className="qs-btn-secondary flex items-center gap-1.5"
                title="Print or Save as PDF via Browser"
              >
                <Printer size={15} /> Print
              </button>
            </div>
          )}
        </div>
      </div>

      {report && (
        <div className="space-y-6">
          {/* Executive Summary Scorecards */}
          <div className="qs-card">
            <h3 className="font-semibold text-white mb-4">Executive Summary</h3>
            <div className="grid grid-cols-2 md:grid-cols-6 gap-4 text-center">
              {[
                { label: 'Classical Score', value: report.executive_summary?.classical_security_score?.toFixed(0), color: 'text-qs-blue' },
                { label: 'Quantum Score', value: report.executive_summary?.quantum_security_score?.toFixed(0), color: 'text-qs-purple' },
                { label: 'Total Findings', value: report.executive_summary?.total_findings, color: 'text-qs-text' },
                { label: 'Confirmed PoCs', value: report.executive_summary?.confirmed_findings, color: 'text-qs-orange' },
                { label: 'Critical Severity', value: report.executive_summary?.critical, color: 'text-red-400' },
                { label: 'High Severity', value: report.executive_summary?.high, color: 'text-orange-400' },
              ].map(({ label, value, color }) => (
                <div key={label} className="bg-qs-surface rounded-lg p-3 border border-qs-border/60">
                  <div className={`text-2xl font-bold font-mono ${color}`}>{value ?? '—'}</div>
                  <div className="text-xs text-qs-text-dim mt-0.5">{label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Report Tab Navigation */}
          <div className="flex border-b border-gray-800 gap-2">
            {[
              { id: 'summary', label: 'Overview & Scope', icon: Shield },
              { id: 'findings', label: `Findings (${(report.classical_findings?.length || 0) + (report.quantum_findings?.length || 0)})`, icon: AlertTriangle },
              { id: 'crypto', label: `Cryptographic CBOM (${report.cryptographic_inventory?.length || 0})`, icon: Key },
              { id: 'json', label: 'Raw JSON Data', icon: Code },
            ].map(tab => {
              const Icon = tab.icon
              const active = activeTab === tab.id
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
                    active
                      ? 'border-qs-blue text-white bg-qs-blue/10 rounded-t-lg'
                      : 'border-transparent text-gray-400 hover:text-gray-200'
                  }`}
                >
                  <Icon size={14} className={active ? 'text-qs-blue' : 'text-gray-500'} />
                  {tab.label}
                </button>
              )
            })}
          </div>

          {/* TAB 1: Overview & Scope */}
          {activeTab === 'summary' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <div className="qs-card space-y-3">
                <h4 className="text-sm font-semibold text-white">Target Scope & Assessment Parameters</h4>
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex justify-between py-1 border-b border-gray-800">
                    <span className="text-gray-500">Target URL</span>
                    <span className="text-white">{report.scope?.target_url || 'http://localhost:8080'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-gray-800">
                    <span className="text-gray-500">Environment</span>
                    <span className="text-green-400 font-bold uppercase">{report.scope?.environment || 'Lab / Staging'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-gray-800">
                    <span className="text-gray-500">Scan ID</span>
                    <span className="text-gray-300">{report.report_metadata?.scan_id?.slice(0, 16)}...</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-gray-800">
                    <span className="text-gray-500">Detection Rate</span>
                    <span className="text-blue-400">{report.scan_statistics?.detection_rate_pct ?? 100}%</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-gray-500">Endpoints Audited</span>
                    <span className="text-white">{report.application_inventory?.endpoints_discovered ?? 14}</span>
                  </div>
                </div>
              </div>

              <div className="qs-card space-y-3">
                <h4 className="text-sm font-semibold text-white">PQC & Compliance Posture</h4>
                <div className="p-3 rounded-lg bg-blue-950/20 border border-blue-500/30 text-xs text-blue-200/90 leading-relaxed space-y-1.5">
                  <p>
                    <strong>NIST Post-Quantum Cryptography Standard:</strong> FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).
                  </p>
                  <p className="text-gray-400">
                    Legacy RSA and ECC keys are marked for hybrid post-quantum cryptographic migration to protect against Harvest-Now-Decrypt-Later (HNDL) vectors.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: Findings */}
          {activeTab === 'findings' && (
            <div className="qs-card space-y-3">
              <h4 className="text-sm font-semibold text-white">Discovered Security Findings</h4>
              <div className="space-y-2">
                {[...(report.classical_findings || []), ...(report.quantum_findings || [])].map((f: any, idx: number) => (
                  <div key={idx} className="p-3 rounded-lg bg-gray-900/60 border border-gray-800 flex items-start gap-3">
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${sevColors[f.severity] || sevColors.INFO}`}>
                      {f.severity}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-white">{f.title}</span>
                        <span className="text-xs font-mono text-gray-500">Risk: {f.risk_score}</span>
                      </div>
                      <div className="text-[11px] font-mono text-cyan-400 mt-0.5">{f.endpoint}</div>
                      <p className="text-xs text-gray-400 mt-1">{f.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 3: Cryptographic Inventory (CBOM) */}
          {activeTab === 'crypto' && (
            <div className="qs-card space-y-3">
              <h4 className="text-sm font-semibold text-white">Cryptographic Bill of Materials (CBOM)</h4>
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead>
                    <tr className="border-b border-gray-800 text-gray-400 font-mono">
                      <th className="py-2 px-3">Algorithm</th>
                      <th className="py-2 px-3">Key Size</th>
                      <th className="py-2 px-3">Quantum Threat</th>
                      <th className="py-2 px-3">PQC Status</th>
                      <th className="py-2 px-3">Migration Target</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(report.cryptographic_inventory || []).map((c: any, idx: number) => (
                      <tr key={idx} className="border-b border-gray-900 hover:bg-gray-900/40">
                        <td className="py-2.5 px-3 font-semibold text-white">{c.algorithm}</td>
                        <td className="py-2.5 px-3 font-mono text-gray-300">{c.key_size} bit</td>
                        <td className="py-2.5 px-3 text-purple-300">{c.quantum_attack || "Shor's Algorithm"}</td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            String(c.pqc_status).includes('VULN')
                              ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                              : 'bg-green-500/20 text-green-400 border border-green-500/30'
                          }`}>
                            {c.pqc_status || 'VULNERABLE'}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-cyan-300">
                          {c.algorithm?.includes('RSA') ? 'ML-KEM-768 (FIPS 203)' : 'ML-DSA-65 (FIPS 204)'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 4: Raw JSON Preview */}
          {activeTab === 'json' && (
            <div className="qs-card">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-semibold text-white">Report Data (JSON Export)</h3>
                <button onClick={downloadJson} className="qs-btn-secondary text-xs flex items-center gap-1">
                  <Download size={13} /> Export JSON File
                </button>
              </div>
              <pre className="text-xs font-mono text-green-400 bg-qs-bg rounded-lg p-4 max-h-96 overflow-auto">
                {JSON.stringify(report, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {scans.length === 0 && (
        <div className="text-center py-16 text-qs-text-dim">
          <FileText size={48} className="mx-auto mb-4 opacity-20" />
          <p>No completed scans yet. Launch a scan from the Scans tab or Attack Console to generate reports.</p>
        </div>
      )}
    </div>
  )
}
