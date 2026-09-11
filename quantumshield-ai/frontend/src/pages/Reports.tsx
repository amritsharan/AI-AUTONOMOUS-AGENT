import { useState, useEffect } from 'react'
import { FileText, Download } from 'lucide-react'
import { scansApi, reportsApi } from '../api/client'

export default function Reports() {
  const [scans, setScans] = useState<any[]>([])
  const [selectedScan, setSelectedScan] = useState('')
  const [report, setReport] = useState<any>(null)
  const [loading, setLoading] = useState(false)

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
    try { setReport(await reportsApi.getJson(selectedScan)) }
    catch (e) { console.error(e) }
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

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Reports</h1>
      </div>

      <div className="qs-card">
        <div className="flex items-center gap-4">
          <select
            className="qs-input flex-1"
            value={selectedScan}
            onChange={e => setSelectedScan(e.target.value)}
          >
            <option value="">Select completed scan...</option>
            {scans.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
          <button onClick={loadReport} disabled={!selectedScan || loading} className="qs-btn-primary">
            <FileText size={16} /> {loading ? 'Loading...' : 'Generate Report'}
          </button>
          {report && (
            <>
              <button onClick={downloadJson} className="qs-btn-secondary">
                <Download size={16} /> JSON
              </button>
              <a
                href={reportsApi.getPdf(selectedScan)}
                target="_blank"
                rel="noopener noreferrer"
                className="qs-btn-secondary"
              >
                <Download size={16} /> PDF
              </a>
            </>
          )}
        </div>
      </div>

      {report && (
        <div className="space-y-6">
          {/* Executive Summary */}
          <div className="qs-card">
            <h3 className="font-semibold text-white mb-4">Executive Summary</h3>
            <div className="grid grid-cols-2 md:grid-cols-6 gap-4 text-center">
              {[
                { label: 'Classical Score', value: report.executive_summary?.classical_security_score?.toFixed(0), color: 'text-qs-blue' },
                { label: 'Quantum Score', value: report.executive_summary?.quantum_security_score?.toFixed(0), color: 'text-qs-purple' },
                { label: 'Total Findings', value: report.executive_summary?.total_findings, color: 'text-qs-text' },
                { label: 'Confirmed', value: report.executive_summary?.confirmed_findings, color: 'text-qs-orange' },
                { label: 'Critical', value: report.executive_summary?.critical, color: 'text-red-400' },
                { label: 'High', value: report.executive_summary?.high, color: 'text-orange-400' },
              ].map(({ label, value, color }) => (
                <div key={label} className="bg-qs-surface rounded-lg p-3">
                  <div className={`text-2xl font-bold font-mono ${color}`}>{value ?? '—'}</div>
                  <div className="text-xs text-qs-text-dim">{label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Raw JSON Preview */}
          <div className="qs-card">
            <h3 className="font-semibold text-white mb-3">Report Data (JSON Preview)</h3>
            <pre className="text-xs font-mono text-green-400 bg-qs-bg rounded-lg p-4 max-h-96 overflow-auto">
              {JSON.stringify(report, null, 2).slice(0, 5000)}
              {JSON.stringify(report).length > 5000 ? '\n...(truncated — download full JSON)' : ''}
            </pre>
          </div>
        </div>
      )}

      {scans.length === 0 && (
        <div className="text-center py-16 text-qs-text-dim">
          <FileText size={48} className="mx-auto mb-4 opacity-20" />
          <p>No completed scans yet. Run a full scan to generate reports.</p>
        </div>
      )}
    </div>
  )
}
