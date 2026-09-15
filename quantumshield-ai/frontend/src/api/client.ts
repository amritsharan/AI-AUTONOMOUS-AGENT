import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export const api = axios.create({
  baseURL: API_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

// ─── Projects ───────────────────────────────────────────────────────────────

export const projectsApi = {
  list: () => api.get('/api/projects/').then(r => r.data),
  create: (data: { name: string; description?: string }) => api.post('/api/projects/', data).then(r => r.data),
  get: (id: string) => api.get(`/api/projects/${id}`).then(r => r.data),
  delete: (id: string) => api.delete(`/api/projects/${id}`),
}

// ─── Targets ────────────────────────────────────────────────────────────────

export const targetsApi = {
  list: (projectId?: string) => api.get('/api/targets/', { params: { project_id: projectId } }).then(r => r.data),
  create: (data: any) => api.post('/api/targets/', data).then(r => r.data),
  get: (id: string) => api.get(`/api/targets/${id}`).then(r => r.data),
  getLabDefault: () => api.get('/api/targets/lab/default').then(r => r.data),
}

// ─── Scans ──────────────────────────────────────────────────────────────────

export const scansApi = {
  list: (projectId?: string) => api.get('/api/scans/', { params: { project_id: projectId } }).then(r => r.data),
  create: (data: { project_id: string; target_id: string; name: string; scan_type?: string }) =>
    api.post('/api/scans/', data).then(r => r.data),
  get: (id: string) => api.get(`/api/scans/${id}`).then(r => r.data),
  getEvents: (id: string, limit?: number) =>
    api.get(`/api/scans/${id}/events`, { params: { limit } }).then(r => r.data),
  getFindings: (id: string) => api.get(`/api/scans/${id}/findings`).then(r => r.data),
  getCrypto: (id: string) => api.get(`/api/scans/${id}/crypto`).then(r => r.data),
  getQuantum: (id: string) => api.get(`/api/scans/${id}/quantum`).then(r => r.data),
  getAttackGraph: (id: string) => api.get(`/api/scans/${id}/attack-graph`).then(r => r.data),
  getDiff: (id: string) => api.get(`/api/scans/${id}/diff`).then(r => r.data),
  cancel: (id: string) => api.post(`/api/scans/${id}/cancel`).then(r => r.data),
}

// ─── Findings ───────────────────────────────────────────────────────────────

export const findingsApi = {
  get: (id: string) => api.get(`/api/findings/${id}`).then(r => r.data),
  updateStatus: (id: string, status: string) =>
    api.post(`/api/findings/${id}/status`, null, { params: { status } }).then(r => r.data),
  runRegression: (id: string) => api.post(`/api/findings/${id}/regression`).then(r => r.data),
}

// ─── Quantum ─────────────────────────────────────────────────────────────────

export const quantumApi = {
  shorDemo: (N: number) => api.post('/api/quantum/shor-demo', { N }).then(r => r.data),
  groverDemo: (searchSpaceSize: number, markedItem?: number) =>
    api.post('/api/quantum/grover-demo', { search_space_size: searchSpaceSize, marked_item: markedItem }).then(r => r.data),
  shorAssessment: (algorithm: string, keySize?: number) =>
    api.post('/api/quantum/shor-assessment', null, { params: { algorithm, key_size: keySize } }).then(r => r.data),
  groverAssessment: (algorithm: string, keySize?: number) =>
    api.post('/api/quantum/grover-assessment', null, { params: { algorithm, key_size: keySize } }).then(r => r.data),
  getAlgorithms: () => api.get('/api/quantum/algorithms').then(r => r.data),
  getPQCStandards: () => api.get('/api/quantum/pqc-standards').then(r => r.data),
  testPQCShield: (message: string, algorithm_mode: string) =>
    api.post('/api/quantum/pqc-shield-test', { message, algorithm_mode }).then(r => r.data),
  getBackends: () => api.get('/api/quantum/backends').then(r => r.data),
  setIbmToken: (token: string) => api.post('/api/quantum/set-ibm-token', { token }).then(r => r.data),
  runHardwareJob: (data: {
    algorithm?: string
    N?: number
    search_space_size?: number
    marked_item?: number
    mode: 'ideal' | 'noisy' | 'real_qpu'
    backend_name: string
    shots?: number
  }) => api.post('/api/quantum/hardware-job', data).then(r => r.data),
  compareModes: (N: number, backend_name: string, shots?: number) =>
    api.post('/api/quantum/compare-modes', { N, backend_name, shots: shots || 4096 }).then(r => r.data),
  simonDemo: (hiddenString: string = '101', shots?: number) =>
    api.post('/api/quantum/simon-demo', { hidden_string: hiddenString, shots: shots || 1024 }).then(r => r.data),
  qpeDemo: (phaseTheta: number = 0.375, precisionQubits: number = 4, shots?: number) =>
    api.post('/api/quantum/qpe-demo', { phase_theta: phaseTheta, precision_qubits: precisionQubits, shots: shots || 2048 }).then(r => r.data),
  qkdBB84: (numPhotons: number = 100, evePresent: boolean = false, eveInterceptProb: number = 1.0, channelNoise: number = 0.02) =>
    api.post('/api/quantum/qkd-bb84', { num_photons: numPhotons, eve_present: evePresent, eve_intercept_prob: eveInterceptProb, channel_noise: channelNoise }).then(r => r.data),
  qkdE91: (numPairs: number = 200, evePresent: boolean = false) =>
    api.post('/api/quantum/qkd-e91', { num_pairs: numPairs, eve_present: evePresent }).then(r => r.data),
  assessHybridTls: (targetUrl: string, customPort?: number) =>
    api.post('/api/quantum/hybrid-tls', { target_url: targetUrl, custom_port: customPort }).then(r => r.data),
  exportCycloneDxCbom: (data?: any) =>
    api.post('/api/quantum/cbom/cyclonedx', data || {}).then(r => r.data),
  exportSpdxCbom: (data?: any) =>
    api.post('/api/quantum/cbom/spdx', data || {}).then(r => r.data),
  exportJsonCbom: (data?: any) =>
    api.post('/api/quantum/cbom/json', data || {}).then(r => r.data),
}

// ─── Dashboard ───────────────────────────────────────────────────────────────

export const dashboardApi = {
  getProjectDashboard: (projectId: string) => api.get(`/api/dashboard/${projectId}`).then(r => r.data),
  getGlobalStats: () => api.get('/api/dashboard/global/stats').then(r => r.data),
}

// ─── Reports ─────────────────────────────────────────────────────────────────

export const reportsApi = {
  getJson: (scanId: string) => api.get(`/api/reports/${scanId}/json`).then(r => r.data),
  getPdf: (scanId: string) => `${API_URL}/api/reports/${scanId}/pdf`,
}

// ─── WebSocket ───────────────────────────────────────────────────────────────

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000'

export function createScanWebSocket(scanId: string, onMessage: (data: any) => void): WebSocket {
  const ws = new WebSocket(`${WS_URL}/api/scans/${scanId}/stream`)
  ws.onmessage = (event) => {
    try {
      onMessage(JSON.parse(event.data))
    } catch {
      onMessage({ type: 'raw', message: event.data })
    }
  }
  ws.onerror = (e) => console.error('WebSocket error:', e)
  return ws
}

// ─── ngrok ───────────────────────────────────────────────────────────────────

export const ngrokApi = {
  status:    ()                    => api.get('/api/ngrok/status').then(r => r.data),
  setToken:  (token: string)       => api.post('/api/ngrok/set-token', { auth_token: token }).then(r => r.data),
  start:     ()                    => api.post('/api/ngrok/start').then(r => r.data),
  stop:      ()                    => api.post('/api/ngrok/stop').then(r => r.data),
  ipAnalysis:(limit = 50)          => api.get('/api/ngrok/ip-analysis', { params: { limit } }).then(r => r.data),
  clearIpLog:()                    => api.post('/api/ngrok/ip-analysis/clear').then(r => r.data),
}

