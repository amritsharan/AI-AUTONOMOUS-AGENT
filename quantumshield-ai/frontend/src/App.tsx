import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Projects from './pages/Projects'
import Targets from './pages/Targets'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import Findings from './pages/Findings'
import QuantumCenter from './pages/QuantumCenter'
import SecurityLab from './pages/SecurityLab'
import Reports from './pages/Reports'
import Settings from './pages/Settings'
import AttackConsole from './pages/AttackConsole'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/projects" element={<Projects />} />
        <Route path="/targets" element={<Targets />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/scans/:scanId" element={<ScanDetail />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/quantum" element={<QuantumCenter />} />
        <Route path="/lab" element={<SecurityLab />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/attack" element={<AttackConsole />} />
      </Routes>
    </Layout>
  )
}
