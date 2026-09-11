import { ReactNode, useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, FolderKanban, Target, Scan, ShieldAlert,
  Atom, FlaskConical, FileText, Settings, ChevronLeft, ChevronRight,
  Shield, Zap, Activity, ShieldOff
} from 'lucide-react'

interface LayoutProps {
  children: ReactNode
}

const navItems = [
  { path: '/dashboard',  label: 'Dashboard',      icon: LayoutDashboard },
  { path: '/projects',   label: 'Projects',        icon: FolderKanban },
  { path: '/targets',    label: 'Targets',         icon: Target },
  { path: '/scans',      label: 'Scans',           icon: Scan },
  { path: '/findings',   label: 'Findings',        icon: ShieldAlert },
  { path: '/attack',     label: 'Attack Console',  icon: ShieldOff, danger: true },
  { path: '/quantum',    label: 'Quantum Center',  icon: Atom, highlight: true },
  { path: '/lab',        label: 'Security Lab',    icon: FlaskConical },
  { path: '/reports',    label: 'Reports',         icon: FileText },
  { path: '/settings',   label: 'Settings',        icon: Settings },
]

export default function Layout({ children }: LayoutProps) {
  const [collapsed, setCollapsed] = useState(false)
  const location = useLocation()

  return (
    <div className="flex h-screen overflow-hidden bg-qs-bg grid-bg">
      {/* Sidebar */}
      <aside
        className={`flex-shrink-0 flex flex-col bg-qs-surface border-r border-qs-border transition-all duration-300 ${
          collapsed ? 'w-16' : 'w-60'
        }`}
      >
        {/* Logo */}
        <div className="flex items-center h-16 px-4 border-b border-qs-border">
          <div className="flex items-center gap-3 min-w-0">
            <div className="flex-shrink-0 w-8 h-8 bg-gradient-to-br from-qs-blue to-qs-purple rounded-lg flex items-center justify-center glow-blue">
              <Shield size={16} className="text-white" />
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <div className="font-bold text-sm text-gradient-blue truncate">QuantumShield AI</div>
                <div className="text-xs text-qs-text-dim truncate">Security Platform</div>
              </div>
            )}
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-4 overflow-y-auto">
          {navItems.map(({ path, label, icon: Icon, highlight, danger }) => (
            <NavLink
              key={path}
              to={path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-2.5 mx-2 mb-1 rounded-lg transition-all duration-200 group
                ${isActive
                  ? danger
                    ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                    : highlight
                      ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                      : 'bg-qs-blue/20 text-qs-blue border border-qs-blue/30'
                  : 'text-qs-text-dim hover:text-qs-text hover:bg-qs-card'
                }
                ${collapsed ? 'justify-center px-2' : ''}
              `}
              title={collapsed ? label : undefined}
            >
              <Icon size={18} className={`flex-shrink-0 ${danger ? 'text-red-400' : highlight ? 'text-purple-400' : ''}`} />
              {!collapsed && (
                <span className="text-sm font-medium truncate">{label}</span>
              )}
              {!collapsed && highlight && (
                <span className="ml-auto">
                  <Zap size={12} className="text-purple-400" />
                </span>
              )}
              {!collapsed && danger && (
                <span className="ml-auto">
                  <Zap size={12} className="text-red-400" />
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Status indicator */}
        {!collapsed && (
          <div className="p-4 border-t border-qs-border">
            <div className="flex items-center gap-2 text-xs text-qs-text-dim">
              <Activity size={12} className="text-qs-green animate-pulse" />
              <span>System Active</span>
            </div>
          </div>
        )}

        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex items-center justify-center h-10 border-t border-qs-border text-qs-text-dim hover:text-qs-text transition-colors"
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        {children}
      </main>
    </div>
  )
}
