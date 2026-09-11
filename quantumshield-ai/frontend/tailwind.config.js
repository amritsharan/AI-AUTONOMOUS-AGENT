/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        'qs-bg': '#0a0e1a',
        'qs-surface': '#111827',
        'qs-card': '#1a2035',
        'qs-border': '#1e2d40',
        'qs-blue': '#3b82f6',
        'qs-purple': '#8b5cf6',
        'qs-cyan': '#06b6d4',
        'qs-green': '#10b981',
        'qs-yellow': '#f59e0b',
        'qs-red': '#ef4444',
        'qs-orange': '#f97316',
        'qs-text': '#e2e8f0',
        'qs-text-dim': '#94a3b8',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'scan-line': 'scan-line 2s linear infinite',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(59, 130, 246, 0.5)' },
          '100%': { boxShadow: '0 0 20px rgba(59, 130, 246, 0.8), 0 0 40px rgba(59, 130, 246, 0.3)' },
        },
        'scan-line': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
      },
    },
  },
  plugins: [],
}
