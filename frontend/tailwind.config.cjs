/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // 主题色全部走 CSS 变量（在 index.css :root 与各 [data-theme] 中定义），
        // 运行时切换 data-theme 即可全站换色。格式需配合 <alpha-value>。
        primary: {
          50:  'rgb(var(--c-primary-50) / <alpha-value>)',
          100: 'rgb(var(--c-primary-100) / <alpha-value>)',
          200: 'rgb(var(--c-primary-200) / <alpha-value>)',
          300: 'rgb(var(--c-primary-300) / <alpha-value>)',
          400: 'rgb(var(--c-primary-400) / <alpha-value>)',
          500: 'rgb(var(--c-primary-500) / <alpha-value>)',
          600: 'rgb(var(--c-primary-600) / <alpha-value>)',
          700: 'rgb(var(--c-primary-700) / <alpha-value>)',
          800: 'rgb(var(--c-primary-800) / <alpha-value>)',
          900: 'rgb(var(--c-primary-900) / <alpha-value>)',
          950: 'rgb(var(--c-primary-950) / <alpha-value>)',
        },
        accent: {
          400: 'rgb(var(--c-accent-400) / <alpha-value>)',
          500: 'rgb(var(--c-accent-500) / <alpha-value>)',
          600: 'rgb(var(--c-accent-600) / <alpha-value>)',
        },
        surface: {
          50:  'rgb(var(--c-surface-50) / <alpha-value>)',
          100: 'rgb(var(--c-surface-100) / <alpha-value>)',
          200: 'rgb(var(--c-surface-200) / <alpha-value>)',
          750: 'rgb(var(--c-surface-750) / <alpha-value>)',
          800: 'rgb(var(--c-surface-800) / <alpha-value>)',
          850: 'rgb(var(--c-surface-850) / <alpha-value>)',
          900: 'rgb(var(--c-surface-900) / <alpha-value>)',
          950: 'rgb(var(--c-surface-950) / <alpha-value>)',
        },
        severity: {
          critical: '#ef4444', high: '#f97316',
          medium: '#eab308',  low: '#22c55e',
          info: '#3b82f6',
        },
        neon: {
          blue: '#3b82f6',
          green: '#10b981',
          purple: '#8b5cf6',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      borderRadius: {
        'xl': '0.75rem', '2xl': '1rem', '3xl': '1.25rem',
      },
      boxShadow: {
        'card': '0 1px 3px 0 rgb(0 0 0 / 0.3), 0 1px 2px -1px rgb(0 0 0 / 0.3)',
        'card-hover': '0 4px 12px -1px rgb(0 0 0 / 0.4), 0 2px 4px -2px rgb(0 0 0 / 0.3)',
        'glow-sm': '0 0 12px rgb(var(--c-primary-500) / 0.12)',
        'glow-md': '0 0 20px rgb(var(--c-primary-500) / 0.18)',
        'glow-lg': '0 0 40px rgb(var(--c-primary-500) / 0.25)',
        'glow-green': '0 0 16px rgb(var(--c-accent-500) / 0.15)',
      },
      animation: {
        'fade-in': 'fadeIn 0.4s ease-out',
        'slide-up': 'slideUp 0.4s ease-out',
        'slide-right': 'slideRight 0.4s ease-out',
        'pulse-soft': 'pulseSoft 2s ease-in-out infinite',
        'count-up': 'countUp 0.8s ease-out',
        'shimmer': 'shimmer 2s ease-in-out infinite',
        'border-glow': 'borderGlow 3s ease-in-out infinite',
      },
      keyframes: {
        fadeIn: { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        slideUp: { '0%': { opacity: '0', transform: 'translateY(12px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
        slideRight: { '0%': { opacity: '0', transform: 'translateX(-8px)' }, '100%': { opacity: '1', transform: 'translateX(0)' } },
        pulseSoft: { '0%, 100%': { opacity: '1' }, '50%': { opacity: '0.65' } },
        countUp: { '0%': { opacity: '0', transform: 'translateY(6px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
        shimmer: { '0%, 100%': { opacity: '0.4' }, '50%': { opacity: '0.8' } },
        borderGlow: { '0%, 100%': { borderColor: 'rgba(59,130,246,0.15)' }, '50%': { borderColor: 'rgba(59,130,246,0.35)' } },
      }
    },
  },
  plugins: [],
}
