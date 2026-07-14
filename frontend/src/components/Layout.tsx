import { useState, useEffect, useMemo } from 'react'
import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom'
import api from '../api/client'
import {
  LayoutDashboard, FolderKanban, Search, ShieldAlert, Sparkles, Zap,
  Server, FileCheck, FileBarChart, ScrollText, Wrench, Settings,
  LogOut, Menu, Shield, Key, Users, Bell,
  Target, ClipboardList, Ticket, Eye, BookOpen
} from 'lucide-react'
import ChangePasswordModal from './ChangePasswordModal'
import CommandPalette from './CommandPalette'
import ThemeSwitcher from './ThemeSwitcher'
import LanguageSwitcher from './LanguageSwitcher'
import { useI18n } from '../i18n'
import { getLogoUrl, fetchLogoUrl } from '../branding'

interface User { email: string; name: string; role: string }

interface NavItem { to: string; icon: React.ReactNode; labelKey: string; end?: boolean; adminOnly?: boolean }
const buildNavGroups = (isAdmin: boolean): { labelKey: string; items: NavItem[] }[] => [
  {
    labelKey: 'group.overview',
    items: [{ to: '/', icon: <Target size={18} />, labelKey: 'nav.today', end: true }]
  },
  {
    labelKey: 'group.workflow',
    items: [
      { to: '/vulnerabilities', icon: <ShieldAlert size={18} />, labelKey: 'nav.vulnerabilities' },
      { to: '/scans', icon: <Search size={18} />, labelKey: 'nav.scans' },
      { to: '/tickets', icon: <Ticket size={18} />, labelKey: 'nav.tickets' },
      { to: '/alerts', icon: <Bell size={18} />, labelKey: 'nav.alerts' },
    ]
  },
  {
    labelKey: 'group.analysis',
    items: [
      { to: '/investigation', icon: <Eye size={18} />, labelKey: 'nav.investigation' },
      { to: '/ai', icon: <Sparkles size={18} />, labelKey: 'nav.ai' },
      { to: '/knowledge-base', icon: <BookOpen size={18} />, labelKey: 'nav.knowledge' },
      { to: '/skills', icon: <Zap size={18} />, labelKey: 'nav.skills' },
    ]
  },
  {
    labelKey: 'group.config',
    items: [
      { to: '/projects', icon: <FolderKanban size={18} />, labelKey: 'nav.projects' },
      { to: '/tools', icon: <Wrench size={18} />, labelKey: 'nav.tools' },
      { to: '/assets', icon: <Server size={18} />, labelKey: 'nav.assets' },
      { to: '/rules', icon: <FileCheck size={18} />, labelKey: 'nav.rules' },
    ]
  },
  {
    labelKey: 'group.compliance',
    items: [
      { to: '/reports', icon: <FileBarChart size={18} />, labelKey: 'nav.reports' },
      { to: '/audit', icon: <ScrollText size={18} />, labelKey: 'nav.audit' },
    ]
  },
  {
    labelKey: 'group.system',
    items: [
      ...(isAdmin ? [{ to: '/users', icon: <Users size={18} />, labelKey: 'nav.users', adminOnly: true }] : []),
      { to: '/settings', icon: <Settings size={18} />, labelKey: 'nav.settings' },
    ]
  },
]

export default function Layout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { t } = useI18n()
  const [user, setUser] = useState<User | null>(null)
  const [collapsed, setCollapsed] = useState(false)
  const [tokenWarning, setTokenWarning] = useState(false)
  const [showPasswordModal, setShowPasswordModal] = useState(false)
  const [forcedPwd, setForcedPwd] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [logoUrl, setLogoUrl] = useState(getLogoUrl())

  // 全局快捷键：Ctrl/Cmd + K 唤起命令面板
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen(o => !o)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => { loadUser() }, [])

  // 强制修改默认口令：本次登录若服务端要求（sessionStorage 标记），挂载即弹出且不可关闭。
  // 注意：标记仅在本次登录时由 /auth/login 写入、改密成功后清除，不再依赖永久 localStorage，
  // 因此密码改掉后不会再被反复弹窗。
  useEffect(() => {
    if (sessionStorage.getItem('sentinel_force_pwd') === '1') {
      setForcedPwd(true)
      setShowPasswordModal(true)
    }
  }, [])

  // 拉取平台 Logo（管理员可能在后台改过）
  useEffect(() => {
    fetchLogoUrl().then(setLogoUrl)
  }, [])

  // Listen for token-expiring event from api client
  useEffect(() => {
    const handler = () => setTokenWarning(true)
    window.addEventListener('sentinel:token-expiring', handler)
    return () => window.removeEventListener('sentinel:token-expiring', handler)
  }, [])

  const loadUser = async () => {
    try {
      const res = await api.get('/auth/me')
      setUser(res.data)
      localStorage.setItem('sentinel_user', JSON.stringify(res.data))
    } catch { logout() }
  }

  const logout = () => { localStorage.clear(); navigate('/login') }

  const handlePwdChanged = () => {
    sessionStorage.removeItem('sentinel_force_pwd')
    localStorage.removeItem('sentinel_force_pwd')
    setForcedPwd(false)
    setShowPasswordModal(false)
  }

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-200 ${
      isActive
        ? 'bg-primary-500/10 text-primary-300 border border-primary-500/15 shadow-[0_0_12px_rgba(59,130,246,0.08)]'
        : 'text-slate-400 hover:text-slate-200 hover:bg-surface-800/50 border border-transparent'
    }`

  const pageTitle = () => {
    const allItems = navGroups.flatMap(g => g.items)
    const current = allItems.find(i => location.pathname === i.to || (i.end && i.to !== '/' && location.pathname.startsWith(i.to)))
    return current ? t(current.labelKey) : t('nav.today')
  }

  const roleMap: Record<string, string> = { admin: '安全管理员', security_analyst: '安全分析师', developer: '开发人员', viewer: '只读用户' }

  const navGroups = useMemo(() => buildNavGroups(user?.role === 'admin'), [user?.role])

  return (
    <div className="flex h-screen overflow-hidden bg-surface-950">
      {/* ── Sidebar ── */}
      <aside className={`flex-shrink-0 bg-surface-900/80 backdrop-blur-xl border-r border-white/[0.03] flex flex-col transition-all duration-300 ${collapsed ? 'w-16' : 'w-60'}`}>
        {/* Logo */}
        <div className="p-4 border-b border-white/[0.03]">
          <div className="flex items-center gap-3">
            {logoUrl ? (
              <img
                src={logoUrl}
                alt="logo"
                className="w-9 h-9 rounded-xl object-cover ring-1 ring-primary-400/20 flex-shrink-0"
              />
            ) : (
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center shadow-[0_0_16px_rgba(59,130,246,0.2)] flex-shrink-0 ring-1 ring-primary-400/20">
                <Shield size={18} strokeWidth={2.5} className="text-white" />
              </div>
            )}
            {!collapsed && (
              <div>
                <span className="font-bold text-white text-base tracking-tight">Sentinel</span>
                <p className="text-[10px] text-slate-500 leading-none mt-0.5">{t('login.brandSubtitle')}</p>
              </div>
            )}
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-3 space-y-5 overflow-y-auto">
          {navGroups.map(group => (
            <div key={group.labelKey}>
              {!collapsed && (
                <div className="px-3 mb-1.5 text-[10px] font-bold uppercase tracking-[0.15em] text-slate-500/70">
                  {t(group.labelKey)}
                </div>
              )}
              <div className="space-y-0.5">
                {group.items.map(item => (
                  <NavLink key={item.to} to={item.to} end={item.end} className={linkClass}>
                    <span className="flex-shrink-0">{item.icon}</span>
                    {!collapsed && <span>{t(item.labelKey)}</span>}
                    {!collapsed && location.pathname === item.to && (
                      <span className="ml-auto w-1.5 h-1.5 rounded-full bg-primary-400 shadow-[0_0_6px_rgba(59,130,246,0.6)]" />
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* User */}
        <div className="p-3 border-t border-white/[0.03]">
          <div className="flex items-center gap-3 px-2 py-2">
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary-500/20 to-accent-500/20 border border-primary-500/15 flex items-center justify-center text-primary-300 text-xs font-bold flex-shrink-0">
              {user?.name?.charAt(0) || user?.email?.charAt(0) || 'S'}
            </div>
            {!collapsed && (
              <>
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-slate-200 truncate font-medium">{user?.name || user?.email}</div>
                  <div className="text-[11px] text-slate-500">{roleMap[user?.role || ''] || user?.role || '-'}</div>
                </div>
                <button onClick={() => setShowPasswordModal(true)} className="text-slate-500 hover:text-primary-400 transition-colors p-1 rounded-lg hover:bg-primary-500/5" title={t('common.changePassword')}>
                  <Key size={14} />
                </button>
                <button onClick={logout} className="text-slate-500 hover:text-red-400 transition-colors p-1 rounded-lg hover:bg-red-500/5" title={t('common.logout')}>
                  <LogOut size={15} />
                </button>
              </>
            )}
          </div>
        </div>
      </aside>

      {/* ── Main ── */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <header className="bg-surface-900/60 backdrop-blur-2xl border-b border-white/[0.03] px-6 py-3 flex items-center justify-between sticky top-0 z-10">
          <div className="flex items-center gap-4">
            <button
              onClick={() => setCollapsed(!collapsed)}
              className="text-slate-500 hover:text-slate-300 p-1.5 rounded-lg hover:bg-surface-800/60 transition-all"
            >
              <Menu size={18} />
            </button>
            <div>
              <h1 className="text-base font-semibold text-white">{pageTitle()}</h1>
            </div>

            <div className="flex items-center gap-2 ml-auto">
              <ThemeSwitcher />
              <LanguageSwitcher />
              <button
                onClick={() => setPaletteOpen(true)}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-white/[0.06] bg-surface-800/50 text-slate-400 hover:text-slate-200 hover:border-white/10 transition-all text-sm"
                title="全局搜索 (Ctrl/Cmd + K)"
              >
                <Search size={15} />
                <span className="hidden sm:inline">{t('common.search')}</span>
                <kbd className="hidden sm:inline text-[10px] text-slate-500 border border-white/10 rounded px-1 py-0.5">⌘K</kbd>
              </button>
            </div>
          </div>

        </header>

        {/* Token expiry warning banner */}
        {tokenWarning && (
          <div className="flex items-center justify-between px-4 py-2 bg-orange-500/10 border-b border-orange-500/20 text-orange-300 text-xs">
            <span className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-orange-400 animate-pulse" />
              会话即将在 5 分钟后到期，操作不会自动保存。
            </span>
            <div className="flex items-center gap-3">
              <button onClick={() => { logout() }} className="underline hover:no-underline">重新登录</button>
              <button onClick={() => setTokenWarning(false)} className="text-orange-400/60 hover:text-orange-300">✕</button>
            </div>
          </div>
        )}

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 bg-grid">
          <div className="animate-fade-in">
            <Outlet />
          </div>
        </div>
      </main>

      {/* Change Password Modal */}
      {showPasswordModal && (
        <ChangePasswordModal
          forced={forcedPwd}
          onSuccess={handlePwdChanged}
          onClose={() => { if (!forcedPwd) setShowPasswordModal(false) }}
        />
      )}

      {/* Global Command Palette */}
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  )
}
