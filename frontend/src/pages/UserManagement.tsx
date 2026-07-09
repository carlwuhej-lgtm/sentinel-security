// ─── 用户管理页面 ───
import { useState, useEffect, useMemo } from 'react'
import api from '../api/client'
import {
  Search, Shield, Users, UserCheck, UserX, Clock,
  Trash2, Lock, Unlock, ChevronLeft, ChevronRight,
  AlertTriangle, X, Check, RefreshCw, UserPlus, Mail,
} from 'lucide-react'

interface User {
  id: number; email: string; name: string; role: string
  status: string; created_at: string; last_login: string
  login_fail_count: number; locked_until: string; is_locked: boolean
}

interface RoleInfo {
  name: string; permissions: { resource: string; action: string }[]
  permission_count: number
}

const ROLE_LABELS: Record<string, string> = {
  admin: '安全管理员',
  security_analyst: '安全分析师',
  developer: '开发人员',
  viewer: '只读用户',
}

const ROLE_COLORS: Record<string, string> = {
  admin: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  security_analyst: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  developer: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  viewer: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
}

const ROLE_ORDER = ['admin', 'security_analyst', 'developer', 'viewer']

const PAGE_SIZE = 10

export default function UserManagement() {
  const [users, setUsers] = useState<User[]>([])
  const [roles, setRoles] = useState<RoleInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filterRole, setFilterRole] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [page, setPage] = useState(1)
  const [deleteConfirm, setDeleteConfirm] = useState<User | null>(null)
  const [actionFeedback, setActionFeedback] = useState<{ msg: string; type: 'success' | 'error' } | null>(null)

  // 创建用户弹窗
  const [showCreate, setShowCreate] = useState(false)
  const [cName, setCName] = useState('')
  const [cEmail, setCEmail] = useState('')
  const [cPassword, setCPassword] = useState('')
  const [cRole, setCRole] = useState('developer')
  const [cStatus, setCStatus] = useState('active')
  const [cError, setCError] = useState('')
  const [cLoading, setCLoading] = useState(false)

  const isAdmin = JSON.parse(localStorage.getItem('sentinel_user') || '{}')?.role === 'admin'

  useEffect(() => { loadUsers(); loadRoles() }, [])

  const loadUsers = async () => {
    setLoading(true)
    try {
      const res = await api.get('/auth/users')
      setUsers(res.data || [])
    } catch { /* 非管理员返回少量字段也正常 */ }
    setLoading(false)
  }

  const loadRoles = async () => {
    try {
      const res = await api.get('/auth/roles')
      setRoles(res.data || [])
    } catch {}
  }

  // 筛选
  const filtered = useMemo(() => {
    return users.filter(u => {
      if (search && !u.email.toLowerCase().includes(search.toLowerCase()) && !u.name.toLowerCase().includes(search.toLowerCase())) return false
      if (filterRole && u.role !== filterRole) return false
      if (filterStatus) {
        if (filterStatus === 'locked' && !u.is_locked) return false
        if (filterStatus === 'active' && u.status !== 'active') return false
        if (filterStatus === 'disabled' && u.status !== 'disabled') return false
      }
      return true
    })
  }, [users, search, filterRole, filterStatus])

  // 统计
  const stats = useMemo(() => {
    const byRole: Record<string, number> = {}
    let active = 0; let disabled = 0; let locked = 0
    users.forEach(u => {
      byRole[u.role] = (byRole[u.role] || 0) + 1
      if (u.status === 'disabled') disabled++
      else active++
      if (u.is_locked) locked++
    })
    return { total: users.length, active, disabled, locked, byRole }
  }, [users])

  // 分页
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const paged = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  // 操作函数
  const showFeedback = (msg: string, type: 'success' | 'error') => {
    setActionFeedback({ msg, type })
    setTimeout(() => setActionFeedback(null), 3000)
  }

  const updateUser = async (userId: number, data: Record<string, string>) => {
    try {
      await api.patch(`/auth/users/${userId}`, data)
      await loadUsers()
      showFeedback('更新成功', 'success')
    } catch (e: any) {
      showFeedback(e?.response?.data?.error || '操作失败', 'error')
    }
  }

  const deleteUser = async (userId: number) => {
    try {
      await api.delete(`/auth/users/${userId}`)
      setDeleteConfirm(null)
      await loadUsers()
      showFeedback('用户已删除', 'success')
    } catch (e: any) {
      showFeedback(e?.response?.data?.error || '删除失败', 'error')
    }
  }

  const unlockUser = async (userId: number) => {
    try {
      await api.post(`/auth/users/${userId}/unlock`)
      await loadUsers()
      showFeedback('用户已解锁', 'success')
    } catch (e: any) {
      showFeedback(e?.response?.data?.error || '解锁失败', 'error')
    }
  }

  const createUser = async () => {
    setCError('')
    if (!cEmail || !cPassword) { setCError('邮箱和密码不能为空'); return }
    if (cPassword.length < 8) { setCError('密码至少 8 位'); return }
    setCLoading(true)
    try {
      await api.post('/auth/users', {
        name: cName, email: cEmail, password: cPassword, role: cRole, status: cStatus,
      })
      setShowCreate(false)
      setCName(''); setCEmail(''); setCPassword(''); setCRole('developer'); setCStatus('active')
      await loadUsers()
      showFeedback('用户创建成功', 'success')
    } catch (e: any) {
      setCError(e?.response?.data?.error || '创建失败')
    } finally { setCLoading(false) }
  }

  const formatDate = (d: string) => {
    if (!d) return '—'
    const date = new Date(d)
    if (isNaN(date.getTime())) return d.length > 16 ? d.slice(0, 16) : d
    return date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
  }

  // 角色卡片顺序显示
  const orderedRoleKeys = ROLE_ORDER.filter(r => stats.byRole[r] !== undefined)

  return (
    <div className="max-w-7xl mx-auto space-y-6 animate-fade-in">
      {/* ── 头部 ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">用户管理</h1>
          <p className="page-subtitle">管理系统中的所有用户账号、角色与权限</p>
        </div>
        <button
          onClick={() => { loadUsers(); loadRoles() }}
          className="btn-secondary text-xs">
          <RefreshCw size={14} /> 刷新
        </button>
        {isAdmin && (
          <button
            onClick={() => { setCError(''); setShowCreate(true) }}
            className="btn-primary text-xs">
            <UserPlus size={14} /> 创建用户
          </button>
        )}
      </div>

      {/* ── 操作反馈 Toast ── */}
      {actionFeedback && (
        <div className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm border ${
          actionFeedback.type === 'success'
            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
            : 'bg-red-500/10 border-red-500/20 text-red-400'
        }`}>
          {actionFeedback.type === 'success' ? <Check size={16} /> : <AlertTriangle size={16} />}
          {actionFeedback.msg}
          <button onClick={() => setActionFeedback(null)} className="ml-auto hover:opacity-70"><X size={14} /></button>
        </div>
      )}

      {/* ── 统计卡片 ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-3">
        <div className="bg-surface-900/60 border border-white/[0.04] rounded-xl p-4">
          <div className="flex items-center gap-2 text-slate-400 text-xs mb-1.5">
            <Users size={14} /> 总用户数
          </div>
          <div className="text-2xl font-bold text-white tabular-nums">{stats.total}</div>
        </div>
        <div className="bg-surface-900/60 border border-white/[0.04] rounded-xl p-4">
          <div className="flex items-center gap-2 text-emerald-400 text-xs mb-1.5">
            <UserCheck size={14} /> 正常
          </div>
          <div className="text-2xl font-bold text-white tabular-nums">{stats.active}</div>
        </div>
        <div className="bg-surface-900/60 border border-white/[0.04] rounded-xl p-4">
          <div className="flex items-center gap-2 text-red-400 text-xs mb-1.5">
            <UserX size={14} /> 已禁用
          </div>
          <div className="text-2xl font-bold text-white tabular-nums">{stats.disabled}</div>
        </div>
        <div className="bg-surface-900/60 border border-white/[0.04] rounded-xl p-4">
          <div className="flex items-center gap-2 text-orange-400 text-xs mb-1.5">
            <Lock size={14} /> 锁定中
          </div>
          <div className="text-2xl font-bold text-white tabular-nums">{stats.locked}</div>
        </div>
        {orderedRoleKeys.map(r => (
          <div key={r} className="bg-surface-900/60 border border-white/[0.04] rounded-xl p-4">
            <div className={`text-xs mb-1.5 ${r === 'admin' ? 'text-purple-400' : r === 'security_analyst' ? 'text-blue-400' : r === 'developer' ? 'text-emerald-400' : 'text-slate-400'}`}>
              {ROLE_LABELS[r] || r}
            </div>
            <div className="text-2xl font-bold text-white tabular-nums">{stats.byRole[r] || 0}</div>
          </div>
        ))}
      </div>

      {/* ── 筛选栏 ── */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text" placeholder="搜索邮箱或姓名..."
            value={search} onChange={e => { setSearch(e.target.value); setPage(1) }}
            className="w-full pl-9 pr-3 py-2 bg-surface-800/60 border border-white/[0.05] rounded-lg text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-primary-500/30 focus:ring-1 focus:ring-primary-500/20"
          />
        </div>
        <select
          value={filterRole} onChange={e => { setFilterRole(e.target.value); setPage(1) }}
          className="px-3 py-2 bg-surface-800/60 border border-white/[0.05] rounded-lg text-sm text-slate-300 focus:outline-none focus:border-primary-500/30"
        >
          <option value="">全部角色</option>
          {ROLE_ORDER.map(r => <option key={r} value={r}>{ROLE_LABELS[r] || r}</option>)}
        </select>
        <select
          value={filterStatus} onChange={e => { setFilterStatus(e.target.value); setPage(1) }}
          className="px-3 py-2 bg-surface-800/60 border border-white/[0.05] rounded-lg text-sm text-slate-300 focus:outline-none focus:border-primary-500/30"
        >
          <option value="">全部状态</option>
          <option value="active">正常</option>
          <option value="disabled">已禁用</option>
          <option value="locked">已锁定</option>
        </select>
        {(search || filterRole || filterStatus) && (
          <button
            onClick={() => { setSearch(''); setFilterRole(''); setFilterStatus(''); setPage(1) }}
            className="text-xs text-slate-400 hover:text-white transition-colors px-2 py-1"
          >
            清除筛选
          </button>
        )}
      </div>

      {/* ── 用户表格 ── */}
      <div className="bg-surface-900/40 border border-white/[0.04] rounded-xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20 text-slate-500">
            <RefreshCw size={20} className="animate-spin mr-2" /> 加载中...
          </div>
        ) : paged.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-slate-500">
            <Users size={40} className="mb-3 opacity-30" />
            <p className="text-sm">暂无匹配的用户</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/[0.04]">
                  <th className="text-left px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wider">用户</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wider">角色</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wider">状态</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wider hidden md:table-cell">注册时间</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wider hidden md:table-cell">最后登录</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wider hidden xl:table-cell">登录失败</th>
                  <th className="text-right px-4 py-3 text-xs font-medium text-slate-500 uppercase tracking-wider">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.02]">
                {paged.map(user => (
                  <tr key={user.id} className="hover:bg-white/[0.01] transition-colors group">
                    {/* 用户信息 */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 ${
                          ROLE_COLORS[user.role]?.split(' ')[1] || 'bg-slate-500/15 text-slate-400'
                        }`}>
                          {(user.name || user.email).charAt(0).toUpperCase()}
                        </div>
                        <div className="min-w-0">
                          <div className="text-slate-200 font-medium truncate">{user.name || '未命名'}</div>
                          <div className="text-xs text-slate-500 truncate">{user.email}</div>
                        </div>
                      </div>
                    </td>
                    {/* 角色 */}
                    <td className="px-4 py-3">
                      <select
                        value={user.role}
                        onChange={e => updateUser(user.id, { role: e.target.value })}
                        className={`text-xs font-medium px-2 py-1 rounded-lg border cursor-pointer transition-colors ${ROLE_COLORS[user.role] || 'bg-slate-500/15 text-slate-400 border-slate-500/30'}`}
                      >
                        {ROLE_ORDER.map(r => (
                          <option key={r} value={r}>{ROLE_LABELS[r] || r}</option>
                        ))}
                      </select>
                    </td>
                    {/* 状态 */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {user.is_locked ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-orange-500/15 text-orange-400 border border-orange-500/20">
                            <Lock size={10} /> 已锁定
                          </span>
                        ) : user.status === 'disabled' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/15 text-red-400 border border-red-500/20">
                            <UserX size={10} /> 已禁用
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
                            <UserCheck size={10} /> 正常
                          </span>
                        )}
                      </div>
                    </td>
                    {/* 注册时间 */}
                    <td className="px-4 py-3 text-slate-500 text-xs hidden md:table-cell">{formatDate(user.created_at)}</td>
                    {/* 最后登录 */}
                    <td className="px-4 py-3 text-slate-500 text-xs hidden md:table-cell">
                      {user.last_login ? (
                        <span className="flex items-center gap-1">
                          <Clock size={11} /> {formatDate(user.last_login)}
                        </span>
                      ) : (
                        <span className="text-slate-600">从未登录</span>
                      )}
                    </td>
                    {/* 登录失败次数 */}
                    <td className="px-4 py-3 text-xs hidden xl:table-cell">
                      <span className={user.login_fail_count > 0 ? 'text-orange-400 font-medium' : 'text-slate-500'}>
                        {user.login_fail_count || 0}
                      </span>
                    </td>
                    {/* 操作 */}
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        {/* 解锁按钮 */}
                        {user.is_locked && (
                          <button
                            onClick={() => unlockUser(user.id)}
                            className="p-1.5 rounded-lg text-orange-400 hover:text-orange-300 hover:bg-orange-500/10 transition-colors"
                            title="解锁用户"
                          >
                            <Unlock size={15} />
                          </button>
                        )}
                        {/* 启用/禁用切换 */}
                        {!user.is_locked && (
                          <button
                            onClick={() => updateUser(user.id, { status: user.status === 'disabled' ? 'active' : 'disabled' })}
                            className={`p-1.5 rounded-lg transition-colors ${
                              user.status === 'disabled'
                                ? 'text-emerald-400 hover:text-emerald-300 hover:bg-emerald-500/10'
                                : 'text-red-400 hover:text-red-300 hover:bg-red-500/10'
                            }`}
                            title={user.status === 'disabled' ? '启用用户' : '禁用用户'}
                          >
                            {user.status === 'disabled' ? <UserCheck size={15} /> : <UserX size={15} />}
                          </button>
                        )}
                        {/* 删除按钮 */}
                        <button
                          onClick={() => setDeleteConfirm(user)}
                          className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors opacity-0 group-hover:opacity-100"
                          title="删除用户"
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* 分页 */}
        {filtered.length > PAGE_SIZE && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-white/[0.04]">
            <div className="text-xs text-slate-500">
              共 {filtered.length} 个用户，第 {page} / {totalPages} 页
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-surface-700/60 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft size={16} />
              </button>
              {Array.from({ length: totalPages }, (_, i) => i + 1)
                .filter(p => p === 1 || p === totalPages || Math.abs(p - page) <= 2)
                .map((p, idx, arr) => (
                  <span key={p}>
                    {idx > 0 && arr[idx - 1] !== p - 1 && <span className="text-slate-600 px-1">...</span>}
                    <button
                      onClick={() => setPage(p)}
                      className={`w-7 h-7 rounded-lg text-xs font-medium transition-colors ${
                        page === p
                          ? 'bg-primary-500/20 text-primary-400 border border-primary-500/30'
                          : 'text-slate-400 hover:text-white hover:bg-surface-700/60'
                      }`}
                    >
                      {p}
                    </button>
                  </span>
                ))}
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-surface-700/60 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── 角色权限速览 ── */}
      {roles.length > 0 && (
        <div className="bg-surface-900/40 border border-white/[0.04] rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
            <Shield size={16} className="text-primary-400" />
            角色权限速览
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
            {ROLE_ORDER.map(roleKey => {
              const roleInfo = roles.find(r => r.name === roleKey)
              if (!roleInfo) return null
              return (
                <div key={roleKey} className={`rounded-xl p-3 border ${ROLE_COLORS[roleKey]?.split(' ')[2] || 'border-slate-500/20'}`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className={`text-sm font-semibold ${ROLE_COLORS[roleKey]?.split(' ')[1] || 'text-slate-400'}`}>
                      {ROLE_LABELS[roleKey] || roleKey}
                    </span>
                    <span className="text-xs text-slate-500">{roleInfo.permission_count} 项权限</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {roleInfo.permissions.slice(0, 6).map((p, i) => (
                      <code key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.03] text-slate-400">
                        {p.resource}:{p.action}
                      </code>
                    ))}
                    {roleInfo.permissions.length > 6 && (
                      <span className="text-[10px] text-slate-600">+{roleInfo.permissions.length - 6} more</span>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ── 删除确认弹窗 ── */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-surface-900 border border-white/[0.06] rounded-2xl p-6 w-full max-w-sm shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-red-500/15 flex items-center justify-center">
                <AlertTriangle size={20} className="text-red-400" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-white">确认删除</h3>
                <p className="text-sm text-slate-400">此操作不可撤销</p>
              </div>
            </div>
            <div className="bg-surface-950/60 rounded-xl p-3 mb-4 border border-white/[0.04]">
              <div className="text-sm text-slate-200 font-medium">{deleteConfirm.name || deleteConfirm.email}</div>
              <div className="text-xs text-slate-500 mt-0.5">{deleteConfirm.email}</div>
              <div className="mt-2 inline-block px-2 py-0.5 rounded text-xs font-medium bg-red-500/15 text-red-400 border border-red-500/20">
                {ROLE_LABELS[deleteConfirm.role] || deleteConfirm.role}
              </div>
            </div>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-slate-400 hover:text-white bg-surface-800/60 rounded-lg hover:bg-surface-700/60 transition-colors"
              >
                取消
              </button>
              <button
                onClick={() => deleteUser(deleteConfirm.id)}
                className="px-4 py-2 text-sm font-medium text-white bg-red-500/80 hover:bg-red-500 rounded-lg transition-colors"
              >
                确认删除
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── 创建用户弹窗 ── */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-surface-900 border border-white/[0.06] rounded-2xl p-6 w-full max-w-md shadow-2xl">
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <UserPlus size={18} className="text-primary-400" /> 创建用户
              </h3>
              <button onClick={() => setShowCreate(false)} className="text-slate-500 hover:text-white transition-colors">
                <X size={18} />
              </button>
            </div>

            <div className="space-y-4">
              {/* 姓名 */}
              <div>
                <label className="text-xs text-slate-400 mb-1 block">姓名（可选）</label>
                <input
                  value={cName} onChange={e => setCName(e.target.value)} placeholder="姓名"
                  className="w-full px-3 py-2 bg-surface-800/60 border border-white/[0.05] rounded-lg text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-primary-500/30"
                />
              </div>
              {/* 邮箱 */}
              <div>
                <label className="text-xs text-slate-400 mb-1 block">邮箱 *</label>
                <div className="relative">
                  <Mail size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    value={cEmail} onChange={e => setCEmail(e.target.value)} placeholder="user@company.com"
                    className="w-full pl-9 pr-3 py-2 bg-surface-800/60 border border-white/[0.05] rounded-lg text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-primary-500/30"
                  />
                </div>
              </div>
              {/* 密码 */}
              <div>
                <label className="text-xs text-slate-400 mb-1 block">密码 *（至少 8 位，含大小写字母与数字）</label>
                <div className="relative">
                  <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    type="password" value={cPassword} onChange={e => setCPassword(e.target.value)} placeholder="••••••••"
                    className="w-full pl-9 pr-3 py-2 bg-surface-800/60 border border-white/[0.05] rounded-lg text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-primary-500/30"
                  />
                </div>
              </div>
              {/* 角色 */}
              <div>
                <label className="text-xs text-slate-400 mb-1 block">角色</label>
                <select
                  value={cRole} onChange={e => setCRole(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-800/60 border border-white/[0.05] rounded-lg text-sm text-slate-200 focus:outline-none focus:border-primary-500/30"
                >
                  {ROLE_ORDER.map(r => <option key={r} value={r}>{ROLE_LABELS[r] || r}</option>)}
                </select>
              </div>
              {/* 状态 */}
              <div>
                <label className="text-xs text-slate-400 mb-1 block">状态</label>
                <select
                  value={cStatus} onChange={e => setCStatus(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-800/60 border border-white/[0.05] rounded-lg text-sm text-slate-200 focus:outline-none focus:border-primary-500/30"
                >
                  <option value="active">正常（可登录）</option>
                  <option value="disabled">已禁用（不可登录）</option>
                </select>
              </div>
              {/* 错误提示 */}
              {cError && (
                <div className="rounded-lg bg-red-500/10 border border-red-500/15 px-3 py-2 text-red-400 text-xs flex items-center gap-2">
                  <AlertTriangle size={14} />{cError}
                </div>
              )}
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => setShowCreate(false)}
                className="px-4 py-2 text-sm text-slate-400 hover:text-white bg-surface-800/60 rounded-lg hover:bg-surface-700/60 transition-colors"
              >
                取消
              </button>
              <button
                onClick={createUser} disabled={cLoading}
                className="px-4 py-2 text-sm font-medium text-white bg-primary-500 hover:bg-primary-400 rounded-lg transition-colors disabled:opacity-50"
              >
                {cLoading ? '创建中...' : '创建用户'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
