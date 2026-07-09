import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'
import {
  Ticket as TicketIcon, Plus, Search, AlertTriangle, Clock, CheckCircle2, XCircle,
  Loader2, MessageCircle, Pencil, Trash2, UserCheck
} from 'lucide-react'

interface UserItem {
  id: number; name: string; email: string; role: string;
}

interface TicketItem {
  id: number; title: string; description: string; priority: string;
  status: string; source_type: string; source_id: number;
  assigned_to: number | null; assignee_name: string;
  created_by: number | null; creator_name: string;
  due_date: string; created_at: string; updated_at: string;
}
interface TicketDetail extends TicketItem {
  comments: { id: number; user_name: string; content: string; created_at: string }[];
  source_detail?: any;
}
interface TicketStats {
  open: number; in_progress: number; resolved: number; active: number;
  by_priority: { priority: string; cnt: number }[];
}

const priBadge: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-warning',
  low: 'badge-info',
}
const priLabel: Record<string, string> = {
  critical: '紧急', high: '高', medium: '中', low: '低'
}
const statusBadge: Record<string, string> = {
  open: 'badge-info',
  in_progress: 'badge-warning',
  resolved: 'badge-success',
  closed: 'badge-neutral',
}
const statusLabel: Record<string, string> = {
  open: '待处理', in_progress: '处理中', resolved: '已修复', closed: '已关闭'
}
const statusIcon: Record<string, React.ReactNode> = {
  open: <AlertTriangle size={12} />,
  in_progress: <Clock size={12} />,
  resolved: <CheckCircle2 size={12} />,
  closed: <XCircle size={12} />,
}

function timeAgo(iso: string): string {
  if (!iso) return '-'
  const d = new Date(iso); const now = new Date()
  const diff = now.getTime() - d.getTime()
  const mins = Math.floor(diff / 60000)
  const hrs = Math.floor(diff / 3600000)
  const days = Math.floor(diff / 86400000)
  if (mins < 1) return '刚刚'
  if (mins < 60) return `${mins}分`
  if (hrs < 24) return `${hrs}小时`
  if (days < 7) return `${days}天`
  return iso.slice(5, 16).replace('T', ' ')
}

const perPage = 15

export default function Tickets() {
  const navigate = useNavigate()
  const [tickets, setTickets] = useState<TicketItem[]>([])
  const [stats, setStats] = useState<TicketStats | null>(null)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState('')
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')

  const [detail, setDetail] = useState<TicketDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [commentText, setCommentText] = useState('')

  const [showEdit, setShowEdit] = useState(false)
  const [editForm, setEditForm] = useState({ title: '', description: '', priority: 'medium', status: 'open', due_date: '', assigned_to: null as number | null })
  const [editingId, setEditingId] = useState<number | null>(null)

  // 用户列表（用于分配负责人）
  const [users, setUsers] = useState<UserItem[]>([])
  const [usersLoading, setUsersLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      params.set('page', String(page))
      params.set('per_page', String(perPage))
      if (statusFilter) params.set('status', statusFilter)
      if (search) params.set('search', search)
      const res = await api.get(`/tickets?${params}`)
      setTickets(res.data.items)
      setTotal(res.data.total)
    } catch { /* ignore */ }
    finally { setLoading(false) }
  }

  const loadStats = async () => {
    try {
      const res = await api.get('/tickets/stats')
      setStats(res.data)
    } catch { /* ignore */ }
  }

  useEffect(() => { load(); loadStats() }, [page, statusFilter, search])

  // 加载可分配的用户列表
  const loadUsers = async () => {
    setUsersLoading(true)
    try {
      const res = await api.get('/users?per_page=100')
      setUsers(res.data.items || res.data || [])
    } catch { setUsers([]) }
    finally { setUsersLoading(false) }
  }

  // 首次加载时获取用户列表
  useEffect(() => { loadUsers() }, [])

  const openDetail = async (id: number) => {
    setDetailLoading(true)
    setDetail(null)
    try {
      const res = await api.get(`/tickets/${id}`)
      setDetail(res.data)
    } catch { /* ignore */ }
    finally { setDetailLoading(false) }
  }

  const updateStatus = async (id: number, newStatus: string) => {
    try {
      await api.put(`/tickets/${id}`, { status: newStatus })
      load()
      if (detail?.id === id) setDetail({ ...detail, status: newStatus })
    } catch { /* ignore */ }
  }

  const addComment = async () => {
    if (!detail || !commentText.trim()) return
    try {
      await api.post(`/tickets/${detail.id}/comments`, { content: commentText.trim() })
      setCommentText('')
      openDetail(detail.id)
    } catch { /* ignore */ }
  }

  const openEdit = (t: TicketItem) => {
    setEditingId(t.id)
    setEditForm({
      title: t.title, description: t.description || '', priority: t.priority,
      status: t.status, due_date: t.due_date || '', assigned_to: t.assigned_to || null
    })
    setShowEdit(true)
  }

  const saveEdit = async () => {
    try {
      if (editingId) {
        await api.put(`/tickets/${editingId}`, editForm)
      } else {
        await api.post('/tickets', editForm)
      }
      setShowEdit(false)
      load()
      if (editingId && detail?.id === editingId) openDetail(editingId)
    } catch { /* ignore */ }
  }

  const deleteTicket = async (id: number) => {
    if (!confirm('确定要删除这个工单吗？')) return
    try {
      await api.delete(`/tickets/${id}`)
      setDetail(null)
      load()
    } catch { /* ignore */ }
  }

  const doSearch = () => { setSearch(searchInput); setPage(1) }

  return (
    <div className="max-w-7xl mx-auto">
      {/* ── Page Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">工单中心</h1>
          <p className="page-subtitle">漏洞修复追踪与工单流转</p>
        </div>
        <button onClick={() => { setEditingId(null); setEditForm({ title: '', description: '', priority: 'medium', status: 'open', due_date: '', assigned_to: null }); setShowEdit(true) }}
          className="btn-primary text-xs">
          <Plus size={14} /> 新建工单
        </button>
      </div>

      {/* ── 统计条 ── */}
      {stats && (
        <div className="flex items-center gap-3 mb-5 flex-wrap">
          <StatusTab active={statusFilter === ''} onClick={() => { setStatusFilter(''); setPage(1) }} label="全部" count={stats.active} />
          <StatusTab active={statusFilter === 'open'} onClick={() => { setStatusFilter('open'); setPage(1) }} label="待处理" count={stats.open} color="text-blue-400" />
          <StatusTab active={statusFilter === 'in_progress'} onClick={() => { setStatusFilter('in_progress'); setPage(1) }} label="处理中" count={stats.in_progress} color="text-yellow-400" />
          <StatusTab active={statusFilter === 'resolved'} onClick={() => { setStatusFilter('resolved'); setPage(1) }} label="已修复" count={stats.resolved} color="text-green-400" />
          {stats.by_priority.some(p => p.priority === 'critical' && p.cnt > 0) && (
            <span className="badge-critical text-xs">
              紧急 {stats.by_priority.find(p => p.priority === 'critical')?.cnt || 0}
            </span>
          )}
        </div>
      )}

      {/* ── 工具栏 ── */}
      <div className="flex items-center gap-3 mb-5">
        <div className="flex-1 flex items-center gap-2 bg-surface-800/50 border border-white/[0.04] rounded-xl px-3 py-2">
          <Search size={15} className="text-slate-500" />
          <input
            className="flex-1 bg-transparent border-none outline-none text-sm text-slate-200 placeholder-slate-600"
            placeholder="搜索工单..."
            value={searchInput}
            onChange={e => setSearchInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && doSearch()}
          />
        </div>
        <button onClick={doSearch} className="btn-secondary">搜索</button>
      </div>

      {/* ── 工单列表 ── */}
      {loading ? (
        <div className="flex items-center justify-center h-48"><Loader2 size={24} className="animate-spin text-slate-500" /></div>
      ) : tickets.length === 0 ? (
        <div className="glass-card text-center py-12">
          <div className="empty-state-icon mx-auto mb-3"><TicketIcon size={24} /></div>
          <p className="text-slate-400 text-sm">暂无工单</p>
          <p className="text-slate-600 text-xs mt-1">从漏洞或告警页面快捷创建工单来追踪修复</p>
        </div>
      ) : (
        <div className="space-y-2">
          {tickets.map(t => (
            <div
              key={t.id}
              className="glass-card-hover !p-4 flex items-center gap-4 cursor-pointer group"
              onClick={() => openDetail(t.id)}
            >
              <span className={`badge text-[11px] ${priBadge[t.priority] || 'badge-warning'}`}>
                {priLabel[t.priority] || t.priority}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-slate-200 truncate group-hover:text-white transition-colors">{t.title}</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-[11px] text-slate-500">{t.assignee_name || '未分配'}</span>
                  {t.source_type !== 'manual' && (
                    <span className="text-[11px] text-slate-600">
                      {t.source_type === 'vuln' ? '来自漏洞' : t.source_type === 'alert' ? '来自告警' : t.source_type}
                    </span>
                  )}
                </div>
              </div>
              <span className={`badge text-[11px] ${statusBadge[t.status] || 'badge-neutral'}`}>
                {statusIcon[t.status]}{statusLabel[t.status] || t.status}
              </span>
              <span className="text-[11px] text-slate-600">{timeAgo(t.created_at)}</span>
              <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                <button onClick={e => { e.stopPropagation(); openEdit(t) }} className="p-1.5 text-slate-500 hover:text-primary-400 rounded-lg hover:bg-primary-500/10 transition-all"><Pencil size={13} /></button>
                <button onClick={e => { e.stopPropagation(); deleteTicket(t.id) }} className="p-1.5 text-slate-500 hover:text-red-400 rounded-lg hover:bg-red-500/10 transition-all"><Trash2 size={13} /></button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── 分页 ── */}
      {total > perPage && (
        <div className="flex items-center justify-center gap-2 mt-6">
          {Array.from({ length: Math.ceil(total / perPage) }, (_, i) => (
            <button
              key={i}
              onClick={() => setPage(i + 1)}
              className={`px-3 py-1.5 text-sm rounded-lg transition-all ${page === i + 1 ? 'bg-primary-500/10 text-primary-400 border border-primary-500/20' : 'text-slate-500 hover:text-slate-300 hover:bg-surface-800/50'}`}
            >
              {i + 1}
            </button>
          ))}
        </div>
      )}

      {/* ── 详情模态框 ── */}
      {detail && (
        <div className="modal-overlay" onClick={() => setDetail(null)}>
          <div className="modal max-w-2xl" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div className="flex items-center gap-3">
                <span className={`badge text-xs ${priBadge[detail.priority]}`}>{priLabel[detail.priority]}</span>
                <h3 className="text-lg font-semibold text-white">{detail.title}</h3>
              </div>
              <button onClick={() => setDetail(null)} className="p-1.5 text-slate-500 hover:text-slate-300 rounded-lg hover:bg-surface-800"><XCircle size={18} /></button>
            </div>
            <div className="modal-body space-y-4">
              <div className="flex items-center gap-2 flex-wrap">
                {['open', 'in_progress', 'resolved', 'closed'].map(s => (
                  <button
                    key={s}
                    onClick={() => updateStatus(detail.id, s)}
                    className={`flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs border transition-all ${detail.status === s ? `${statusBadge[s]}` : 'border-transparent text-slate-500 hover:text-slate-300 hover:bg-surface-800'}`}
                  >
                    {statusIcon[s]} {statusLabel[s]}
                  </button>
                ))}
              </div>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <InfoRow label="负责人" value={detail.assignee_name || '未分配'} />
                <InfoRow label="创建者" value={detail.creator_name || '-'} />
                <InfoRow label="来源" value={detail.source_type === 'vuln' ? '漏洞' : detail.source_type === 'alert' ? '告警' : '手动'} />
                <InfoRow label="截止日期" value={detail.due_date ? detail.due_date.slice(0, 16) : '-'} />
                <InfoRow label="创建时间" value={detail.created_at.slice(0, 16)} />
                <InfoRow label="更新时间" value={detail.updated_at.slice(0, 16)} />
              </div>
              {detail.description && (
                <div>
                  <div className="text-xs font-medium text-slate-400 mb-1.5">描述</div>
                  <div className="text-sm text-slate-300 bg-surface-800/40 rounded-xl p-3 whitespace-pre-wrap">{detail.description}</div>
                </div>
              )}
              {detail.source_detail && (
                <div>
                  <div className="text-xs font-medium text-slate-400 mb-1.5">关联{detail.source_type === 'vuln' ? '漏洞' : '告警'}</div>
                  <div className="bg-surface-800/40 rounded-xl p-3">
                    <p className="text-sm text-slate-300">{detail.source_detail.title}</p>
                    <p className="text-xs text-slate-500 mt-1">
                      严重度: {detail.source_detail.severity} · 状态: {detail.source_detail.status}
                    </p>
                  </div>
                </div>
              )}
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <MessageCircle size={14} className="text-slate-400" />
                  <span className="text-xs font-medium text-slate-400">评论 ({detail.comments?.length || 0})</span>
                </div>
                {detail.comments?.length === 0 && <p className="text-xs text-slate-600">暂无评论</p>}
                {detail.comments?.map(c => (
                  <div key={c.id} className="mb-2 pl-3 border-l-2 border-white/[0.04]">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-xs font-medium text-slate-400">{c.user_name || '系统'}</span>
                      <span className="text-[10px] text-slate-600">{timeAgo(c.created_at)}</span>
                    </div>
                    <p className="text-sm text-slate-300">{c.content}</p>
                  </div>
                ))}
                <div className="flex items-center gap-2 mt-3">
                  <input
                    className="flex-1 bg-surface-800/50 border border-white/[0.04] rounded-xl px-3 py-2 text-sm text-slate-200 outline-none placeholder-slate-600"
                    placeholder="添加评论..."
                    value={commentText}
                    onChange={e => setCommentText(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && addComment()}
                  />
                  <button onClick={addComment} className="btn-primary text-xs">发送</button>
                </div>
              </div>
            </div>
            <div className="modal-footer justify-between">
              <button onClick={() => deleteTicket(detail.id)} className="btn-danger text-xs"><Trash2 size={12} /> 删除工单</button>
              <button onClick={() => setDetail(null)} className="btn-secondary text-xs">关闭</button>
            </div>
          </div>
        </div>
      )}

      {/* ── 编辑/新建弹窗 ── */}
      {showEdit && (
        <div className="modal-overlay" onClick={() => setShowEdit(false)}>
          <div className="modal max-w-lg" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="text-lg font-semibold text-white">{editingId ? '编辑工单' : '新建工单'}</h3>
              <button onClick={() => setShowEdit(false)} className="p-1 text-slate-500 hover:text-slate-300"><XCircle size={18} /></button>
            </div>
            <div className="modal-body space-y-4">
              <div className="input-group">
                <label className="input-label">标题</label>
                <input className="input" value={editForm.title} onChange={e => setEditForm({ ...editForm, title: e.target.value })} />
              </div>
              <div className="input-group">
                <label className="input-label">描述</label>
                <textarea className="input h-20 resize-none" value={editForm.description} onChange={e => setEditForm({ ...editForm, description: e.target.value })} />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="input-group">
                  <label className="input-label">优先级</label>
                  <select className="select" value={editForm.priority} onChange={e => setEditForm({ ...editForm, priority: e.target.value })}>
                    <option value="critical">紧急</option>
                    <option value="high">高</option>
                    <option value="medium">中</option>
                    <option value="low">低</option>
                  </select>
                </div>
                <div className="input-group">
                  <label className="input-label">状态</label>
                  <select className="select" value={editForm.status} onChange={e => setEditForm({ ...editForm, status: e.target.value })}>
                    <option value="open">待处理</option>
                    <option value="in_progress">处理中</option>
                    <option value="resolved">已修复</option>
                    <option value="closed">已关闭</option>
                  </select>
                </div>
              </div>
              {/* 负责人选择 */}
              <div className="input-group">
                <label className="input-label"><UserCheck size={13} className="inline mr-1" /> 负责人</label>
                {usersLoading ? (
                  <div className="text-xs text-slate-500">加载用户...</div>
                ) : users.length === 0 ? (
                  <div className="text-xs text-slate-600">暂无可选用户（请先在"用户管理"中添加成员）</div>
                ) : (
                  <select
                    className="select"
                    value={editForm.assigned_to || ''}
                    onChange={e => setEditForm({ ...editForm, assigned_to: e.target.value ? Number(e.target.value) : null })}
                  >
                    <option value="">— 未分配 —</option>
                    {users.map(u => (
                      <option key={u.id} value={u.id}>
                        {u.name || u.email}{u.role !== 'user' ? ` (${u.role})` : ''}
                      </option>
                    ))}
                  </select>
                )}
              </div>
            </div>
            <div className="modal-footer">
              <button onClick={() => setShowEdit(false)} className="btn-secondary">取消</button>
              <button onClick={saveEdit} className="btn-primary">{editingId ? '保存' : '创建'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function StatusTab({ active, onClick, label, count, color }: {
  active: boolean; onClick: () => void; label: string; count: number; color?: string;
}) {
  return (
    <button onClick={onClick}
      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm border transition-all ${
        active ? 'bg-surface-800 border-white/[0.06] text-white font-medium' : 'border-transparent text-slate-500 hover:text-slate-300 hover:bg-surface-800/50'
      }`}
    >
      {label}
      <span className={`text-xs font-bold tabular-nums ${color || 'text-slate-400'}`}>{count}</span>
    </button>
  )
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-slate-500 flex-shrink-0 w-16">{label}</span>
      <span className="text-sm text-slate-300 truncate">{value}</span>
    </div>
  )
}
