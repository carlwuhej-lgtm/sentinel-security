import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'
import {
  Bell, AlertTriangle, CheckCircle2, XCircle, Filter, Search,
  RefreshCw, Clock, Check, ArrowRight
} from 'lucide-react'

interface Alert {
  id: number
  title: string
  severity: string
  status: string
  alert_type: string
  source_type: string
  project_name: string
  vuln_count: number
  critical_count: number
  high_count: number
  created_at: string
  updated_at: string
}

interface AlertStats {
  today_total: number
  today_new: number
  pending: number
  by_status: { status: string; cnt: number }[]
  by_severity: { severity: string; cnt: number }[]
  trend_7d: { date: string; count: number }[]
  recent: Alert[]
}

const severityConfig: Record<string, { label: string; bg: string; border: string; text: string; dot: string }> = {
  critical: { label: '严重', bg: 'bg-red-500/8', border: 'border-l-red-500', text: 'text-red-400', dot: 'bg-red-500' },
  high:     { label: '高危', bg: 'bg-orange-500/8', border: 'border-l-orange-500', text: 'text-orange-400', dot: 'bg-orange-500' },
  medium:   { label: '中危', bg: 'bg-yellow-500/8', border: 'border-l-yellow-500', text: 'text-yellow-400', dot: 'bg-yellow-500' },
  low:      { label: '低危', bg: 'bg-blue-500/8', border: 'border-l-blue-500', text: 'text-blue-400', dot: 'bg-blue-500' },
}

const statusConfig: Record<string, { label: string; icon: React.ReactNode; style: string }> = {
  new:            { label: '未处理', icon: <Bell size={12} />, style: 'bg-red-500/10 text-red-400 border-red-500/20' },
  acknowledged:   { label: '已确认', icon: <CheckCircle2 size={12} />, style: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' },
  resolved:       { label: '已关闭', icon: <CheckCircle2 size={12} />, style: 'bg-green-500/10 text-green-400 border-green-500/20' },
  false_positive: { label: '误报', icon: <XCircle size={12} />, style: 'bg-slate-500/10 text-slate-400 border-slate-500/20' },
}

function formatTime(iso: string): string {
  if (!iso) return '-'
  const d = new Date(iso)
  const now = new Date()
  const diff = now.getTime() - d.getTime()
  const min = Math.floor(diff / 60000)
  const hr = Math.floor(diff / 3600000)
  if (min < 1) return '刚刚'
  if (min < 60) return `${min} 分钟前`
  if (hr < 24) return `${hr} 小时前`
  return iso.slice(0, 16).replace('T', ' ')
}

export default function Alerts() {
  const navigate = useNavigate()
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [stats, setStats] = useState<AlertStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const searchTimer = useRef<ReturnType<typeof setTimeout>>()

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      if (statusFilter) params.set('status', statusFilter)
      if (severityFilter) params.set('severity', severityFilter)
      if (search) params.set('search', search)
      params.set('page', String(page))
      params.set('per_page', '20')

      const [alertsRes, statsRes] = await Promise.all([
        api.get(`/alerts?${params}`),
        api.get('/alerts/stats'),
      ])
      setAlerts(alertsRes.data.items || [])
      setTotal(alertsRes.data.total || 0)
      setStats(statsRes.data)
    } catch {
      // silent
    } finally {
      setLoading(false)
    }
  }, [page, statusFilter, severityFilter, search])

  useEffect(() => { fetchData() }, [fetchData])

  // Debounced search
  const handleSearchChange = (value: string) => {
    setSearch(value)
    if (searchTimer.current) clearTimeout(searchTimer.current)
    searchTimer.current = setTimeout(() => {
      setPage(1)
    }, 400)
  }

  const updateStatus = async (id: number, status: string) => {
    try {
      await api.put(`/alerts/${id}`, { status })
      fetchData()
    } catch { /* silent */ }
  }

  const batchAction = async (action: string) => {
    if (selected.size === 0) return
    try {
      await api.post('/alerts/batch', { ids: Array.from(selected), action })
      setSelected(new Set())
      fetchData()
    } catch { /* silent */ }
  }

  const toggleSelect = (id: number) => {
    const next = new Set(selected)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSelected(next)
  }

  const toggleAll = () => {
    if (selected.size === alerts.length) {
      setSelected(new Set())
    } else {
      setSelected(new Set(alerts.map(a => a.id)))
    }
  }

  const severityCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  if (stats?.by_severity) {
    stats.by_severity.forEach(s => { severityCounts[s.severity] = s.cnt })
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">告警中心</h1>
          <p className="text-sm text-slate-400 mt-1">安全告警监控与处置</p>
        </div>
        <button onClick={fetchData} className="btn-secondary text-xs">
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          刷新
        </button>
      </div>

      {/* ── Stats Row ── */}
      {stats && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Today Total */}
          <div className="glass-card-hover !p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/15 flex items-center justify-center shrink-0">
              <Bell size={18} className="text-blue-400" />
            </div>
            <div className="min-w-0">
              <div className="stat-value text-lg">{stats.today_total}</div>
              <div className="stat-label">今日告警</div>
            </div>
          </div>

          {/* Pending */}
          <div className="glass-card-hover !p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/15 flex items-center justify-center shrink-0">
              <AlertTriangle size={18} className="text-red-400" />
            </div>
            <div className="min-w-0">
              <div className="stat-value text-lg text-red-400">{stats.pending}</div>
              <div className="stat-label">待处理</div>
            </div>
          </div>

          {/* Today New */}
          <div className="glass-card-hover !p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-orange-500/10 border border-orange-500/15 flex items-center justify-center shrink-0">
              <Clock size={18} className="text-orange-400" />
            </div>
            <div className="min-w-0">
              <div className="stat-value text-lg">{stats.today_new}</div>
              <div className="stat-label">今日新增</div>
            </div>
          </div>

          {/* Resolved */}
          <div className="glass-card-hover !p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-green-500/10 border border-green-500/15 flex items-center justify-center shrink-0">
              <CheckCircle2 size={18} className="text-green-400" />
            </div>
            <div className="min-w-0">
              <div className="stat-value text-lg">
                {stats.by_status.find(s => s.status === 'resolved')?.cnt || 0}
              </div>
              <div className="stat-label">已关闭</div>
            </div>
          </div>
        </div>
      )}

      {/* ── Severity Breakdown ── */}
      {stats && (
        <div className="glass-card !p-4">
          <div className="flex items-center gap-6">
            <span className="text-xs text-slate-500 font-medium">告警级别分布</span>
            {(Object.entries(severityConfig) as [string, typeof severityConfig[string]][]).map(([key, cfg]) => (
              <div key={key} className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${cfg.dot}`} />
                <span className="text-xs text-slate-400">{cfg.label}</span>
                <span className={`text-sm font-bold ${cfg.text}`}>{severityCounts[key] || 0}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Filters + Batch Actions ── */}
      <div className="glass-card !p-4">
        <div className="flex flex-wrap items-center gap-3">
          <Filter size={15} className="text-slate-500 shrink-0" />

          <select
            value={statusFilter}
            onChange={e => { setStatusFilter(e.target.value); setPage(1) }}
            className="bg-surface-800 text-slate-300 text-sm rounded-lg px-3 py-2 border border-white/10 focus:outline-none focus:border-primary-500/50"
          >
            <option value="">全部状态</option>
            <option value="new">未处理</option>
            <option value="acknowledged">已确认</option>
            <option value="resolved">已关闭</option>
            <option value="false_positive">误报</option>
          </select>

          <select
            value={severityFilter}
            onChange={e => { setSeverityFilter(e.target.value); setPage(1) }}
            className="bg-surface-800 text-slate-300 text-sm rounded-lg px-3 py-2 border border-white/10 focus:outline-none focus:border-primary-500/50"
          >
            <option value="">全部级别</option>
            <option value="critical">严重</option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
          </select>

          <div className="relative flex-1 min-w-[180px] max-w-[320px]">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="搜索告警标题..."
              value={search}
              onChange={e => handleSearchChange(e.target.value)}
              className="w-full bg-surface-800 text-slate-300 text-sm rounded-lg pl-9 pr-3 py-2 border border-white/10 focus:outline-none focus:border-primary-500/50"
            />
          </div>

          <div className="flex-1" />

          {selected.size > 0 && (
            <div className="flex items-center gap-2 rounded-lg bg-primary-500/10 border border-primary-500/15 px-3 py-2">
              <span className="text-primary-300 text-sm font-medium">{selected.size} 条选中</span>
              <span className="text-slate-600">|</span>
              <button onClick={() => batchAction('acknowledge')} className="text-xs text-slate-300 hover:text-white px-2 py-1 rounded bg-white/5 hover:bg-white/10 transition-colors">
                标记已确认
              </button>
              <button onClick={() => batchAction('resolve')} className="text-xs text-green-400 hover:text-green-300 px-2 py-1 rounded bg-green-500/10 hover:bg-green-500/15 transition-colors">
                批量关闭
              </button>
            </div>
          )}

          {selected.size > 0 && (
            <button
              onClick={toggleAll}
              className="text-xs text-slate-500 hover:text-slate-300 ml-auto"
            >
              {selected.size === alerts.length ? '取消全选' : '全选'}
            </button>
          )}
        </div>
      </div>

      {/* ── Alert Cards ── */}
      <div className="space-y-2">
        {loading ? (
          // Skeleton
          Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="glass-card !p-0 animate-pulse">
              <div className="flex gap-4 p-4">
                <div className="w-1 rounded-full bg-surface-800" />
                <div className="flex-1 space-y-3">
                  <div className="h-4 bg-surface-800 rounded w-3/4" />
                  <div className="h-3 bg-surface-800 rounded w-1/2" />
                  <div className="flex gap-3">
                    <div className="h-6 w-16 bg-surface-800 rounded-full" />
                    <div className="h-6 w-14 bg-surface-800 rounded-full" />
                  </div>
                </div>
              </div>
            </div>
          ))
        ) : alerts.length === 0 ? (
          <div className="glass-card">
            <div className="flex flex-col items-center justify-center py-16">
              <div className="w-16 h-16 rounded-2xl bg-green-500/10 border border-green-500/15 flex items-center justify-center mb-4">
                <CheckCircle2 size={36} className="text-green-400" />
              </div>
              <p className="text-slate-400 font-medium text-base">暂无告警</p>
              <p className="text-slate-600 text-sm mt-1">系统安全状态良好</p>
            </div>
          </div>
        ) : (
          <>
            {/* Select all header */}
            {selected.size > 0 && (
              <div className="flex items-center gap-3 text-xs text-slate-400 px-1">
                <span>{selected.size} / {alerts.length} 条已选</span>
              </div>
            )}

            {alerts.map(alert => {
              const sev = severityConfig[alert.severity] || severityConfig.low
              const st = statusConfig[alert.status] || statusConfig.new
              const isSelected = selected.has(alert.id)

              return (
                <div
                  key={alert.id}
                  className={`glass-card-hover !p-0 cursor-pointer transition-all duration-200 border-l-4 ${sev.border} ${isSelected ? 'ring-1 ring-primary-500/30 bg-primary-500/[0.03]' : 'border-l-white/[0.03]'}`}
                  style={{ borderLeftColor: isSelected ? undefined : undefined }}
                  onClick={() => toggleSelect(alert.id)}
                >
                  <div className="flex items-start gap-4 p-4">
                    {/* Checkbox */}
                    <div className="pt-0.5 shrink-0">
                      <div className={`w-4 h-4 rounded border-2 flex items-center justify-center transition-colors ${
                        isSelected
                          ? 'bg-primary-500 border-primary-500'
                          : 'border-slate-600 hover:border-slate-400'
                      }`}>
                        {isSelected && <Check size={10} className="text-white" />}
                      </div>
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0" onClick={e => e.stopPropagation()}>
                      {/* Title row */}
                      <div className="flex items-start justify-between gap-3 mb-2">
                        <div className="flex items-center gap-2 min-w-0 flex-wrap">
                          <span
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold border ${sev.bg} ${sev.text} border-current/20`}
                          >
                            <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
                            {sev.label}
                          </span>
                          <span className="text-slate-300 font-medium text-sm truncate">{alert.title}</span>
                        </div>
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-medium border ${st.style} shrink-0`}>
                          {st.icon}
                          {st.label}
                        </span>
                      </div>

                      {/* Meta row */}
                      <div className="flex items-center gap-4 text-xs text-slate-500 mb-3">
                        {alert.project_name && (
                          <span className="flex items-center gap-1">
                            <span className="w-3 h-3 rounded bg-primary-500/20 inline-block" />
                            {alert.project_name}
                          </span>
                        )}
                        <span className="flex items-center gap-1">
                          <Clock size={11} />
                          {formatTime(alert.created_at)}
                        </span>
                        <span className="flex items-center gap-1">
                          <AlertTriangle size={11} />
                          漏洞 {alert.vuln_count || 0} 个
                          {alert.critical_count > 0 && (
                            <span className="text-red-400 font-medium">（严重 {alert.critical_count}）</span>
                          )}
                        </span>
                      </div>

                      {/* Actions */}
                      <div className="flex items-center gap-2">
                        {alert.status === 'new' && (
                          <>
                            <button
                              onClick={e => { e.stopPropagation(); updateStatus(alert.id, 'acknowledged') }}
                              className="text-xs text-primary-400 hover:text-primary-300 px-2.5 py-1 rounded-lg border border-primary-500/20 hover:bg-primary-500/10 transition-colors"
                            >
                              确认告警
                            </button>
                            <button
                              onClick={e => { e.stopPropagation(); updateStatus(alert.id, 'resolved') }}
                              className="text-xs text-green-400 hover:text-green-300 px-2.5 py-1 rounded-lg border border-green-500/20 hover:bg-green-500/10 transition-colors"
                            >
                              关闭
                            </button>
                          </>
                        )}
                        {alert.status === 'acknowledged' && (
                          <button
                            onClick={e => { e.stopPropagation(); updateStatus(alert.id, 'resolved') }}
                            className="text-xs text-green-400 hover:text-green-300 px-2.5 py-1 rounded-lg border border-green-500/20 hover:bg-green-500/10 transition-colors"
                          >
                            标记已关闭
                          </button>
                        )}
                        {alert.status === 'resolved' && (
                          <span className="text-xs text-slate-600">已处置完成</span>
                        )}
                        {alert.status === 'false_positive' && (
                          <span className="text-xs text-slate-600">已标记误报</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )
            })}

            {/* Pagination */}
            {total > 20 && (
              <div className="flex items-center justify-between pt-4">
                <span className="text-slate-500 text-sm">共 {total} 条告警</span>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="btn-secondary btn-sm disabled:opacity-30"
                  >
                    上一页
                  </button>
                  <span className="text-slate-400 text-sm px-3">{page} / {Math.ceil(total / 20)}</span>
                  <button
                    onClick={() => setPage(p => p + 1)}
                    disabled={page >= Math.ceil(total / 20)}
                    className="btn-secondary btn-sm disabled:opacity-30"
                  >
                    下一页
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
