import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import api from '../api/client'
import {
  Search, Bug, Bell, ChevronRight, ExternalLink, Clock, Loader2,
  Server, RefreshCw, Ticket, Target, AlertTriangle, CheckCircle2
} from 'lucide-react'

interface EventItem {
  id: number; type: 'vuln' | 'alert';
  title: string; severity: string; status: string;
  project_name?: string; file_path?: string;
  cve_id?: string; cwe_id?: string;
  alert_type?: string; vuln_count?: number;
  critical_count?: number; high_count?: number;
  created_at: string; sla_due_date?: string; sla_breached?: number;
  description?: string; fix_suggestion?: string;
  cvss_score?: number; source_tool?: string;
  source_type?: string; source_id?: number;
}
interface RelatedItem {
  id: number; title: string; severity: string; status: string; created_at: string;
}

const sevBadge: Record<string, string> = {
  critical: 'badge-critical', high: 'badge-high', medium: 'badge-warning', low: 'badge-info',
}
const sevDotBg: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-blue-500', info: 'bg-gray-500'
}
const sevLabel: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息'
}
const vulnStatusLabel: Record<string, string> = {
  open: '待修复', in_progress: '修复中', fixed: '已修复', ignored: '已忽略'
}
const alertStatusLabel: Record<string, string> = {
  new: '待确认', acknowledged: '已确认', resolved: '已关闭', false_positive: '误报'
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

export default function Investigation() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const hasAutoSelected = useRef(false)

  const [events, setEvents] = useState<EventItem[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<'all' | 'critical' | 'high' | 'open'>('all')
  const [typeFilter, setTypeFilter] = useState<'all' | 'vuln' | 'alert'>('all')
  const [search, setSearch] = useState('')

  const [selected, setSelected] = useState<EventItem | null>(null)
  const [related, setRelated] = useState<RelatedItem[]>([])
  const [detailLoading, setDetailLoading] = useState(false)
  const [aiResult, setAiResult] = useState<string | null>(null)
  const [aiLoading, setAiLoading] = useState(false)

  const loadEvents = useCallback(async () => {
    setLoading(true)
    try {
      const [vRes, aRes] = await Promise.all([
        api.get('/vulnerabilities?per_page=100&status=open,in_progress'),
        api.get('/alerts?per_page=50&status=new,acknowledged'),
      ])
      const vulnItems = (vRes.data.items || []).map((v: any) => ({ ...v, type: 'vuln' as const }))
      const alertItems = (aRes.data.items || []).map((a: any) => ({ ...a, type: 'alert' as const }))

      let merged = [...vulnItems, ...alertItems]
      if (filter === 'critical') merged = merged.filter(e => e.severity === 'critical')
      if (filter === 'high') merged = merged.filter(e => e.severity === 'critical' || e.severity === 'high')
      if (filter === 'open') merged = merged.filter(e => e.status === 'open' || e.status === 'new')
      if (typeFilter === 'vuln') merged = merged.filter(e => e.type === 'vuln')
      if (typeFilter === 'alert') merged = merged.filter(e => e.type === 'alert')
      if (search) {
        const q = search.toLowerCase()
        merged = merged.filter(e =>
          e.title?.toLowerCase().includes(q) || e.cve_id?.toLowerCase().includes(q) || e.file_path?.toLowerCase().includes(q)
        )
      }
      merged.sort((a, b) => {
        const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
        const sevDiff = (sevOrder[a.severity] || 5) - (sevOrder[b.severity] || 5)
        if (sevDiff !== 0) return sevDiff
        return new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      })
      setEvents(merged)
    } catch { /* ignore */ }
    finally { setLoading(false) }
  }, [filter, typeFilter, search])

  useEffect(() => { loadEvents() }, [loadEvents])

  // 数据加载完成后自动选中第一条
  useEffect(() => {
    if (!loading && events.length > 0 && !hasAutoSelected.current) {
      // 检查 URL 参数
      const vulnId = searchParams.get('vuln')
      const alertId = searchParams.get('alert')
      if (vulnId) {
        const e = events.find(ev => ev.type === 'vuln' && ev.id === parseInt(vulnId))
        if (e) { selectEvent(e); hasAutoSelected.current = true; return }
      }
      if (alertId) {
        const e = events.find(ev => ev.type === 'alert' && ev.id === parseInt(alertId))
        if (e) { selectEvent(e); hasAutoSelected.current = true; return }
      }
      // 默认选第一条
      selectEvent(events[0])
      hasAutoSelected.current = true
    }
    if (events.length === 0) {
      hasAutoSelected.current = false
      setSelected(null)
    }
  }, [loading, events, searchParams])

  const selectEvent = async (e: EventItem) => {
    setSelected(e)
    setAiResult(null)
    setDetailLoading(true)
    try {
      if (e.type === 'vuln') {
        const res = await api.get(`/vulnerabilities/${e.id}`)
        const data = { ...res.data, type: 'vuln' }
        setSelected(data)
        // 恢复已保存的 AI 分析结果
        if (data.ai_analysis) {
          setAiResult(data.ai_analysis)
        }
        try {
          const relRes = await api.get('/vulnerabilities?per_page=10')
          const related = (relRes.data.items || [])
            .filter((v: any) => v.id !== e.id && (v.file_path === e.file_path || v.source_tool === e.source_tool))
            .slice(0, 5)
          setRelated(related.map((r: any) => ({ id: r.id, title: r.title, severity: r.severity, status: r.status, created_at: r.created_at })))
        } catch { setRelated([]) }
      } else {
        const res = await api.get(`/alerts/${e.id}`)
        setSelected({ ...res.data, type: 'alert' })
        setRelated([])
      }
    } catch { /* ignore */ }
    finally { setDetailLoading(false) }
  }

  const runAiAnalysis = async () => {
    if (!selected) return
    setAiLoading(true)
    try {
      // 根据事件类型调用不同的 AI 分析接口
      let result = ''
      if (selected.type === 'vuln') {
        const res = await api.post('/ai/analyze-vulnerability', {
          vulnerability_id: selected.id,
        })
        result = res.data.analysis || JSON.stringify(res.data)
      } else {
        // 告警类：用通用分析
        const res = await api.post('/ai/chat', {
          message: `请分析以下安全告警：\n标题: ${selected.title}\n类型: ${selected.alert_type || '未知'}\n描述: ${selected.description || ''}\n\n请提供：风险评估、可能原因、处置建议`,
          context: { alert_id: selected.id },
        })
        result = res.data.reply || JSON.stringify(res.data)
      }
      setAiResult(result)
      // 自动保存到数据库（仅漏洞类型）
      if (selected.type === 'vuln') {
        try {
          await api.patch(`/vulnerabilities/${selected.id}`, { ai_analysis: result })
        } catch { /* 保存失败不影响用户体验 */ }
      }
    } catch (err: any) {
      const msg = err?.response?.data?.error || err?.message || 'AI 分析暂不可用'
      setAiResult(`AI 分析失败: ${msg}\n\n请确认 AI 服务已配置并正在运行。`)
    }
    finally { setAiLoading(false) }
  }

  const createTicket = async () => {
    if (!selected) return
    try {
      await api.post('/tickets', {
        title: `[${selected.type === 'vuln' ? '漏洞' : '告警'}] ${selected.title.slice(0, 80)}`,
        description: `${selected.description || ''}\n\n来源: ${selected.type === 'vuln' ? '漏洞管理' : '告警中心'}`,
        priority: selected.severity === 'critical' ? 'critical' : selected.severity === 'high' ? 'high' : 'medium',
        source_type: selected.type, source_id: selected.id,
      })
      navigate('/tickets')
    } catch { alert('创建工单失败') }
  }

  // 统计
  const vulnCount = events.filter(e => e.type === 'vuln').length
  const alertCount = events.filter(e => e.type === 'alert').length
  const critCount = events.filter(e => e.severity === 'critical').length
  const highCount = events.filter(e => e.severity === 'high').length

  return (
    <div className="max-w-7xl mx-auto">
      {/* ── Page Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">事件调查</h1>
          <p className="page-subtitle">
            将待处理的漏洞与告警聚合在一个视图中，快速研判、AI 分析、转工单处置
          </p>
        </div>
        <div className="flex items-center gap-2">
          {!loading && (
            <span className="text-xs text-slate-500">
              共 {events.length} 条待调查事件
            </span>
          )}
          <button onClick={loadEvents} className="btn-secondary text-xs"><RefreshCw size={14} /> 刷新</button>
        </div>
      </div>

      {/* ── 统计条 ── */}
      {!loading && events.length > 0 && (
        <div className="grid grid-cols-4 gap-3 mb-5">
          <StatBadge label="漏洞" value={vulnCount} color="text-blue-400" icon={<Bug size={12} />} />
          <StatBadge label="告警" value={alertCount} color="text-orange-400" icon={<Bell size={12} />} />
          <StatBadge label="严重" value={critCount} color="text-red-400" icon={<AlertTriangle size={12} />} />
          <StatBadge label="高危" value={highCount} color="text-orange-400" icon={<AlertTriangle size={12} />} />
        </div>
      )}

      {/* ── 筛选 & 搜索行 ── */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <FilterPill active={filter === 'all'} label="全部" onClick={() => setFilter('all')} />
        <FilterPill active={filter === 'critical'} label="严重" onClick={() => setFilter('critical')} color="text-red-400" />
        <FilterPill active={filter === 'high'} label="高危+" onClick={() => setFilter('high')} color="text-orange-400" />
        <FilterPill active={filter === 'open'} label="待处理" onClick={() => setFilter('open')} color="text-blue-400" />
        <span className="w-px h-4 bg-white/[0.06]" />
        <FilterPill active={typeFilter === 'all'} label="全部类型" onClick={() => setTypeFilter('all')} />
        <FilterPill active={typeFilter === 'vuln'} label="漏洞" onClick={() => setTypeFilter('vuln')} />
        <FilterPill active={typeFilter === 'alert'} label="告警" onClick={() => setTypeFilter('alert')} />
        <div className="flex-1" />
        <div className="flex items-center gap-2 bg-surface-800/40 border border-white/[0.04] rounded-xl px-3 py-1.5 min-w-[200px]">
          <Search size={13} className="text-slate-500 flex-shrink-0" />
          <input
            className="flex-1 bg-transparent border-none outline-none text-xs text-slate-200 placeholder-slate-600"
            placeholder="搜索标题/CVE/文件路径..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* ── 三栏布局 ── */}
      <div className="grid grid-cols-1 lg:grid-cols-[300px_1fr_260px] gap-5">
        {/* ── 左列：事件列表 ── */}
        <div className="glass-card !p-3 overflow-y-auto" style={{ maxHeight: 'calc(100vh - 16rem)' }}>
          {loading ? (
            <div className="flex items-center justify-center h-32"><Loader2 size={18} className="animate-spin text-slate-500" /></div>
          ) : events.length === 0 ? (
            <div className="text-center py-10">
              <CheckCircle2 size={28} className="mx-auto mb-2 text-green-400/60" />
              <p className="text-sm text-slate-400">没有待处理事件</p>
              <p className="text-xs text-slate-600 mt-1">系统运行正常</p>
            </div>
          ) : (
            <div className="space-y-0.5">
              {events.map(e => (
                <div
                  key={`${e.type}-${e.id}`}
                  className={`flex items-start gap-2.5 p-2.5 rounded-lg cursor-pointer transition-all border ${
                    selected?.id === e.id && selected?.type === e.type
                      ? 'bg-primary-500/8 border-primary-500/20 shadow-[0_0_8px_rgba(59,130,246,0.06)]'
                      : 'border-transparent hover:bg-surface-800/50 hover:border-white/[0.03]'
                  }`}
                  onClick={() => selectEvent(e)}
                >
                  <span className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${sevDotBg[e.severity] || 'bg-gray-500'}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5 mb-0.5">
                      <span className={`badge text-[9px] ${sevBadge[e.severity] || 'badge-warning'}`}>
                        {sevLabel[e.severity] || e.severity}
                      </span>
                      {e.type === 'vuln'
                        ? <Bug size={10} className="text-blue-400/60 flex-shrink-0" />
                        : <Bell size={10} className="text-orange-400/60 flex-shrink-0" />
                      }
                      {e.cve_id && <span className="text-[10px] text-slate-500 truncate">{e.cve_id}</span>}
                    </div>
                    <p className="text-xs text-slate-200 truncate leading-relaxed">{e.title}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px] text-slate-600">{timeAgo(e.created_at)}</span>
                      {e.project_name && <span className="text-[10px] text-slate-600 truncate">{e.project_name}</span>}
                    </div>
                  </div>
                  <ChevronRight size={11} className="text-slate-600 mt-1 flex-shrink-0" />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ── 中列：详情 ── */}
        <div className="glass-card">
          {!selected ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <div className="w-14 h-14 rounded-full bg-surface-800/60 flex items-center justify-center mb-4">
                <Target size={22} className="text-slate-500" />
              </div>
              <p className="text-sm text-slate-400 font-medium">选择左侧事件查看详情</p>
              <p className="text-xs text-slate-600 mt-1">
                你可以在这里快速查看漏洞或告警的完整信息，<br />
                使用 AI 辅助分析，或一键转为工单追踪处置。
              </p>
            </div>
          ) : detailLoading ? (
            <div className="flex items-center justify-center h-48"><Loader2 size={22} className="animate-spin text-slate-500" /></div>
          ) : (
            <div className="space-y-5 p-1">
              {/* 标题行 */}
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className={`badge text-[11px] ${sevBadge[selected.severity] || 'badge-warning'}`}>
                    {sevLabel[selected.severity] || selected.severity}
                  </span>
                  {selected.type === 'vuln' ? <Bug size={13} className="text-blue-400" /> : <Bell size={13} className="text-orange-400" />}
                  <span className="text-[11px] text-slate-500">
                    {selected.type === 'vuln'
                      ? vulnStatusLabel[selected.status] || selected.status
                      : alertStatusLabel[selected.status] || selected.status}
                  </span>
                </div>
                <h2 className="text-base font-semibold text-white leading-snug">{selected.title}</h2>
              </div>

              {/* 元数据 */}
              <div className="grid grid-cols-2 gap-1.5">
                {selected.cve_id && <MetaBadge label="CVE" value={selected.cve_id} />}
                {selected.cwe_id && <MetaBadge label="CWE" value={selected.cwe_id} />}
                {selected.cvss_score != null && selected.cvss_score > 0 && <MetaBadge label="CVSS" value={String(selected.cvss_score)} />}
                {selected.source_tool && <MetaBadge label="扫描器" value={selected.source_tool} />}
                {selected.file_path && <MetaBadge label="文件" value={selected.file_path} />}
                {selected.project_name && <MetaBadge label="项目" value={selected.project_name} />}
                {selected.alert_type && <MetaBadge label="告警类型" value={selected.alert_type} />}
                {selected.critical_count !== undefined && selected.critical_count > 0 && (
                  <MetaBadge label="严重漏洞" value={String(selected.critical_count)} color="text-red-400" />
                )}
                {selected.high_count !== undefined && selected.high_count > 0 && (
                  <MetaBadge label="高危漏洞" value={String(selected.high_count)} color="text-orange-400" />
                )}
                <MetaBadge label="发现时间" value={timeAgo(selected.created_at)} />
              </div>

              {/* SLA */}
              {selected.sla_due_date && (
                <div className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs ${
                  selected.sla_breached === 1
                    ? 'bg-red-500/10 border border-red-500/15 text-red-400'
                    : 'bg-yellow-500/5 border border-yellow-500/15 text-yellow-400'
                }`}>
                  <Clock size={13} />
                  <span>SLA: {selected.sla_breached === 1 ? '已超时' : `到期 ${selected.sla_due_date.slice(0, 16)}`}</span>
                </div>
              )}

              {/* 描述 */}
              {selected.description && (
                <div>
                  <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">漏洞描述</div>
                  <div className="bg-surface-800/40 rounded-xl p-3 text-sm text-slate-300 whitespace-pre-wrap leading-relaxed">
                    {selected.description}
                  </div>
                </div>
              )}

              {/* 修复建议 */}
              {selected.fix_suggestion && (
                <div>
                  <div className="text-xs font-medium text-green-400 uppercase tracking-wider mb-2">修复建议</div>
                  <div className="bg-green-500/5 border border-green-500/10 rounded-xl p-3 text-sm text-slate-300 whitespace-pre-wrap leading-relaxed">
                    {selected.fix_suggestion}
                  </div>
                </div>
              )}

              {/* AI 分析 */}
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">AI 分析</div>
                  <button
                    onClick={runAiAnalysis}
                    disabled={aiLoading}
                    className="text-[10px] px-2 py-0.5 rounded border border-purple-500/20 text-purple-400 hover:bg-purple-500/10 transition-colors disabled:opacity-50"
                  >
                    {aiLoading ? '分析中...' : aiResult ? '重新分析' : '开始分析'}
                  </button>
                </div>
                {aiLoading ? (
                  <div className="flex items-center gap-2 text-xs text-slate-500"><Loader2 size={12} className="animate-spin" /> AI 正在分析，请稍候...</div>
                ) : aiResult ? (
                  <div className="bg-surface-800/40 rounded-xl p-3 text-sm text-slate-300 whitespace-pre-wrap max-h-[300px] overflow-y-auto">{aiResult}</div>
                ) : (
                  <p className="text-xs text-slate-600">点击"开始分析"获取 AI 辅助的漏洞解析、风险评估和修复建议</p>
                )}
              </div>

              {/* 操作按钮 */}
              <div className="flex items-center gap-3 pt-3 border-t border-white/[0.03]">
                <button onClick={createTicket} className="btn-primary text-xs"><Ticket size={14} /> 创建工单</button>
                {selected.type === 'vuln' && (
                  <button onClick={() => navigate(`/vulnerabilities?id=${selected.id}`)} className="btn-secondary text-xs">
                    <ExternalLink size={14} /> 漏洞详情
                  </button>
                )}
                {selected.type === 'alert' && (
                  <button onClick={() => navigate(`/alerts?id=${selected.id}`)} className="btn-secondary text-xs">
                    <ExternalLink size={14} /> 告警详情
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        {/* ── 右列：关联上下文 ── */}
        <div className="glass-card">
          <div className="flex items-center gap-2 mb-4">
            <Server size={14} className="text-slate-400" />
            <span className="text-xs font-medium text-white">关联上下文</span>
          </div>
          {!selected ? (
            <p className="text-xs text-slate-600">选择事件后显示关联信息</p>
          ) : (
            <div className="space-y-4">
              {related.length > 0 ? (
                <div>
                  <div className="text-[10px] font-medium text-slate-500 uppercase tracking-wider mb-2">同类问题</div>
                  <div className="space-y-1.5">
                    {related.map(r => (
                      <div key={r.id} className="flex items-center gap-2 p-2 rounded-lg bg-surface-800/60 border border-white/[0.02]">
                        <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${sevDotBg[r.severity] || 'bg-gray-500'}`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-[11px] text-slate-300 truncate">{r.title}</p>
                          <p className="text-[10px] text-slate-600">{timeAgo(r.created_at)}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-600">暂无已知关联事件</p>
              )}

              <div className="border-t border-white/[0.03] pt-4">
                <div className="text-[10px] font-medium text-slate-500 uppercase tracking-wider mb-2">快捷操作</div>
                <div className="space-y-1">
                  <button onClick={createTicket} className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-[11px] text-slate-400 hover:text-blue-400 hover:bg-blue-500/5 transition-all text-left">
                    <Ticket size={12} /> 转为工单追踪
                  </button>
                  <button onClick={() => navigate('/vulnerabilities')} className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-[11px] text-slate-400 hover:text-slate-300 hover:bg-surface-800/50 transition-all text-left">
                    <Bug size={12} /> 查看所有漏洞
                  </button>
                  <button onClick={() => navigate('/alerts')} className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-[11px] text-slate-400 hover:text-slate-300 hover:bg-surface-800/50 transition-all text-left">
                    <Bell size={12} /> 查看所有告警
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── 子组件 ───
function StatBadge({ label, value, color, icon }: {
  label: string; value: number; color: string; icon: React.ReactNode;
}) {
  return (
    <div className="glass-card !p-3 flex items-center gap-3">
      <span className={color}>{icon}</span>
      <div>
        <div className={`text-lg font-bold tabular-nums ${color}`}>{value}</div>
        <div className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</div>
      </div>
    </div>
  )
}

function FilterPill({ active, label, onClick }: {
  active: boolean; onClick: () => void; label: string; color?: string;
}) {
  return (
    <button onClick={onClick}
      className={`px-2.5 py-1 rounded-lg text-xs border transition-all ${
        active
          ? 'bg-surface-800 text-white border-white/[0.08]'
          : 'text-slate-500 border-transparent hover:text-slate-300'
      }`}
    >
      {label}
    </button>
  )
}

function MetaBadge({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div className="flex items-center gap-2 bg-surface-800/40 rounded-lg px-2.5 py-1.5">
      <span className="text-[11px] text-slate-500 flex-shrink-0">{label}</span>
      <span className={`text-xs truncate ${color || 'text-slate-300'}`}>{value}</span>
    </div>
  )
}
