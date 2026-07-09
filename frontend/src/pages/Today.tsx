import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'
import {
  AlertTriangle, Clock, Shield, Bell, CheckCircle2, ArrowRight,
  TrendingDown, TrendingUp, Ticket, Bug, Activity, RefreshCw, Loader2,
  Search, FolderKanban, Rocket
} from 'lucide-react'
import { useI18n } from '../i18n'

interface UrgentVuln {
  id: number; title: string; severity: string; cve_id: string;
  file_path: string; status: string; sla_due_date: string;
  sla_breached: number; created_at: string; project_name: string;
}
interface AlertItem {
  id: number; title: string; severity: string; alert_type: string;
  project_name: string; vuln_count: number; critical_count: number;
  high_count: number; status: string; created_at: string;
}
interface SLAItem {
  id: number; title: string; severity: string; sla_due_date: string;
  sla_breached: number; status: string; created_at: string; project_name: string;
}
interface TodayStats {
  total_open_vulns: number; total_fixed: number; this_week_fixed: number;
  this_week_new: number; range_new: number; range_fixed: number; scans_in_range: number;
  alerts_pending: number; alerts_critical: number;
  sla_breached_count: number; tickets_open: number; fix_rate: number;
}
interface TodayData {
  range: string; range_label: string; today_date: string; today_weekday: string;
  urgent_vulns: UrgentVuln[];
  new_alerts: AlertItem[];
  sla_expiring: SLAItem[];
  sla_breached_list: SLAItem[];
  stats: TodayStats;
}

const sevBadge: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-warning',
  low: 'badge-info',
}
const sevLabel: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危'
}
const sevDot: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-blue-500'
}

function timeAgo(iso: string): string {
  if (!iso) return '-'
  const d = new Date(iso); const now = new Date()
  const diff = now.getTime() - d.getTime()
  const mins = Math.floor(diff / 60000)
  const hrs = Math.floor(diff / 3600000)
  const days = Math.floor(diff / 86400000)
  if (mins < 1) return '刚刚'
  if (mins < 60) return `${mins} 分钟前`
  if (hrs < 24) return `${hrs} 小时前`
  if (days < 7) return `${days} 天前`
  return iso.slice(0, 16).replace('T', ' ')
}

function slaRemaining(iso: string): string {
  if (!iso) return '-'
  const d = new Date(iso); const now = new Date()
  const diff = d.getTime() - now.getTime()
  if (diff <= 0) return '已超时'
  const hrs = Math.ceil(diff / 3600000)
  return hrs <= 24 ? `剩余 ${hrs}h` : `剩余 ${Math.floor(hrs / 24)}d ${hrs % 24}h`
}

export default function Today() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const [data, setData] = useState<TodayData | null>(null)
  const [loading, setLoading] = useState(true)
  const [range, setRange] = useState('today')
  const [projectCount, setProjectCount] = useState<number | null>(null)

  const load = async (r?: string) => {
    const useRange = r || range
    try {
      const res = await api.get('/today', { params: { range: useRange } })
      setData(res.data)
      if (res.data?.range) setRange(res.data.range)
    } catch { /* ignore */ }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  // 拉取项目数，用于首次使用引导
  useEffect(() => {
    api.get('/projects').then(r => {
      const items = r.data?.items
      setProjectCount(Array.isArray(items) ? items.length : (r.data?.total ?? 0))
    }).catch(() => setProjectCount(0))
  }, [])

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto">
        <div className="page-header"><div><h1 className="page-title">{t('nav.today')}</h1><p className="page-subtitle">{t('common.loading')}</p></div></div>
        <div className="flex items-center justify-center h-64"><Loader2 size={24} className="animate-spin text-slate-500" /></div>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="max-w-7xl mx-auto">
        <div className="page-header"><div><h1 className="page-title">{t('nav.today')}</h1></div></div>
        <div className="glass-card text-center py-16"><p className="text-slate-400">加载失败，请刷新页面</p></div>
      </div>
    )
  }

  const { urgent_vulns, new_alerts, sla_expiring, sla_breached_list, stats } = data
  const hasUrgent = urgent_vulns.length > 0 || sla_breached_list.length > 0 || new_alerts.filter(a => a.severity === 'critical').length > 0

  return (
    <div className="max-w-7xl mx-auto">
      {/* ── Page Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">{t('nav.today')}</h1>
          <p className="page-subtitle">
            {data.today_date} {data.today_weekday} · {t('today.range.' + data.range)}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-0.5 p-1 rounded-lg bg-surface-800/60 border border-white/5">
            {[
              { k: 'today', labelKey: 'today.range.today' },
              { k: '7d', labelKey: 'today.range.7d' },
              { k: '30d', labelKey: 'today.range.30d' },
              { k: 'all', labelKey: 'today.range.all' },
            ].map(opt => (
              <button
                key={opt.k}
                onClick={() => load(opt.k)}
                className={`px-3 py-1.5 text-xs rounded-md transition-colors ${range === opt.k ? 'bg-primary-500 text-white' : 'text-slate-400 hover:text-slate-200'}`}
              >
                {t(opt.labelKey)}
              </button>
            ))}
          </div>
          <button onClick={() => load()} className="btn-secondary text-xs"><RefreshCw size={14} /> {t('today.refresh')}</button>
        </div>
      </div>

      {/* ── 快捷操作 ── */}
      <div className="flex flex-wrap items-center gap-3 mb-6">
        <button onClick={() => navigate('/scans')} className="btn-primary text-sm flex items-center gap-1.5">
          <Search size={14} /> {t('today.startScan')}
        </button>
        <button onClick={() => navigate('/projects')} className="btn-secondary text-sm flex items-center gap-1.5">
          <FolderKanban size={14} /> {t('today.newProject')}
        </button>
      </div>

      {/* ── 首次使用引导 ── */}
      {projectCount === 0 && (
        <div className="glass-card flex flex-col sm:flex-row sm:items-center gap-4 mb-6 border-primary-500/20 bg-primary-500/[0.04]">
          <div className="w-10 h-10 rounded-xl bg-primary-500/15 flex items-center justify-center flex-shrink-0">
            <Rocket size={20} className="text-primary-400" />
          </div>
          <div className="flex-1">
            <p className="text-sm font-medium text-slate-100">{t('today.welcome')}</p>
            <p className="text-sm text-slate-400 mt-0.5">{t('today.guideDesc')}</p>
          </div>
          <button onClick={() => navigate('/projects')} className="btn-primary text-sm flex items-center gap-1.5 self-start sm:self-auto">
            <FolderKanban size={14} /> {t('today.createFirst')}
          </button>
        </div>
      )}

      {/* ── 顶部统计卡片 ── */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-5 mb-6">
        <CompactStatCard icon={<Bug size={20} />} label={t('today.stat.openVulns')} value={stats.total_open_vulns} color="text-red-400" bg="bg-red-500/10" onClick={() => navigate('/vulnerabilities?status=open')} />
        <CompactStatCard icon={<Bell size={20} />} label={t('today.stat.pendingAlerts')} value={stats.alerts_pending} color="text-orange-400" bg="bg-orange-500/10" onClick={() => navigate('/alerts?status=new')} />
        <CompactStatCard icon={<Ticket size={20} />} label={t('today.stat.openTickets')} value={stats.tickets_open} color="text-blue-400" bg="bg-blue-500/10" onClick={() => navigate('/tickets')} />
        <CompactStatCard icon={<Clock size={20} />} label={t('today.stat.slaBreached')} value={stats.sla_breached_count} color={stats.sla_breached_count > 0 ? 'text-red-400' : 'text-green-400'} bg={stats.sla_breached_count > 0 ? 'bg-red-500/10' : 'bg-green-500/10'} onClick={() => navigate('/vulnerabilities?filter=sla_breached')} />
        <CompactStatCard icon={<TrendingUp size={20} />} label={`${t('today.range.' + data.range)} ${t('today.stat.new')}`} value={stats.range_new} color="text-yellow-400" bg="bg-yellow-500/10" onClick={() => navigate('/vulnerabilities')} />
        <CompactStatCard icon={<TrendingDown size={20} />} label={t('today.stat.fixRate')} value={`${stats.fix_rate}%`} isString color={stats.fix_rate > 50 ? 'text-green-400' : 'text-yellow-400'} bg={stats.fix_rate > 50 ? 'bg-green-500/10' : 'bg-yellow-500/10'} />
      </div>

      {/* ── 无紧急事项时的安心提示 ── */}
      {!hasUrgent && (
        <div className="glass-card text-center p-10">
          <CheckCircle2 size={40} className="mx-auto mb-3 text-green-400/60" />
          <p className="text-slate-300 font-medium text-lg">{t('today.allClear.title')}</p>
          <p className="text-slate-500 text-sm mt-1">{t('today.allClear.desc')}</p>
          <p className="text-slate-600 text-xs mt-3">
            {t('today.allClear.fixed1')} {stats.range_fixed} {t('today.allClear.fixed2')} · {t('today.allClear.rate')} {stats.fix_rate}%
          </p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* ── 左列：紧急事项 ── */}
        <div className="space-y-6">
          {/* 严重 + 高危漏洞 */}
          {urgent_vulns.length > 0 && (
            <div className="glass-card">
              <div className="flex items-center gap-2 mb-4">
                <AlertTriangle size={16} className="text-red-400" />
                <span className="text-sm font-semibold text-white">{t('today.sec.urgent')}</span>
                <span className="px-2 py-0.5 rounded text-[11px] text-slate-400 bg-surface-800/80 font-medium">{urgent_vulns.length}</span>
                <span className="badge-critical text-[10px]">严重</span>
              </div>
              <div className="space-y-2">
                {urgent_vulns.map(v => (
                  <div
                    key={v.id}
                    className="flex items-start gap-3 p-3 rounded-xl bg-surface-800/60 border border-white/[0.03] hover:border-red-500/10 cursor-pointer transition-all group"
                    onClick={() => navigate(`/investigation?vuln=${v.id}`)}
                  >
                    <span className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 shadow-[0_0_6px] ${v.severity === 'critical' ? 'bg-red-500 shadow-red-500/50' : 'bg-orange-500 shadow-orange-500/50'}`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className={`badge ${sevBadge[v.severity] || 'badge-warning'} text-[10px]`}>
                          {sevLabel[v.severity] || v.severity}
                        </span>
                        {v.sla_breached === 1 && (
                          <span className="badge-critical text-[10px]">SLA已超</span>
                        )}
                        {v.project_name && <span className="text-[11px] text-slate-500">{v.project_name}</span>}
                      </div>
                      <p className="text-sm text-slate-200 truncate group-hover:text-white transition-colors">{v.title}</p>
                      {v.file_path && <p className="text-[11px] text-slate-500 truncate mt-0.5">{v.file_path}</p>}
                    </div>
                    <ArrowRight size={14} className="text-slate-600 group-hover:text-slate-400 mt-1 transition-colors flex-shrink-0" />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* SLA 已超时 */}
          {sla_breached_list.length > 0 && (
            <div className="glass-card">
              <div className="flex items-center gap-2 mb-4">
                <Clock size={16} className="text-red-400" />
                <span className="text-sm font-semibold text-white">{t('today.sec.slaBreached')}</span>
                <span className="px-2 py-0.5 rounded text-[11px] text-slate-400 bg-surface-800/80 font-medium">{sla_breached_list.length}</span>
              </div>
              <div className="space-y-2">
                {sla_breached_list.map(s => (
                  <div
                    key={s.id}
                    className="flex items-center gap-3 p-2.5 rounded-lg bg-red-500/5 border border-red-500/10 hover:border-red-500/20 cursor-pointer transition-all"
                    onClick={() => navigate(`/investigation?vuln=${s.id}`)}
                  >
                    <span className={`w-1.5 h-1.5 rounded-full ${sevDot[s.severity] || 'bg-gray-500'}`} />
                    <span className="flex-1 text-sm text-slate-300 truncate">{s.title}</span>
                    <span className="text-[11px] text-red-400 font-medium flex-shrink-0">超时</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── 右列：告警 + SLA 即将到期 ── */}
        <div className="space-y-6">
          {/* 新告警 */}
          {new_alerts.length > 0 && (
            <div className="glass-card">
              <div className="flex items-center gap-2 mb-4">
                <Bell size={16} className="text-orange-400" />
                <span className="text-sm font-semibold text-white">{t('today.sec.alerts')}</span>
                <span className="px-2 py-0.5 rounded text-[11px] text-slate-400 bg-surface-800/80 font-medium">{new_alerts.length}</span>
              </div>
              <div className="space-y-2">
                {new_alerts.map(a => (
                  <div
                    key={a.id}
                    className="flex items-start gap-3 p-3 rounded-xl bg-surface-800/60 border border-white/[0.03] hover:border-orange-500/10 cursor-pointer transition-all group"
                    onClick={() => navigate(`/investigation?alert=${a.id}`)}
                  >
                    <span className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${a.severity === 'critical' ? 'bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.5)]' : 'bg-orange-500'}`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className={`badge ${sevBadge[a.severity] || 'badge-warning'} text-[10px]`}>
                          {sevLabel[a.severity] || a.severity}
                        </span>
                        {a.project_name && <span className="text-[11px] text-slate-500">{a.project_name}</span>}
                      </div>
                      <p className="text-sm text-slate-200 truncate group-hover:text-white transition-colors">{a.title}</p>
                      {a.critical_count + a.high_count > 0 && (
                        <p className="text-[11px] text-slate-500 mt-0.5">
                          含 {a.critical_count} 严重 {a.high_count} 高危漏洞
                        </p>
                      )}
                    </div>
                    <span className="text-[11px] text-slate-500 flex-shrink-0 mt-1">{timeAgo(a.created_at)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* SLA 即将到期 */}
          {sla_expiring.length > 0 && (
            <div className="glass-card">
              <div className="flex items-center gap-2 mb-4">
                <Clock size={16} className="text-yellow-400" />
                <span className="text-sm font-semibold text-white">{t('today.sec.slaExpiring')}</span>
                <span className="px-2 py-0.5 rounded text-[11px] text-slate-400 bg-surface-800/80 font-medium">{sla_expiring.length}</span>
              </div>
              <div className="space-y-2">
                {sla_expiring.map(s => (
                  <div
                    key={s.id}
                    className="flex items-center gap-3 p-2.5 rounded-lg bg-yellow-500/5 border border-yellow-500/10 hover:border-yellow-500/20 cursor-pointer transition-all"
                    onClick={() => navigate(`/investigation?vuln=${s.id}`)}
                  >
                    <span className={`w-1.5 h-1.5 rounded-full ${sevDot[s.severity] || 'bg-gray-500'}`} />
                    <span className="flex-1 text-sm text-slate-300 truncate">{s.title}</span>
                    <span className="text-[11px] text-yellow-400 font-medium flex-shrink-0">{slaRemaining(s.sla_due_date)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 时间范围摘要（随切换器变化） */}
          <div className="glass-card">
            <div className="flex items-center gap-2 mb-4">
              <Activity size={16} className="text-slate-400" />
              <span className="text-sm font-semibold text-white">{t('today.range.' + data.range)} {t('today.summary')}</span>
            </div>
            <div className="grid grid-cols-2 gap-3 text-center">
              <div className="bg-surface-800/60 rounded-xl p-3">
                <div className="text-2xl font-bold text-green-400 tabular-nums">{stats.range_fixed}</div>
                <div className="text-[11px] text-slate-500 mt-0.5">已修复</div>
              </div>
              <div className="bg-surface-800/60 rounded-xl p-3">
                <div className="text-2xl font-bold text-yellow-400 tabular-nums">{stats.range_new}</div>
                <div className="text-[11px] text-slate-500 mt-0.5">新发现</div>
              </div>
              <div className="bg-surface-800/60 rounded-xl p-3">
                <div className="text-2xl font-bold text-blue-400 tabular-nums">{stats.scans_in_range}</div>
                <div className="text-[11px] text-slate-500 mt-0.5">扫描次数</div>
              </div>
              <div className="bg-surface-800/60 rounded-xl p-3">
                <div className="flex items-center justify-center gap-2">
                  <span className="text-sm text-slate-400">修复率</span>
                  <span className={`text-2xl font-bold tabular-nums ${stats.fix_rate > 50 ? 'text-green-400' : 'text-yellow-400'}`}>
                    {stats.fix_rate}%
                  </span>
                  {stats.fix_rate > 50 ? <TrendingUp size={16} className="text-green-400" /> : <TrendingDown size={16} className="text-yellow-400" />}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── 统一统计卡片（与 Dashboard 风格一致） ───
function CompactStatCard({ icon, label, value, color, bg, onClick, isString }: {
  icon: React.ReactNode; label: string; value: string | number; color: string; bg: string;
  onClick?: () => void; isString?: boolean;
}) {
  return (
    <div className="glass-card-hover !p-5 cursor-pointer group" onClick={onClick}>
      <div className="flex items-center justify-between mb-4">
        <div className="stat-icon group-hover:scale-110 transition-transform duration-300">
          {icon}
        </div>
      </div>
      <div className="stat-value text-white">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}
