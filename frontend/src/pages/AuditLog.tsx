// ─── 审计日志页面 v2 Enhanced ───
import { useState, useEffect, useCallback } from 'react'
import api from '../api/client'

interface AuditLog {
  id: number
  user_id: number | null
  user_email: string
  operator_name: string
  action: string
  target_type: string
  target_id: number
  detail: string
  ip_address: string
  created_at: string
  result: string
  risk_level: string
  user_agent: string
  duration_ms: number
  request_path: string
  request_method: string
}

interface AuditStats {
  today_count: number
  week_count: number
  by_action: { action: string; count: number }[]
  by_target: { type: string; count: number }[]
  security_events: AuditLog[]
  top_users: { user_id: number | null; email: string; count: number }[]
}

// 操作类型元数据映射
const ACTION_META: Record<string, { icon: string; label: string; risk: string }> = {
  'user.login': { icon: '🔑', label: '用户登录', risk: 'low' },
  'user.login_failed': { icon: '❌', label: '登录失败', risk: 'medium' },
  'user.register': { icon: '👤', label: '用户注册', risk: 'low' },
  'user.delete': { icon: '🗑️', label: '删除用户', risk: 'critical' },
  'user.role_change': { icon: '🔄', label: '角色变更', risk: 'high' },
  'user.change_password': { icon: '🔒', label: '修改密码', risk: 'medium' },
  'user.token_refresh': { icon: '🔄', label: '刷新Token', risk: 'low' },
  'user.token_revoke': { icon: '🚫', label: '吊销Token', risk: 'medium' },
  'project.create': { icon: '📦', label: '创建项目', risk: 'medium' },
  'project.update': { icon: '✏️', label: '编辑项目', risk: 'low' },
  'project.delete': { icon: '🗑️', label: '删除项目', risk: 'critical' },
  'scan.triggered': { icon: '🔍', label: '触发扫描', risk: 'medium' },
  'scan.deleted': { icon: '🗑️', label: '删除扫描', risk: 'high' },
  'vuln.status_change': { icon: '⚠️', label: '漏洞状态变更', risk: 'medium' },
  'vuln.assigned': { icon: '👤', label: '漏洞指派', risk: 'low' },
  'vuln.deleted': { icon: '🗑️', label: '删除漏洞', risk: 'high' },
  'vuln.batch_deleted': { icon: '💥', label: '批量删除漏洞', risk: 'critical' },
  'vuln.reverified': { icon: '✅', label: '复验漏洞', risk: 'medium' },
  'rule.create': { icon: '⚖️', label: '创建规则', risk: 'medium' },
  'rule.update': { icon: '✏️', label: '编辑规则', risk: 'low' },
  'rule.delete': { icon: '🗑️', label: '删除规则', risk: 'high' },
  'rule.toggle': { icon: '🔛', label: '启用/禁用规则', risk: 'medium' },
  'asset.create': { icon: '🏗️', label: '创建资产', risk: 'medium' },
  'asset.update': { icon: '✏️', label: '编辑资产', risk: 'low' },
  'asset.delete': { icon: '🗑️', label: '删除资产', risk: 'high' },
  'asset.synced': { icon: '🔄', label: '同步资产', risk: 'low' },
  'asset.recalc_risk': { icon: '📊', label: '重算风险', risk: 'low' },
  'report.generated': { icon: '📄', label: '生成报告', risk: 'low' },
  'report.deleted': { icon: '🗑️', label: '删除报告', risk: 'medium' },
  'report.downloaded': { icon: '📥', label: '下载报告', risk: 'low' },
  'setting.changed': { icon: '⚙️', label: '配置变更', risk: 'high' },
  'audit.exported': { icon: '📋', label: '导出审计日志', risk: 'medium' },
  'webhook.scan_triggered': { icon: '🔗', label: 'Webhook扫描', risk: 'medium' },
  'security.login_blocked': { icon: '🛡️', label: '登录被拦截', risk: 'high' },
  'security.account_locked': { icon: '🔒', label: '账户锁定', risk: 'critical' },
}

function getActionMeta(action: string) {
  if (ACTION_META[action]) return ACTION_META[action]
  // fallback patterns
  if (action.includes('create')) return { icon: '➕', label: action, risk: 'medium' }
  if (action.includes('delete')) return { icon: '🗑️', label: action, risk: 'high' }
  if (action.includes('update') || action.includes('change')) return { icon: '✏️', label: action, risk: 'low' }
  return { icon: '📌', label: action, risk: 'low' }
}

const RISK_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
}

const RESULT_BADGE: Record<string, string> = {
  success: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  failure: 'bg-red-500/10 text-red-400 border-red-500/30',
  warning: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  blocked: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
}

function formatTime(t: string) {
  try {
    const d = new Date(t.replace(' ', 'T'))
    return d.toLocaleString('zh-CN', {
      month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    })
  } catch { return t }
}

function formatUA(ua: string) {
  if (!ua) return '-'
  if (ua.includes('Chrome')) return 'Chrome'
  if (ua.includes('Firefox')) return 'Firefox'
  if (ua.includes('Safari') && !ua.includes('Chrome')) return 'Safari'
  if (ua.includes('Edge')) return 'Edge'
  if (ua.includes('python')) return 'Python'
  if (ua.includes('curl')) return 'curl'
  return ua.substring(0, 30)
}

export default function AuditLogPage() {
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [stats, setStats] = useState<AuditStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [total, setTotal] = useState(0)
  const [filterAction, setFilterAction] = useState('')
  const [filterType, setFilterType] = useState('')
  const [filterResult, setFilterResult] = useState('')
  const [filterRisk, setFilterRisk] = useState('')
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [activeTab, setActiveTab] = useState<'logs' | 'stats' | 'security'>('logs')
  const [detailLog, setDetailLog] = useState<AuditLog | null>(null)
  const [autoRefresh, setAutoRefresh] = useState(false)

  const fetchLogs = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, string | number> = { page, page_size: 20 }
      if (filterAction) params.action = filterAction
      if (filterType) params.target_type = filterType
      if (filterResult) params.result = filterResult
      if (filterRisk) params.risk_level = filterRisk
      if (startDate) params.start_date = startDate
      if (endDate) params.end_date = endDate

      const res = await api.get('/audit/logs', { params })
      setLogs(res.data.data)
      setTotal(res.data.pagination.total)
      setTotalPages(res.data.pagination.total_pages)
    } catch (e) {
      console.error('Failed to load audit logs:', e)
    } finally {
      setLoading(false)
    }
  }, [page, filterAction, filterType, filterResult, filterRisk, startDate, endDate])

  const fetchStats = async () => {
    try {
      const res = await api.get('/audit/stats')
      setStats(res.data)
    } catch (e) {
      console.error('Failed to load stats:', e)
    }
  }

  useEffect(() => { fetchLogs() }, [fetchLogs])
  useEffect(() => { fetchStats() }, [])

  // 自动刷新
  useEffect(() => {
    if (!autoRefresh) return
    const timer = setInterval(() => { fetchLogs(); fetchStats() }, 15000)
    return () => clearInterval(timer)
  }, [autoRefresh, fetchLogs])

  const handleExport = async () => {
    try {
      const res = await api.get('/audit/export', { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `sentinel-audit-${new Date().toISOString().slice(0, 10)}.csv`)
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
    } catch (e) {
      alert('导出失败，请检查权限')
    }
  }

  const clearFilters = () => {
    setFilterAction(''); setFilterType(''); setFilterResult('')
    setFilterRisk(''); setStartDate(''); setEndDate(''); setPage(1)
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* 页头 */}
      <div className="page-header">
        <div>
          <h1 className="page-title">审计日志</h1>
          <p className="page-subtitle">
            记录平台所有操作行为，支持筛选、追溯和导出
            {autoRefresh && <span className="ml-2 text-emerald-400 text-xs">自动刷新中 (15s)</span>}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`btn-secondary text-xs ${
              autoRefresh
                ? '!bg-emerald-500/10 !text-emerald-400 !border-emerald-500/30'
                : ''
            }`}
          >
            {autoRefresh ? '停止刷新' : '自动刷新'}
          </button>
          <button onClick={handleExport}
            className="btn-primary text-xs">
            导出 CSV
          </button>
        </div>
      </div>

      {/* 统计概览 */}
      {stats && (
        <div className="grid grid-cols-5 gap-4">
          <div className="bg-[#1a1f2e] rounded-xl p-4 border border-gray-800">
            <div className="text-xs text-gray-500 uppercase tracking-wider">今日操作</div>
            <div className="text-2xl font-bold text-white mt-1">{stats.today_count}</div>
          </div>
          <div className="bg-[#1a1f2e] rounded-xl p-4 border border-gray-800">
            <div className="text-xs text-gray-500 uppercase tracking-wider">本周操作</div>
            <div className="text-2xl font-bold text-blue-400 mt-1">{stats.week_count}</div>
          </div>
          <div className="bg-[#1a1f2e] rounded-xl p-4 border border-gray-800">
            <div className="text-xs text-gray-500 uppercase tracking-wider">安全事件</div>
            <div className="text-2xl font-bold text-red-400 mt-1">{stats.security_events?.length || 0}</div>
          </div>
          <div className="bg-[#1a1f2e] rounded-xl p-4 border border-gray-800">
            <div className="text-xs text-gray-500 uppercase tracking-wider">总记录数</div>
            <div className="text-2xl font-bold text-emerald-400 mt-1">{total.toLocaleString()}</div>
          </div>
          <div className="bg-[#1a1f2e] rounded-xl p-4 border border-gray-800">
            <div className="text-xs text-gray-500 uppercase tracking-wider">活跃用户</div>
            <div className="text-2xl font-bold text-purple-400 mt-1">{stats.top_users?.length || 0}</div>
          </div>
        </div>
      )}

      {/* Tab 切换 */}
      <div className="flex gap-2">
        {[
          { key: 'logs' as const, label: '操作日志' },
          { key: 'stats' as const, label: '统计分布' },
          { key: 'security' as const, label: '安全事件' },
        ].map(tab => (
          <button key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2 text-sm rounded-lg transition ${
              activeTab === tab.key
                ? 'bg-indigo-600 text-white'
                : 'bg-[#1a1f2e] text-gray-400 hover:text-white hover:border-gray-700 border border-transparent'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab: 操作日志 */}
      {activeTab === 'logs' && (
        <>
          {/* 增强筛选栏 */}
          <div className="bg-[#0d1117] rounded-xl border border-gray-800 p-4 space-y-3">
            <div className="flex items-center gap-3 flex-wrap">
              <input type="text" placeholder="搜索操作类型..." value={filterAction}
                onChange={e => { setFilterAction(e.target.value); setPage(1) }}
                className="px-3 py-2 bg-[#161b22] border border-gray-700 rounded-lg text-sm text-white placeholder-gray-600 w-40" />
              <select value={filterType} onChange={e => { setFilterType(e.target.value); setPage(1) }}
                className="px-3 py-2 bg-[#161b22] border border-gray-700 rounded-lg text-sm text-white">
                <option value="">全部资源</option>
                <option value="user">用户</option>
                <option value="project">项目</option>
                <option value="scan">扫描</option>
                <option value="vulnerability">漏洞</option>
                <option value="rule">规则</option>
                <option value="asset">资产</option>
                <option value="report">报告</option>
                <option value="setting">配置</option>
                <option value="webhook">Webhook</option>
                <option value="audit">审计</option>
              </select>
              <select value={filterResult} onChange={e => { setFilterResult(e.target.value); setPage(1) }}
                className="px-3 py-2 bg-[#161b22] border border-gray-700 rounded-lg text-sm text-white">
                <option value="">全部结果</option>
                <option value="success">✅ 成功</option>
                <option value="failure">❌ 失败</option>
                <option value="warning">⚠️ 警告</option>
                <option value="blocked">🚫 已阻止</option>
              </select>
              <select value={filterRisk} onChange={e => { setFilterRisk(e.target.value); setPage(1) }}
                className="px-3 py-2 bg-[#161b22] border border-gray-700 rounded-lg text-sm text-white">
                <option value="">全部风险</option>
                <option value="critical">🔴 严重</option>
                <option value="high">🟠 高</option>
                <option value="medium">🟡 中</option>
                <option value="low">🔵 低</option>
              </select>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-500">日期:</span>
                <input type="date" value={startDate} onChange={e => { setStartDate(e.target.value); setPage(1) }}
                  className="px-2 py-1.5 bg-[#161b22] border border-gray-700 rounded-lg text-sm text-white" />
                <span className="text-xs text-gray-600">至</span>
                <input type="date" value={endDate} onChange={e => { setEndDate(e.target.value); setPage(1) }}
                  className="px-2 py-1.5 bg-[#161b22] border border-gray-700 rounded-lg text-sm text-white" />
              </div>
              {(filterAction || filterType || filterResult || filterRisk || startDate || endDate) && (
                <button onClick={clearFilters}
                  className="px-3 py-1.5 text-xs text-gray-400 hover:text-white bg-[#1a1f2e] rounded-lg border border-gray-700">
                  清除筛选
                </button>
              )}
              <span className="text-xs text-gray-600 ml-auto">{total} 条记录</span>
            </div>
          </div>

          {/* 日志表格 */}
          <div className="bg-[#0d1117] rounded-xl border border-gray-800 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-left">
                  <th className="px-4 py-3 text-xs text-gray-500 font-medium w-36">时间</th>
                  <th className="px-4 py-3 text-xs text-gray-500 font-medium w-20">结果</th>
                  <th className="px-4 py-3 text-xs text-gray-500 font-medium w-20">风险</th>
                  <th className="px-4 py-3 text-xs text-gray-500 font-medium">操作人</th>
                  <th className="px-4 py-3 text-xs text-gray-500 font-medium">操作</th>
                  <th className="px-4 py-3 text-xs text-gray-500 font-medium">详情</th>
                  <th className="px-4 py-3 text-xs text-gray-500 font-medium w-16">IP</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={7} className="px-4 py-12 text-center text-gray-600">加载中...</td></tr>
                ) : logs.length === 0 ? (
                  <tr><td colSpan={7} className="px-4 py-12 text-center text-gray-600">
                    暂无匹配的审计记录
                  </td></tr>
                ) : logs.map(log => {
                  const meta = getActionMeta(log.action)
                  return (
                    <tr key={log.id}
                      onClick={() => setDetailLog(log)}
                      className="border-b border-gray-900/50 hover:bg-gray-900/30 transition cursor-pointer">
                      <td className="px-4 py-3 text-gray-400 whitespace-nowrap text-xs">{formatTime(log.created_at)}</td>
                      <td className="px-4 py-3">
                        <span className={`px-1.5 py-0.5 text-[10px] rounded border ${RESULT_BADGE[log.result] || 'bg-gray-800 text-gray-500 border-gray-700'}`}>
                          {log.result === 'success' ? '成功' : log.result === 'failure' ? '失败' : log.result === 'warning' ? '警告' : log.result === 'blocked' ? '已阻止' : log.result || '-'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-1.5 py-0.5 text-[10px] rounded border ${RISK_COLORS[log.risk_level] || 'bg-gray-800 text-gray-500 border-gray-700'}`}>
                          {log.risk_level === 'critical' ? '严重' : log.risk_level === 'high' ? '高' : log.risk_level === 'medium' ? '中' : log.risk_level === 'low' ? '低' : log.risk_level || '-'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-white text-xs">{log.operator_name || log.user_email || '-'}</div>
                        {log.user_id && <div className="text-gray-600 text-[10px]">ID: {log.user_id}</div>}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs">
                          {meta.icon} <span className="text-gray-300">{meta.label}</span>
                        </span>
                        <div className="text-gray-600 text-[10px] mt-0.5 font-mono">{log.action}</div>
                      </td>
                      <td className="px-4 py-3 text-gray-300 text-xs max-w-xs truncate" title={log.detail}>{log.detail || '-'}</td>
                      <td className="px-4 py-3 text-gray-600 text-[10px] font-mono whitespace-nowrap">{log.ip_address || '-'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>

            {/* 分页 */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-gray-800">
                <button disabled={page <= 1} onClick={() => setPage(p => p - 1)}
                  className="px-3 py-1.5 text-xs bg-[#1a1f2e] text-gray-400 rounded hover:text-white disabled:opacity-30">← 上一页</button>
                <span className="text-xs text-gray-600">第 {page}/{totalPages} 页</span>
                <button disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}
                  className="px-3 py-1.5 text-xs bg-[#1a1f2e] text-gray-400 rounded hover:text-white disabled:opacity-30">下一页 →</button>
              </div>
            )}
          </div>
        </>
      )}

      {/* Tab: 统计分布 */}
      {activeTab === 'stats' && stats && (
        <div className="grid grid-cols-2 gap-6">
          <div className="bg-[#0d1117] rounded-xl border border-gray-800 p-5">
            <h3 className="text-sm font-semibold text-white mb-4">操作类型 TOP 10</h3>
            <div className="space-y-3">
              {stats.by_action.map((item, i) => (
                <div key={item.action} className="flex items-center gap-3">
                  <span className={`w-5 h-5 flex items-center justify-center rounded text-[10px] font-bold ${i < 3 ? 'bg-yellow-500/20 text-yellow-400' : 'bg-gray-800 text-gray-500'}`}>{i + 1}</span>
                  <span className="text-sm text-gray-300 flex-1 truncate font-mono">{getActionMeta(item.action).icon} {item.action}</span>
                  <div className="w-24 bg-gray-800 rounded-full h-2">
                    <div className="bg-indigo-500 h-2 rounded-full" style={{ width: `${Math.min(100, item.count / (stats.by_action[0]?.count || 1) * 100)}%` }} />
                  </div>
                  <span className="text-xs text-gray-500 w-8 text-right">{item.count}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-[#0d1117] rounded-xl border border-gray-800 p-5">
              <h3 className="text-sm font-semibold text-white mb-4">按资源类型</h3>
              <div className="space-y-3">
                {stats.by_target.map(item => (
                  <div key={item.type} className="flex items-center justify-between">
                    <span className="text-sm text-gray-300 capitalize">{item.type}</span>
                    <span className="text-sm font-bold text-white">{item.count}</span>
                  </div>
                ))}
              </div>
            </div>

            {stats.top_users.length > 0 && (
              <div className="bg-[#0d1117] rounded-xl border border-gray-800 p-5">
                <h3 className="text-sm font-semibold text-white mb-3">最活跃用户</h3>
                <div className="space-y-2">
                  {stats.top_users.map((u, i) => (
                    <div key={u.user_id ?? i} className="flex items-center justify-between">
                      <span className="text-sm text-gray-300">{u.email || '系统'}</span>
                      <span className="px-2 py-0.5 bg-indigo-500/20 text-indigo-400 text-xs rounded-full">{u.count} 次</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab: 安全事件 */}
      {activeTab === 'security' && stats && (
        <div className="bg-[#0d1117] rounded-xl border border-red-900/50 overflow-hidden">
          <div className="px-5 py-3 bg-red-950/20 border-b border-red-900/30 flex items-center gap-2">
            <span className="text-red-400">🚨</span>
            <h3 className="text-sm font-semibold text-red-400">安全事件监控</h3>
            <span className="ml-auto text-xs text-red-600">{stats.security_events.length} 条事件</span>
          </div>
          <div className="divide-y divide-gray-900/50">
            {stats.security_events.length === 0 ? (
              <div className="px-5 py-12 text-center text-green-600">✅ 暂无安全异常事件</div>
            ) : stats.security_events.map(evt => {
              const meta = getActionMeta(evt.action)
              return (
                <div key={evt.id} className="px-5 py-3 flex items-start gap-3 hover:bg-red-950/10 cursor-pointer"
                  onClick={() => setDetailLog(evt)}>
                  <span className="text-red-400 mt-0.5">{meta.icon}</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-red-300 font-mono">{evt.action}</span>
                      <span className={`px-1.5 py-0.5 text-[10px] rounded border ${RISK_COLORS[evt.risk_level] || ''}`}>
                        {evt.risk_level === 'critical' ? '严重' : evt.risk_level === 'high' ? '高' : evt.risk_level}
                      </span>
                    </div>
                    <div className="text-xs text-gray-500 mt-0.5 truncate">{evt.detail}</div>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-xs text-gray-600">{formatTime(evt.created_at)}</div>
                    <div className="text-[10px] text-gray-700 font-mono">{evt.ip_address}</div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* 详情弹窗 */}
      {detailLog && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
          onClick={() => setDetailLog(null)}>
          <div className="bg-[#161b22] rounded-xl border border-gray-700 w-[600px] max-h-[80vh] overflow-y-auto shadow-2xl"
            onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-800">
              <div className="flex items-center gap-2">
                <span className="text-lg">{getActionMeta(detailLog.action).icon}</span>
                <h3 className="text-sm font-semibold text-white">{getActionMeta(detailLog.action).label}</h3>
              </div>
              <button onClick={() => setDetailLog(null)}
                className="text-gray-500 hover:text-white text-xl leading-none">&times;</button>
            </div>
            <div className="p-5 space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-500 text-xs">时间</span>
                  <p className="text-white">{detailLog.created_at}</p>
                </div>
                <div>
                  <span className="text-gray-500 text-xs">操作ID</span>
                  <p className="text-white font-mono">#{detailLog.id}</p>
                </div>
                <div>
                  <span className="text-gray-500 text-xs">操作人</span>
                  <p className="text-white">{detailLog.operator_name || detailLog.user_email || '系统'} {detailLog.user_id ? `(ID: ${detailLog.user_id})` : ''}</p>
                </div>
                <div>
                  <span className="text-gray-500 text-xs">IP 地址</span>
                  <p className="text-white font-mono">{detailLog.ip_address || '-'}</p>
                </div>
                <div>
                  <span className="text-gray-500 text-xs">操作类型</span>
                  <p className="text-white font-mono text-xs">{detailLog.action}</p>
                </div>
                <div>
                  <span className="text-gray-500 text-xs">目标</span>
                  <p className="text-white">{detailLog.target_type}#{detailLog.target_id > 0 ? detailLog.target_id : '-'}</p>
                </div>
                <div>
                  <span className="text-gray-500 text-xs">结果</span>
                  <span className={`ml-2 px-1.5 py-0.5 text-[10px] rounded border ${RESULT_BADGE[detailLog.result] || ''}`}>
                    {detailLog.result}
                  </span>
                </div>
                <div>
                  <span className="text-gray-500 text-xs">风险等级</span>
                  <span className={`ml-2 px-1.5 py-0.5 text-[10px] rounded border ${RISK_COLORS[detailLog.risk_level] || ''}`}>
                    {detailLog.risk_level}
                  </span>
                </div>
                {detailLog.duration_ms > 0 && (
                  <div>
                    <span className="text-gray-500 text-xs">耗时</span>
                    <p className="text-white">{detailLog.duration_ms}ms</p>
                  </div>
                )}
                <div>
                  <span className="text-gray-500 text-xs">请求路径</span>
                  <p className="text-white font-mono text-xs truncate">{detailLog.request_path || '-'}</p>
                </div>
              </div>
              <div>
                <span className="text-gray-500 text-xs">详情</span>
                <p className="text-gray-300 text-sm mt-1 bg-[#0d1117] rounded-lg p-3 border border-gray-800">
                  {detailLog.detail || '无'}
                </p>
              </div>
              {detailLog.user_agent && (
                <div>
                  <span className="text-gray-500 text-xs">客户端</span>
                  <p className="text-gray-400 text-xs mt-1 font-mono truncate">{formatUA(detailLog.user_agent)} — {detailLog.user_agent.substring(0, 100)}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
