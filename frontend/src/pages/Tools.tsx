import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'

interface Tool {
  id: number
  name: string
  tool_type: string
  description: string
  endpoint: string
  enabled: boolean
  scan_count: number
  last_scan_at: string | null
  vuln_found_total: number
  has_adapter: boolean
  adapter_label: string | null
  adapter_desc: string | null
  created_at: string
}

interface KbArticle {
  id: number
  title: string
  summary: string
  category: string
  tags: string[]
  view_count: number
  updated_at: string
}

interface TestResult {
  ok: boolean
  message: string
  latency_ms?: number
  status_code?: number
}

interface ToastMessage {
  id: number
  text: string
  variant: 'success' | 'error'
}

const toolTypeBadge: Record<string, string> = {
  SAST: 'badge-info',
  SCA: 'badge-success',
  DAST: 'badge-warning',
  SECRET: 'badge-critical',
}

const toolTypeColor: Record<string, { border: string; icon: string; bg: string }> = {
  SAST: { border: 'border-blue-500/30', icon: 'text-blue-400', bg: 'bg-blue-500/10' },
  SCA: { border: 'border-green-500/30', icon: 'text-green-400', bg: 'bg-green-500/10' },
  DAST: { border: 'border-orange-500/30', icon: 'text-orange-400', bg: 'bg-orange-500/10' },
  SECRET: { border: 'border-red-500/30', icon: 'text-red-400', bg: 'bg-red-500/10' },
}

const toolIcons: Record<string, string> = {
  SAST: 'M14.5 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V7.5L14.5 2z M14 2v6h6 M16 13H8 M16 17H8 M10 9H8',
  SCA: 'M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4',
  DAST: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
  SECRET: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z',
}

const CATEGORY_LABELS: Record<string, string> = {
  web_security: 'Web 安全',
  supply_chain: '供应链安全',
  data_security: '数据安全',
  ops_process: '运维与流程',
  tool_guide: '工具指南',
  incident_case: '事件案例',
  compliance: '合规与标准',
  general: '综合',
}

let toastIdCounter = 0

export default function Tools() {
  const navigate = useNavigate()
  const [tools, setTools] = useState<Tool[]>([])
  const [loading, setLoading] = useState(true)
  const [toasts, setToasts] = useState<ToastMessage[]>([])
  const [showModal, setShowModal] = useState(false)
  const [editingTool, setEditingTool] = useState<Tool | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [expandedTool, setExpandedTool] = useState<number | null>(null)
  const [kbArticles, setKbArticles] = useState<Record<number, KbArticle[]>>({})
  const [testResults, setTestResults] = useState<Record<number, TestResult | null>>({})
  const [testing, setTesting] = useState<number | null>(null)
  const [form, setForm] = useState({
    name: '',
    tool_type: 'SAST',
    description: '',
    endpoint: '',
    api_key: '',
  })

  const addToast = useCallback((text: string, variant: ToastMessage['variant']) => {
    const id = ++toastIdCounter
    setToasts((prev) => [...prev, { id, text, variant }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, 4000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const fetchTools = async () => {
    setLoading(true)
    try {
      const res = await api.get('/tools')
      setTools(res.data?.items || [])
    } catch {
      addToast('获取工具列表失败', 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchTools()
  }, [])

  const fetchKnowledge = async (tool: Tool) => {
    if (kbArticles[tool.id]) return
    try {
      const res = await api.get(`/tools/${tool.id}/knowledge`)
      setKbArticles(prev => ({ ...prev, [tool.id]: res.data?.articles || [] }))
    } catch {
      // silent
    }
  }

  const toggleExpanded = (tool: Tool) => {
    if (expandedTool === tool.id) {
      setExpandedTool(null)
    } else {
      setExpandedTool(tool.id)
      fetchKnowledge(tool)
    }
  }

  const toggleEnabled = async (tool: Tool) => {
    const next = !tool.enabled
    const previous = tools
    setTools((prev) => prev.map((t) => (t.id === tool.id ? { ...t, enabled: next } : t)))
    try {
      await api.patch(`/tools/${tool.id}`, { enabled: next })
    } catch {
      setTools(previous)
      addToast('状态切换失败', 'error')
    }
  }

  const testConnection = async (tool: Tool) => {
    setTesting(tool.id)
    setTestResults(prev => ({ ...prev, [tool.id]: null }))
    try {
      const res = await api.post(`/tools/${tool.id}/test`)
      setTestResults(prev => ({ ...prev, [tool.id]: res.data }))
      addToast(`${tool.name} 连接测试成功`, 'success')
    } catch (err: any) {
      const data = err.response?.data
      setTestResults(prev => ({ ...prev, [tool.id]: data || { ok: false, message: '连接失败' } }))
      addToast(`${tool.name} 连接测试失败`, 'error')
    } finally {
      setTesting(null)
    }
  }

  const deleteTool = async (tool: Tool) => {
    if (!window.confirm(`确认删除工具 "${tool.name}"？此操作不可撤销。`)) return
    const previous = tools
    setTools((prev) => prev.filter((t) => t.id !== tool.id))
    try {
      await api.delete(`/tools/${tool.id}`)
      addToast(`${tool.name} 已删除`, 'success')
    } catch {
      setTools(previous)
      addToast('删除失败', 'error')
    }
  }

  const handleSubmit = async () => {
    if (!form.name.trim() || !form.endpoint.trim()) return
    setSubmitting(true)
    try {
      if (editingTool) {
        await api.patch(`/tools/${editingTool.id}`, form)
        addToast(`工具 "${form.name}" 更新成功`, 'success')
      } else {
        await api.post('/tools', form)
        addToast(`工具 "${form.name}" 注册成功`, 'success')
      }
      setShowModal(false)
      setEditingTool(null)
      setForm({ name: '', tool_type: 'SAST', description: '', endpoint: '', api_key: '' })
      fetchTools()
    } catch {
      addToast(editingTool ? '更新失败' : '注册失败', 'error')
    } finally {
      setSubmitting(false)
    }
  }

  const openCreateModal = () => {
    setEditingTool(null)
    setForm({ name: '', tool_type: 'SAST', description: '', endpoint: '', api_key: '' })
    setShowModal(true)
  }

  const openEditModal = (tool: Tool) => {
    setEditingTool(tool)
    setForm({
      name: tool.name,
      tool_type: tool.tool_type,
      description: tool.description || '',
      endpoint: tool.endpoint,
      api_key: '',
    })
    setShowModal(true)
  }

  const formatDate = (d: string | null) => {
    if (!d) return '-'
    try {
      return new Date(d.replace(' ', 'T') + '+08:00').toLocaleString('zh-CN', {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
      })
    } catch {
      return d.slice(0, 16)
    }
  }

  return (
    <div className="max-w-7xl mx-auto">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">安全工具集成</h1>
          <p className="page-subtitle">注册和管理 SAST、SCA、DAST 等安全扫描工具</p>
        </div>
        <button onClick={openCreateModal} className="btn-primary text-xs">
          注册工具
        </button>
      </div>

      {/* Toasts */}
      {toasts.length > 0 && (
        <div className="fixed top-4 right-4 z-[100] flex flex-col gap-2">
          {toasts.map((t) => (
            <div
              key={t.id}
              onClick={() => dismissToast(t.id)}
              className={`px-4 py-3 rounded-xl shadow-lg text-sm font-medium cursor-pointer max-w-sm ${
                t.variant === 'success'
                  ? 'bg-emerald-500/90 text-white'
                  : 'bg-red-500/90 text-white'
              }`}
            >
              {t.text}
            </div>
          ))}
        </div>
      )}

      {/* Content */}
      {loading ? (
        <div className="text-slate-500 text-sm">加载中...</div>
      ) : tools.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          </div>
          <div className="empty-state-title">暂无已注册的工具</div>
          <div className="empty-state-desc mb-4">注册安全扫描工具以开始使用</div>
          <button onClick={openCreateModal} className="btn-primary text-sm">
            注册第一个工具
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {tools.map((tool) => {
            const colors = toolTypeColor[tool.tool_type] || toolTypeColor.SAST
            const tr = testResults[tool.id]
            const isExpanded = expandedTool === tool.id
            const hasKb = (kbArticles[tool.id] || []).length > 0
            return (
              <div key={tool.id} className="card flex flex-col">
                {/* Card header */}
                <div className="flex items-start justify-between mb-3">
                  <div className={`w-10 h-10 rounded-xl ${colors.bg} ${colors.border} border flex items-center justify-center flex-shrink-0`}>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={colors.icon}>
                      <path d={toolIcons[tool.tool_type] || toolIcons.SAST} />
                    </svg>
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => openEditModal(tool)}
                      className="text-slate-600 hover:text-primary-400 text-xs transition-colors"
                      title="编辑工具"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
                        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
                      </svg>
                    </button>
                    <button
                      onClick={() => deleteTool(tool)}
                      className="text-slate-600 hover:text-red-400 text-xs transition-colors"
                      title="删除工具"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
                      </svg>
                    </button>
                  </div>
                </div>

                {/* Tool name + badge */}
                <div className="flex items-center gap-2 mb-2">
                  <h3 className="text-white font-semibold text-sm">{tool.name}</h3>
                  <span className={`badge ${toolTypeBadge[tool.tool_type] || 'badge-info'}`}>
                    {tool.tool_type}
                  </span>
                </div>

                {/* Adapter badge */}
                {tool.has_adapter ? (
                  <div className="flex items-center gap-1.5 mb-2">
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M20 6L9 17l-5-5" />
                      </svg>
                      {tool.adapter_label || '已对接扫描引擎'}
                    </span>
                  </div>
                ) : (
                  <div className="flex items-center gap-1.5 mb-2">
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">
                      自定义工具（无适配器）
                    </span>
                  </div>
                )}

                {/* Description */}
                <p className="text-slate-500 text-xs leading-relaxed mb-3 flex-1 line-clamp-2">
                  {tool.description || '暂无描述'}
                </p>

                {/* Stats row */}
                {(tool.scan_count > 0 || tool.last_scan_at) && (
                  <div className="grid grid-cols-3 gap-2 mb-3 bg-surface-800/40 rounded-lg p-2.5 border border-white/[0.04]">
                    <div className="text-center">
                      <div className="text-xs font-bold text-white tabular-nums">{tool.scan_count || 0}</div>
                      <div className="text-[9px] text-slate-500">次扫描</div>
                    </div>
                    <div className="text-center">
                      <div className="text-xs font-bold text-white tabular-nums">{tool.vuln_found_total || 0}</div>
                      <div className="text-[9px] text-slate-500">个漏洞</div>
                    </div>
                    <div className="text-center">
                      <div className="text-[9px] text-slate-400 tabular-nums leading-tight">{formatDate(tool.last_scan_at)}</div>
                      <div className="text-[9px] text-slate-500">最近扫描</div>
                    </div>
                  </div>
                )}

                {/* Test result inline */}
                {tr && (
                  <div className={`text-[10px] rounded-lg px-2.5 py-1.5 mb-2 flex items-center gap-1.5 ${tr.ok ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                    <span className="font-semibold">{tr.ok ? '✓' : '✗'}</span>
                    {tr.message}
                    {tr.latency_ms != null && <span className="text-slate-500 ml-1">({tr.latency_ms}ms)</span>}
                  </div>
                )}

                {/* Divider */}
                <div className="divider my-0 mb-3" />

                {/* Actions */}
                <div className="flex items-center justify-between">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <span className="text-slate-400 text-xs">
                      {tool.enabled ? '已启用' : '已禁用'}
                    </span>
                    <button
                      onClick={() => toggleEnabled(tool)}
                      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none ${
                        tool.enabled ? 'bg-primary-600' : 'bg-slate-700'
                      }`}
                    >
                      <span
                        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                          tool.enabled ? 'translate-x-4.5' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </label>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => testConnection(tool)}
                      disabled={testing === tool.id || !tool.enabled}
                      className="btn-secondary text-xs px-2.5 py-1.5 disabled:opacity-50"
                    >
                      {testing === tool.id ? '测试中...' : '测试'}
                    </button>
                    <button
                      onClick={() => toggleExpanded(tool)}
                      className={`btn-secondary text-xs px-2 py-1.5 transition-colors ${isExpanded ? 'bg-primary-500/10 text-primary-300 border-primary-500/20' : ''}`}
                      title="查看相关知识库"
                    >
                      {isExpanded ? '收起' : '相关'}
                    </button>
                  </div>
                </div>

                {/* Expanded: Related KB articles */}
                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-white/[0.05]">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M4 19.5v-15A2.5 2.5 0 016.5 2H20v20H6.5a2.5 2.5 0 01-2.5-2.5z" />
                        </svg>
                        知识库指南
                      </span>
                      <button
                        onClick={() => navigate('/knowledge-base')}
                        className="text-[10px] text-primary-400 hover:text-primary-300 transition-colors"
                      >
                        查看全部 →
                      </button>
                    </div>

                    {!kbArticles[tool.id] ? (
                      <div className="text-[10px] text-slate-600 py-2">加载中...</div>
                    ) : hasKb ? (
                      <div className="space-y-1.5 max-h-[200px] overflow-y-auto">
                        {(kbArticles[tool.id] || []).map((a) => (
                          <button
                            key={a.id}
                            onClick={() => navigate(`/knowledge-base/${a.id}`)}
                            className="w-full text-left px-2.5 py-2 rounded-lg hover:bg-white/[0.03] transition-colors group"
                          >
                            <div className="text-xs font-medium text-slate-300 group-hover:text-white truncate">{a.title}</div>
                            <div className="flex items-center gap-2 mt-0.5">
                              <span className="text-[9px] text-slate-600">{CATEGORY_LABELS[a.category] || a.category}</span>
                              <span className="text-[9px] text-slate-600">{a.view_count} 次浏览</span>
                            </div>
                          </button>
                        ))}
                      </div>
                    ) : (
                      <div className="text-[10px] text-slate-600 py-2">
                        暂无相关指南文章 —
                        <button onClick={() => navigate(`/knowledge-base/new?from_tool_type=${tool.tool_type}`)} className="text-primary-400 hover:underline ml-1">去创建</button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* New Tool Modal */}
      {showModal && (
        <div className="modal-overlay" onClick={() => { setShowModal(false); setEditingTool(null) }}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="text-lg font-semibold text-white">{editingTool ? '编辑工具' : '注册工具'}</h2>
              <button
                onClick={() => { setShowModal(false); setEditingTool(null) }}
                className="text-slate-500 hover:text-slate-300 text-sm"
              >
                ✕
              </button>
            </div>

            <div className="modal-body space-y-4">
              <div className="input-group">
                <label className="input-label">工具名称 *</label>
                <input
                  type="text"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="e.g. Semgrep / SonarQube"
                  className="input"
                />
              </div>

              <div className="input-group">
                <label className="input-label">工具类型</label>
                <select
                  value={form.tool_type}
                  onChange={(e) => setForm({ ...form, tool_type: e.target.value })}
                  className="select"
                >
                  <option value="SAST">SAST</option>
                  <option value="SCA">SCA</option>
                  <option value="DAST">DAST</option>
                  <option value="SECRET">SECRET</option>
                </select>
              </div>

              <div className="input-group">
                <label className="input-label">描述</label>
                <textarea
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder="工具描述..."
                  rows={3}
                  className="input resize-none"
                />
              </div>

              <div className="input-group">
                <label className="input-label">API 端点 *</label>
                <input
                  type="text"
                  value={form.endpoint}
                  onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
                  placeholder="https://..."
                  className="input"
                />
              </div>

              <div className="input-group">
                <label className="input-label">API Key</label>
                <input
                  type="password"
                  value={form.api_key}
                  onChange={(e) => setForm({ ...form, api_key: e.target.value })}
                  placeholder="••••••••"
                  className="input"
                />
              </div>
            </div>

            <div className="modal-footer">
              <button
                onClick={() => { setShowModal(false); setEditingTool(null) }}
                className="btn-secondary text-sm"
              >
                取消
              </button>
              <button
                onClick={handleSubmit}
                disabled={!form.name.trim() || !form.endpoint.trim() || submitting}
                className="btn-primary text-sm disabled:opacity-50"
              >
                {submitting ? '保存中...' : editingTool ? '保存' : '注册'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
