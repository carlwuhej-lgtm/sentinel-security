import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'
import MarkdownRenderer from '../components/MarkdownRenderer'
import {
  X, ChevronRight, Zap, Shield, AlertTriangle, CheckCircle2, Clock, RefreshCw,
  User, FileCode, Tag, Calendar, Bot, ChevronDown, ChevronUp, Copy, Check,
  Search, Crosshair, Code, Download, ShieldOff, Send, Key, Unlock,
  Repeat, EyeOff, GitBranch, TrendingUp, Target, BarChart3, Activity,
  ArrowRight, Sparkles, Trash2, Ticket
} from 'lucide-react'

interface Vulnerability {
  id: number
  cve_id: string
  title: string
  severity: string
  file_path: string
  line: number
  source_tool: string
  status: string
  description?: string
  fix_suggestion?: string
  created_at: string
  sla_due_date?: string
  sla_breached?: number
  assigned_to?: number | null
  assignee_name?: string
}

interface User {
  id: number
  name: string
  email: string
}

interface SlaInfo {
  status: 'ok' | 'urgent' | 'breached' | 'closed' | 'unknown'
  remaining_text: string
  remaining_hours: number
}

interface AnalysisSections {
  vulnerability_type?: string
  severity_assessment?: {
    original_level: string
    ai_risk_score: number
    recommendation: string
    recommendation_color: string
  }
  attack_path?: {
    summary: string
    steps: { title: string; detail: string; icon: string }[]
  }
  exploitation_difficulty?: {
    label: string
    description: string
    value: number
  }
  business_impact?: {
    summary: string
    areas: { name: string; level: string; level_value: number; detail: string }[]
  }
  mitigation?: {
    priority: string
    recommendation: string
  }
}

interface AiAnalysis {
  analysis?: string
  analysis_sections?: AnalysisSections
  suggestion?: string
  code_examples?: { title: string; before: string; after: string; language: string }[]
  risk_score?: number
  ai_model?: string
}

const severityStyle: Record<string, { dot: string; text: string; border: string; bg: string; badge: string }> = {
  critical: { dot: 'bg-red-500', text: 'text-red-400', border: 'border-red-500/40', bg: 'bg-red-500/10', badge: 'badge-critical' },
  high: { dot: 'bg-orange-500', text: 'text-orange-400', border: 'border-orange-500/40', bg: 'bg-orange-500/10', badge: 'badge-high' },
  medium: { dot: 'bg-yellow-500', text: 'text-yellow-400', border: 'border-yellow-500/40', bg: 'bg-yellow-500/10', badge: 'badge-medium' },
  low: { dot: 'bg-blue-500', text: 'text-blue-400', border: 'border-blue-500/40', bg: 'bg-blue-500/10', badge: 'badge-low' },
}

const statusLabel: Record<string, string> = { open: '待处理', fixed: '已修复', ignored: '已忽略', in_progress: '处理中' }
const statusStyle: Record<string, string> = {
  open: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
  fixed: 'bg-green-500/10 text-green-400 border border-green-500/20',
  ignored: 'bg-slate-500/10 text-slate-400 border border-slate-500/20',
  in_progress: 'bg-blue-500/10 text-blue-400 border border-blue-500/20',
}

const PAGE_SIZE = 10
const filterTabs = ['全部', 'Critical', 'High', 'Medium', 'Low', '超时', '已修复'] as const

// ─── Code Block with Copy ───
function CodeBlock({ code, language }: { code: string; language?: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(code).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000) })
  }
  return (
    <div className="relative group rounded-lg bg-surface-950/80 border border-white/[0.05] overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-white/[0.04]">
        <span className="text-[10px] text-slate-500 font-mono">{language || 'code'}</span>
        <button onClick={copy} className="text-slate-500 hover:text-slate-300 transition-colors p-0.5">
          {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
        </button>
      </div>
      <pre className="text-xs font-mono text-slate-300 p-3 overflow-x-auto whitespace-pre-wrap leading-relaxed">{code}</pre>
    </div>
  )
}

// ─── Drawer ───
function VulnDrawer({
  vuln, users, onClose, onStatusChange, onAssign
}: {
  vuln: Vulnerability; users: User[]; onClose: () => void
  onStatusChange: (id: number, status: string) => Promise<void>
  onAssign: (id: number, userId: number | null) => Promise<void>
}) {
  const navigate2 = useNavigate()
  const [tab, setTab] = useState<'detail' | 'ai-fix' | 'ai-analysis'>('detail')
  const [aiData, setAiData] = useState<AiAnalysis | null>(null)
  const [showAiRaw, setShowAiRaw] = useState(false)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState('')
  const [updating, setUpdating] = useState(false)
  const [expandedFix, setExpandedFix] = useState<number | null>(null)
  const drawerRef = useRef<HTMLDivElement>(null)

  const sev = severityStyle[vuln.severity?.toLowerCase()] || severityStyle.low

  // Close on backdrop click
  const handleBackdrop = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) onClose()
  }

  const loadAi = async (type: 'fix' | 'analysis') => {
    setAiLoading(true); setAiError('')
    try {
      const endpoint = type === 'fix' ? '/ai/fix-suggestion' : '/ai/analyze-vulnerability'
      const res = await api.post(endpoint, { vulnerability_id: vuln.id })
      setAiData(prev => ({ ...prev, ...res.data }))
    } catch (e: any) {
      setAiError(e.response?.data?.error || 'AI 分析失败，请重试')
    } finally { setAiLoading(false) }
  }

  const handleTabChange = (t: 'detail' | 'ai-fix' | 'ai-analysis') => {
    setTab(t)
    if (t === 'ai-fix' && !aiData?.suggestion) loadAi('fix')
    if (t === 'ai-analysis' && !aiData?.analysis) loadAi('analysis')
  }

  const handleStatus = async (status: string) => {
    setUpdating(true)
    await onStatusChange(vuln.id, status)
    setUpdating(false)
  }

  // 从漏洞一键创建工单，进入修复跟踪闭环
  const handleCreateTicket = async () => {
    if (!confirm(`为漏洞「${vuln.title}」创建工单并进入修复跟踪？`)) return
    setUpdating(true)
    try {
      const priorityMap: Record<string, string> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' }
      const priority = priorityMap[vuln.severity?.toLowerCase()] || 'medium'
      const desc = [
        `漏洞：${vuln.title}`,
        vuln.cve_id ? `CVE：${vuln.cve_id}` : '',
        `严重度：${vuln.severity}`,
        vuln.file_path ? `文件：${vuln.file_path}${vuln.line ? ':' + vuln.line : ''}` : '',
        vuln.description || '',
      ].filter(Boolean).join('\n')
      await api.post('/tickets', {
        title: `[${vuln.severity?.toUpperCase()}] ${vuln.title}`,
        description: desc,
        priority,
        source_type: 'vuln',
        source_id: vuln.id,
      })
      navigate2('/tickets')
    } catch (e: any) {
      alert(e.response?.data?.error || '创建工单失败，请重试')
      setUpdating(false)
    }
  }

  const slaInfo = (() => {
    if (vuln.status === 'fixed' || vuln.status === 'ignored') return { text: '已关闭', color: 'text-slate-500' }
    if (vuln.sla_breached) return { text: '⚠ 已超时', color: 'text-red-400' }
    if (!vuln.sla_due_date) return { text: '-', color: 'text-slate-500' }
    try {
      const due = new Date(vuln.sla_due_date.replace(' ', 'T') + 'Z')
      const h = (due.getTime() - Date.now()) / 3600000
      if (h < 0) return { text: '⚠ 已超时', color: 'text-red-400' }
      if (h < 24) return { text: `⚡ 剩余 ${Math.round(h)}h`, color: 'text-orange-400' }
      return { text: `剩余 ${Math.round(h / 24)}d`, color: 'text-green-400' }
    } catch { return { text: '-', color: 'text-slate-500' } }
  })()

  const riskScore = aiData?.risk_score
  const riskColor = riskScore
    ? riskScore >= 80 ? '#ef4444' : riskScore >= 50 ? '#f97316' : '#22c55e'
    : '#64748b'

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end"
      style={{ background: 'rgba(0,0,0,0.5)', backdropFilter: 'blur(4px)' }}
      onClick={handleBackdrop}
    >
      <div
        ref={drawerRef}
        className="relative flex flex-col bg-surface-900 border-l border-white/[0.06] shadow-2xl"
        style={{ width: 'min(600px, 95vw)', animation: 'slideInRight 0.25s ease-out' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start gap-3 px-5 pt-5 pb-4 border-b border-white/[0.05]">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1.5">
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${sev.bg} ${sev.text}`}>
                {vuln.severity?.toUpperCase()}
              </span>
              {vuln.cve_id && (
                <span className="text-[10px] text-slate-500 font-mono bg-surface-800/80 px-2 py-0.5 rounded border border-white/[0.05]">
                  {vuln.cve_id}
                </span>
              )}
              <span className={`text-[10px] px-2 py-0.5 rounded-md ${statusStyle[vuln.status] || ''}`}>
                {statusLabel[vuln.status] || vuln.status}
              </span>
            </div>
            <h2 className="text-white font-semibold text-sm leading-snug truncate">{vuln.title}</h2>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors shrink-0 mt-0.5 p-1 hover:bg-white/[0.05] rounded-lg">
            <X size={16} />
          </button>
        </div>

        {/* AI Risk Score (shown if loaded) */}
        {riskScore !== undefined && (
          <div className="mx-5 mt-3 flex items-center gap-3 bg-surface-800/50 rounded-xl px-4 py-2.5 border border-white/[0.04]">
            <div className="text-xs text-slate-400">AI 风险评分</div>
            <div className="flex-1 h-1.5 bg-surface-700 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{ width: `${riskScore}%`, background: riskColor, boxShadow: `0 0 8px ${riskColor}80` }}
              />
            </div>
            <div className="font-bold text-sm tabular-nums" style={{ color: riskColor }}>{riskScore}</div>
          </div>
        )}

        {/* Tabs */}
        <div className="flex items-center gap-1 px-5 pt-3 pb-0 border-b border-white/[0.05]">
          {[
            { key: 'detail', label: '详情', icon: <Shield size={12} /> },
            { key: 'ai-fix', label: 'AI 修复', icon: <Zap size={12} /> },
            { key: 'ai-analysis', label: 'AI 分析', icon: <Bot size={12} /> },
          ].map((t) => (
            <button
              key={t.key}
              onClick={() => handleTabChange(t.key as any)}
              className={`flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium border-b-2 transition-colors -mb-px ${
                tab === t.key
                  ? 'text-primary-400 border-primary-500'
                  : 'text-slate-500 border-transparent hover:text-slate-300 hover:border-slate-700'
              }`}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
          {/* Detail Tab */}
          {tab === 'detail' && (
            <>
              {/* Meta */}
              <div className="grid grid-cols-2 gap-3">
                {[
                  { icon: <FileCode size={12} />, label: '文件路径', value: vuln.file_path + (vuln.line ? `:${vuln.line}` : '') },
                  ...(vuln.source_tool ? [{
                    icon: <Tag size={12} />, label: '扫描工具', value: vuln.source_tool,
                    isTool: true
                  }] : [{
                    icon: <Tag size={12} />, label: '扫描工具', value: '-',
                    isTool: false
                  }]),
                  { icon: <User size={12} />, label: '指派给', value: vuln.assignee_name || '未指派' },
                  { icon: <Calendar size={12} />, label: '发现时间', value: vuln.created_at?.slice(0, 10) || '-' },
                  { icon: <Clock size={12} />, label: 'SLA 状态', value: slaInfo.text, valueClass: slaInfo.color },
                  { icon: <Calendar size={12} />, label: 'SLA 到期', value: vuln.sla_due_date?.slice(0, 10) || '-' },
                ].map((item: any, i: number) => (
                  <div key={i} className="bg-surface-800/40 rounded-lg px-3 py-2.5 border border-white/[0.04]">
                    <div className="flex items-center gap-1.5 text-slate-500 text-[10px] mb-1">{item.icon}{item.label}</div>
                    {item.isTool ? (
                      <button
                        onClick={() => { onClose(); navigate2('/tools') }}
                        className="text-xs font-mono font-medium text-primary-400 hover:text-primary-300 hover:underline transition-colors cursor-pointer text-left"
                      >
                        {item.value}
                      </button>
                    ) : (
                      <div className={`text-xs font-mono truncate font-medium ${item.valueClass || 'text-slate-300'}`}>{item.value}</div>
                    )}
                  </div>
                ))}
              </div>

              {/* Description */}
              <div>
                <div className="text-slate-500 text-[10px] font-semibold uppercase tracking-wider mb-2">漏洞描述</div>
                <div className="text-slate-300 text-xs leading-relaxed bg-surface-800/30 rounded-lg p-3 border border-white/[0.04]">
                  {vuln.description || '暂无描述'}
                </div>
              </div>

              {/* Fix suggestion (static) */}
              {vuln.fix_suggestion && (
                <div>
                  <div className="text-slate-500 text-[10px] font-semibold uppercase tracking-wider mb-2">修复建议（扫描工具）</div>
                  <div className="text-slate-300 text-xs leading-relaxed bg-surface-800/30 rounded-lg p-3 border border-white/[0.04] whitespace-pre-wrap">
                    {vuln.fix_suggestion}
                  </div>
                </div>
              )}

              {/* Assignee change */}
              {vuln.status === 'open' || vuln.status === 'in_progress' ? (
                <div>
                  <div className="text-slate-500 text-[10px] font-semibold uppercase tracking-wider mb-2">重新指派</div>
                  <select
                    defaultValue={vuln.assigned_to || ''}
                    onChange={e => onAssign(vuln.id, e.target.value ? Number(e.target.value) : null)}
                    className="w-full text-xs bg-surface-800 border border-surface-600 rounded-lg px-3 py-2 text-slate-300 focus:border-primary-500/50 focus:outline-none"
                  >
                    <option value="">未指派</option>
                    {users.map(u => <option key={u.id} value={u.id}>{u.name}</option>)}
                  </select>
                </div>
              ) : null}
            </>
          )}

          {/* AI Fix Tab */}
          {tab === 'ai-fix' && (
            <>
              {aiLoading && (
                <div className="flex flex-col items-center justify-center py-12 gap-3">
                  <div className="w-8 h-8 rounded-full border-2 border-primary-500 border-t-transparent animate-spin" />
                  <p className="text-slate-400 text-xs">AI 正在生成修复建议...</p>
                </div>
              )}
              {aiError && !aiLoading && (
                <div className="text-center py-8">
                  <p className="text-red-400 text-xs mb-3">{aiError}</p>
                  <button onClick={() => loadAi('fix')} className="btn-secondary text-xs">
                    <RefreshCw size={12} /> 重试
                  </button>
                </div>
              )}
              {aiData?.code_examples && !aiLoading && (
                <div className="space-y-4">
                  {aiData.code_examples.map((ex, i) => (
                    <div key={i} className="space-y-2">
                      <button
                        onClick={() => setExpandedFix(expandedFix === i ? null : i)}
                        className="w-full flex items-center justify-between text-xs font-medium text-slate-300 bg-surface-800/50 px-3 py-2.5 rounded-lg border border-white/[0.05] hover:bg-surface-800 transition-colors"
                      >
                        <span className="flex items-center gap-2">
                          <Zap size={12} className="text-primary-400" />
                          方案 {i + 1}：{ex.title}
                        </span>
                        {expandedFix === i ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                      </button>
                      {expandedFix === i && (
                        <div className="space-y-2 pl-2">
                          <div>
                            <p className="text-[10px] text-red-400 font-medium mb-1 flex items-center gap-1">
                              <AlertTriangle size={10} /> 修复前
                            </p>
                            <CodeBlock code={ex.before} language={ex.language} />
                          </div>
                          <div>
                            <p className="text-[10px] text-green-400 font-medium mb-1 flex items-center gap-1">
                              <CheckCircle2 size={10} /> 修复后
                            </p>
                            <CodeBlock code={ex.after} language={ex.language} />
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
              {aiData?.suggestion && !aiLoading && (
                <div className="prose prose-invert prose-xs max-w-none">
                  <div className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">
                    {aiData.suggestion.split('```').map((part, i) =>
                      i % 2 === 1
                        ? <CodeBlock key={i} code={part.replace(/^\w+\n/, '')} language={part.split('\n')[0]} />
                        : <span key={i}>{part}</span>
                    )}
                  </div>
                </div>
              )}
              {!aiLoading && !aiError && !aiData?.suggestion && (
                <div className="text-center py-10">
                  <Zap size={32} className="text-primary-400/40 mx-auto mb-3" />
                  <p className="text-slate-500 text-xs">点击重新加载获取 AI 修复建议</p>
                  <button onClick={() => loadAi('fix')} className="btn-primary text-xs mt-4">
                    <Bot size={13} /> 生成修复建议
                  </button>
                </div>
              )}
            </>
          )}

          {/* AI Analysis Tab */}
          {tab === 'ai-analysis' && (
            <>
              {aiLoading && (
                <div className="flex flex-col items-center justify-center py-16 gap-4">
                  <div className="relative">
                    <div className="w-12 h-12 rounded-xl border-2 border-accent-500/30 border-t-accent-500 animate-spin" />
                    <Sparkles size={18} className="absolute inset-0 m-auto text-accent-400 animate-pulse" />
                  </div>
                  <div>
                    <p className="text-slate-300 text-xs font-medium mb-1">AI 正在分析漏洞风险...</p>
                    <p className="text-slate-500 text-[10px]">识别攻击路径 · 评估业务影响 · 计算风险分值</p>
                  </div>
                </div>
              )}
              {aiError && !aiLoading && (
                <div className="text-center py-12">
                  <AlertTriangle size={28} className="text-red-400/50 mx-auto mb-3" />
                  <p className="text-red-400 text-xs mb-3">{aiError}</p>
                  <button onClick={() => loadAi('analysis')} className="btn-secondary text-xs">
                    <RefreshCw size={12} /> 重试
                  </button>
                </div>
              )}

              {/* Rich Structured Analysis */}
              {aiData?.analysis_sections && !aiLoading && (
                <div className="space-y-5">
                  {/* ─── Header Badge ─── */}
                  <div className="flex items-center gap-2 -mb-1">
                    <span className="text-[10px] font-bold px-2.5 py-1 rounded-full bg-accent-500/15 text-accent-400 border border-accent-500/20 flex items-center gap-1.5">
                      <Sparkles size={10} />
                      AI 深度分析
                    </span>
                    {aiData.analysis_sections.vulnerability_type && (
                      <span className="text-[10px] px-2 py-1 rounded-full bg-surface-800 text-slate-400 border border-white/[0.06]">
                        {aiData.analysis_sections.vulnerability_type}
                      </span>
                    )}
                    {aiData.ai_model && (
                      <span className="text-[10px] text-slate-600 ml-auto">模型：{aiData.ai_model}</span>
                    )}
                  </div>

                  {/* ─── 1. Risk Score Gauge ─── */}
                  {aiData.analysis_sections.severity_assessment && (
                    <div className="glass-card rounded-xl border border-white/[0.06] overflow-hidden">
                      <div className="px-4 py-3 border-b border-white/[0.05] flex items-center gap-2">
                        <Target size={13} className="text-orange-400" />
                        <span className="text-xs font-semibold text-white">风险评估</span>
                      </div>
                      <div className="p-4">
                        <div className="flex items-center gap-5">
                          {/* Gauge circle */}
                          <div className="relative shrink-0">
                            <svg width={72} height={72} className="-rotate-90">
                              <circle cx={36} cy={36} r={30} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={5} />
                              <circle
                                cx={36} cy={36} r={30} fill="none"
                                stroke={aiData.analysis_sections.severity_assessment.recommendation_color}
                                strokeWidth={5}
                                strokeLinecap="round"
                                strokeDasharray={`${(aiData.analysis_sections.severity_assessment.ai_risk_score / 100) * 188.5} 188.5`}
                                style={{ filter: `drop-shadow(0 0 6px ${aiData.analysis_sections.severity_assessment.recommendation_color}60)` }}
                              />
                            </svg>
                            <div className="absolute inset-0 flex flex-col items-center justify-center">
                              <span className="text-lg font-bold text-white tabular-nums leading-none">{aiData.analysis_sections.severity_assessment.ai_risk_score}</span>
                              <span className="text-[9px] text-slate-500">/100</span>
                            </div>
                          </div>
                          <div className="flex-1 min-w-0 space-y-1.5">
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-slate-500">原始等级</span>
                              <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${severityStyle[aiData.analysis_sections.severity_assessment.original_level?.toLowerCase()]?.bg || ''} ${severityStyle[aiData.analysis_sections.severity_assessment.original_level?.toLowerCase()]?.text || ''}`}>
                                {aiData.analysis_sections.severity_assessment.original_level}
                              </span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-slate-500">AI 建议</span>
                              <span
                                className="text-[11px] font-bold px-2.5 py-1 rounded-lg border"
                                style={{
                                  color: aiData.analysis_sections.severity_assessment.recommendation_color,
                                  borderColor: aiData.analysis_sections.severity_assessment.recommendation_color + '40',
                                  backgroundColor: aiData.analysis_sections.severity_assessment.recommendation_color + '10',
                                }}
                              >
                                {aiData.analysis_sections.severity_assessment.recommendation}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ─── 2. Attack Path Flow ─── */}
                  {aiData.analysis_sections.attack_path && (
                    <div className="glass-card rounded-xl border border-white/[0.06] overflow-hidden">
                      <div className="px-4 py-3 border-b border-white/[0.05] flex items-center gap-2">
                        <GitBranch size={13} className="text-red-400" />
                        <span className="text-xs font-semibold text-white">攻击路径还原</span>
                      </div>
                      <div className="p-4">
                        <p className="text-xs text-slate-400 leading-relaxed mb-4">{aiData.analysis_sections.attack_path.summary}</p>
                        {/* Step flow */}
                        <div className="flex items-start gap-0 overflow-x-auto pb-2">
                          {aiData.analysis_sections.attack_path.steps.map((step, idx) => (
                            <div key={idx} className="flex items-start shrink-0">
                              <div className="flex flex-col items-center w-[100px]">
                                <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center mb-2">
                                  {step.icon === 'search' && <Search size={13} className="text-red-400" />}
                                  {step.icon === 'target' && <Crosshair size={13} className="text-red-400" />}
                                  {step.icon === 'code' && <Code size={13} className="text-red-400" />}
                                  {step.icon === 'download' && <Download size={13} className="text-red-400" />}
                                  {step.icon === 'shield-off' && <ShieldOff size={13} className="text-red-400" />}
                                  {step.icon === 'send' && <Send size={13} className="text-red-400" />}
                                  {step.icon === 'key' && <Key size={13} className="text-red-400" />}
                                  {step.icon === 'repeat' && <Repeat size={13} className="text-red-400" />}
                                  {step.icon === 'unlock' && <Unlock size={13} className="text-red-400" />}
                                  {step.icon === 'eye-off' && <EyeOff size={13} className="text-red-400" />}
                                  {step.icon === 'alert-triangle' && <AlertTriangle size={13} className="text-red-400" />}
                                  {step.icon === 'zap' && <Zap size={13} className="text-red-400" />}
                                  {step.icon === 'git-branch' && <GitBranch size={13} className="text-red-400" />}
                                </div>
                                <p className="text-[10px] font-semibold text-white text-center leading-tight mb-1">{step.title}</p>
                                <p className="text-[9px] text-slate-500 text-center leading-relaxed line-clamp-2">{step.detail.slice(0, 40)}</p>
                              </div>
                              {idx < (aiData.analysis_sections?.attack_path?.steps?.length ?? 0) - 1 && (
                                <div className="flex items-start pt-3 px-1">
                                  <ArrowRight size={12} className="text-slate-700" />
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ─── 3. Exploitation Difficulty + Business Impact Grid ─── */}
                  <div className="grid grid-cols-1 gap-4">
                    {/* Exploitation Difficulty */}
                    {aiData.analysis_sections.exploitation_difficulty && (
                      <div className="glass-card rounded-xl border border-white/[0.06] overflow-hidden">
                        <div className="px-4 py-3 border-b border-white/[0.05] flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Activity size={13} className="text-yellow-400" />
                            <span className="text-xs font-semibold text-white">利用难度评估</span>
                          </div>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                            aiData.analysis_sections.exploitation_difficulty.value >= 70
                              ? 'bg-red-500/15 text-red-400 border border-red-500/20'
                              : aiData.analysis_sections.exploitation_difficulty.value >= 40
                              ? 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/20'
                              : 'bg-green-500/15 text-green-400 border border-green-500/20'
                          }`}>
                            {aiData.analysis_sections.exploitation_difficulty.label}难度
                          </span>
                        </div>
                        <div className="p-4">
                          <div className="flex items-center gap-3 mb-2">
                            <div className="flex-1 h-2 bg-surface-800 rounded-full overflow-hidden">
                              <div
                                className="h-full rounded-full transition-all duration-700"
                                style={{
                                  width: `${aiData.analysis_sections.exploitation_difficulty.value}%`,
                                  background: `linear-gradient(90deg, #22c55e, #eab308, #ef4444)`,
                                }}
                              />
                            </div>
                            <span className="text-[10px] text-slate-500 tabular-nums w-8 text-right">{aiData.analysis_sections.exploitation_difficulty.value}%</span>
                          </div>
                          <p className="text-[10px] text-slate-500 leading-relaxed">
                            难度越高 = 越难利用 = 越安全；越低 = 越容易利用 = 越危险
                          </p>
                        </div>
                      </div>
                    )}

                    {/* Business Impact Areas */}
                    {aiData.analysis_sections.business_impact && (
                      <div className="glass-card rounded-xl border border-white/[0.06] overflow-hidden">
                        <div className="px-4 py-3 border-b border-white/[0.05] flex items-center gap-2">
                          <BarChart3 size={13} className="text-purple-400" />
                          <span className="text-xs font-semibold text-white">业务影响评估</span>
                        </div>
                        <div className="p-4 space-y-3">
                          {aiData.analysis_sections.business_impact.areas.map((area, idx) => {
                            const impactColor = area.level_value >= 70 ? '#ef4444' : area.level_value >= 40 ? '#f97316' : '#22c55e'
                            return (
                              <div key={idx} className="group">
                                <div className="flex items-center justify-between mb-1">
                                  <div className="flex items-center gap-2">
                                    <span className="text-[10px] text-slate-300 font-medium">{area.name}</span>
                                    <span
                                      className="text-[9px] font-bold px-1.5 py-0.5 rounded"
                                      style={{ color: impactColor, backgroundColor: impactColor + '15' }}
                                    >
                                      {area.level}
                                    </span>
                                  </div>
                                  <span className="text-[10px] text-slate-500 tabular-nums">{area.level_value}%</span>
                                </div>
                                <div className="h-1.5 bg-surface-800 rounded-full overflow-hidden">
                                  <div
                                    className="h-full rounded-full transition-all duration-500"
                                    style={{
                                      width: `${area.level_value}%`,
                                      background: impactColor,
                                      boxShadow: `0 0 6px ${impactColor}40`,
                                    }}
                                  />
                                </div>
                                <p className="text-[9px] text-slate-600 mt-1 leading-relaxed opacity-0 group-hover:opacity-100 transition-opacity">{area.detail}</p>
                              </div>
                            )
                          })}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* ─── 4. Mitigation Recommendation ─── */}
                  {aiData.analysis_sections.mitigation && (
                    <div className="glass-card rounded-xl border border-white/[0.06] overflow-hidden">
                      <div className="px-4 py-3 border-b border-white/[0.05] flex items-center gap-2">
                        <Shield size={13} className="text-green-400" />
                        <span className="text-xs font-semibold text-white">缓解建议</span>
                      </div>
                      <div className="p-4">
                        <div className="flex items-center gap-3 mb-3">
                          <span
                            className="text-[11px] font-bold px-3 py-1.5 rounded-lg border"
                            style={{
                              color: riskScore ? (riskScore >= 80 ? '#ef4444' : riskScore >= 50 ? '#f97316' : '#22c55e') : '#22c55e',
                              borderColor: (riskScore ? (riskScore >= 80 ? '#ef4444' : riskScore >= 50 ? '#f97316' : '#22c55e') : '#22c55e') + '40',
                              backgroundColor: (riskScore ? (riskScore >= 80 ? '#ef4444' : riskScore >= 50 ? '#f97316' : '#22c55e') : '#22c55e') + '10',
                            }}
                          >
                            {aiData.analysis_sections.mitigation.priority}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 leading-relaxed">{aiData.analysis_sections.mitigation.recommendation}</p>
                      </div>
                    </div>
                  )}

                  {/* AI Raw Response (collapsible — shown when real AI + structured data both exist) */}
                  {aiData?.analysis_sections && aiData?.analysis && aiData?.ai_model !== 'simulated' && !aiLoading && (
                    <div className="mt-4 rounded-xl border border-white/[0.06] overflow-hidden">
                      <button
                        onClick={() => setShowAiRaw(!showAiRaw)}
                        className="w-full px-4 py-2.5 flex items-center justify-between hover:bg-white/[0.02] transition-colors"
                      >
                        <div className="flex items-center gap-2">
                          <Bot size={12} className="text-accent-400" />
                          <span className="text-[10px] font-medium text-slate-400">AI 模型原文</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-accent-500/10 text-accent-400 border border-accent-500/20">
                            {aiData.ai_model}
                          </span>
                        </div>
                        <ChevronDown size={12} className={`text-slate-500 transition-transform ${showAiRaw ? 'rotate-180' : ''}`} />
                      </button>
                      {showAiRaw && (
                        <div className="px-4 pb-4 border-t border-white/[0.04]">
                          <div className="bg-surface-900/60 rounded-lg p-3 max-h-[300px] overflow-y-auto">
                            <MarkdownRenderer content={aiData.analysis} />
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Disclaimer */}
                  <p className="text-[9px] text-slate-600 text-center pt-1">
                    <Sparkles size={9} className="inline mr-1 text-accent-400/50" />
                    {aiData?.ai_model !== 'simulated'
                      ? `此分析由 ${aiData.ai_model || 'AI'} 生成，结合结构化增强引擎`
                      : '此分析由哨兵安全平台生成'}
                  </p>
                </div>
              )}

              {/* Fallback: plain markdown for real AI responses without structured data */}
              {aiData?.analysis && !aiData?.analysis_sections && !aiLoading && (
                <div className="bg-surface-800/30 rounded-lg p-4 border border-white/[0.04]">
                  <MarkdownRenderer content={aiData.analysis} />
                </div>
              )}

              {/* Empty state */}
              {!aiLoading && !aiError && !aiData?.analysis && !aiData?.analysis_sections && (
                <div className="text-center py-12">
                  <Bot size={36} className="text-accent-400/30 mx-auto mb-3" />
                  <p className="text-slate-500 text-xs mb-1">AI 深度分析漏洞威胁路径和业务影响</p>
                  <p className="text-slate-600 text-[10px] mb-4">攻击路径还原 · 利用难度评估 · 业务影响量化</p>
                  <button onClick={() => loadAi('analysis')} className="btn-primary text-xs">
                    <Sparkles size={13} /> 开始 AI 分析
                  </button>
                </div>
              )}

              {/* Model footer */}
              {aiData?.ai_model && !aiData?.analysis_sections && !aiLoading && (
                <p className="text-[10px] text-slate-600 text-right pt-1">模型：{aiData.ai_model}</p>
              )}
            </>
          )}
        </div>

        {/* Action Footer */}
        {(vuln.status === 'open' || vuln.status === 'in_progress') && (
          <div className="px-5 py-4 border-t border-white/[0.05] flex items-center gap-2 flex-wrap">
            <button
              disabled={updating}
              onClick={() => handleStatus('fixed')}
              className="btn-primary text-xs flex-1 justify-center"
            >
              <CheckCircle2 size={13} /> 标记已修复
            </button>
            {vuln.status === 'open' && (
              <button
                disabled={updating}
                onClick={() => handleStatus('in_progress')}
                className="btn-secondary text-xs flex-1 justify-center"
              >
                <ChevronRight size={13} /> 处理中
              </button>
            )}
            <button
              disabled={updating}
              onClick={() => handleStatus('ignored')}
              className="btn-secondary text-xs px-3 text-slate-500"
            >
              忽略
            </button>
            <button
              disabled={updating}
              onClick={handleCreateTicket}
              className="btn-secondary text-xs px-3 text-blue-400"
            >
              <Ticket size={13} /> 创建工单
            </button>
          </div>
        )}
      </div>

      <style>{`
        @keyframes slideInRight {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
      `}</style>
    </div>
  )
}

// ─── Main Component ───
export default function Vulnerabilities() {
  const navigate = useNavigate()
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<string>('全部')
  const [search, setSearch] = useState('')
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [drawerVuln, setDrawerVuln] = useState<Vulnerability | null>(null)
  const [verifyingId, setVerifyingId] = useState<number | null>(null)
  const [verifyMsg, setVerifyMsg] = useState<{ id: number; text: string; ok: boolean } | null>(null)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [totalPages, setTotalPages] = useState(1)
  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0, breached: 0, fixed: 0 })
  const [exporting, setExporting] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)

  // 把当前 tab / 搜索映射为后端筛选参数
  const buildFilterParams = () => {
    const params: Record<string, string> = {}
    if (activeTab === 'Critical') params.severity = 'critical'
    else if (activeTab === 'High') params.severity = 'high'
    else if (activeTab === 'Medium') params.severity = 'medium'
    else if (activeTab === 'Low') params.severity = 'low'
    else if (activeTab === '超时') params.sla = 'breached'
    else if (activeTab === '已修复') params.status = 'fixed'
    if (search.trim()) params.q = search.trim()
    return params
  }

  useEffect(() => {
    loadUsers()
    loadStats()
  }, [])

  // 分页 / 筛选 / 搜索变化时重新拉取（搜索做 300ms 防抖）
  useEffect(() => {
    const t = setTimeout(() => { loadVulnerabilities() }, search ? 300 : 0)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, activeTab, search])

  const loadVulnerabilities = async () => {
    setLoading(true)
    try {
      const res = await api.get('/scans/vulnerabilities', {
        params: { ...buildFilterParams(), page, per_page: PAGE_SIZE }
      })
      const data = res.data || {}
      // 兼容后端两种返回：分页对象 {items,...} 或旧版数组 [...]
      const items = Array.isArray(data) ? data : (data.items || [])
      setVulnerabilities(items)
      setTotal(Array.isArray(data) ? items.length : (data.total || 0))
      setTotalPages(Array.isArray(data) ? 1 : (data.total_pages || 1))
      setLoadError(null)
    } catch (e: any) {
      setVulnerabilities([]); setTotal(0); setTotalPages(1)
      if (e?.response?.status === 401) {
        setLoadError('登录状态已失效，请重新登录后再查看漏洞数据。')
      } else {
        setLoadError('漏洞数据加载失败，请确认后端服务是否正常运行。')
      }
    } finally { setLoading(false) }
  }

  const loadStats = async () => {
    try {
      const res = await api.get('/scans/vulnerabilities/stats')
      setStats(res.data || { total: 0, critical: 0, high: 0, medium: 0, low: 0, breached: 0, fixed: 0 })
    } catch {}
  }

  const loadUsers = async () => {
    try {
      const res = await api.get('/auth/users')
      setUsers(res.data || [])
    } catch { setUsers([]) }
  }

  const handleExport = async () => {
    setExporting(true)
    try {
      const res = await api.get('/scans/vulnerabilities/export', {
        params: buildFilterParams(),
        responseType: 'blob'
      })
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/csv;charset=utf-8' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `vulnerabilities_${new Date().toISOString().slice(0, 10)}.csv`
      document.body.appendChild(a); a.click(); a.remove()
      URL.revokeObjectURL(url)
    } catch {} finally { setExporting(false) }
  }

  const handleStatusChange = async (id: number, status: string) => {
    try {
      await api.patch(`/scans/vulnerabilities/${id}`, { status })
      setVulnerabilities(prev => prev.map(v => v.id === id ? { ...v, status } : v))
      if (drawerVuln?.id === id) setDrawerVuln(prev => prev ? { ...prev, status } : prev)
      loadStats()
    } catch {}
  }

  const handleAssign = async (vid: number, userId: number | null) => {
    try {
      await api.patch(`/scans/vulnerabilities/${vid}`, { assigned_to: userId })
      const user = users.find(u => u.id === userId)
      setVulnerabilities(prev => prev.map(v => v.id === vid
        ? { ...v, assigned_to: userId, assignee_name: user?.name || undefined }
        : v
      ))
    } catch {}
  }

  const handleReverify = async (vid: number) => {
    setVerifyingId(vid)
    setVerifyMsg(null)
    try {
      const res = await api.post(`/scans/vulnerabilities/${vid}/reverify`)
      const { result, message } = res.data
      setVerifyMsg({ id: vid, text: message, ok: result === 'fixed' })
      setTimeout(() => setVerifyMsg(null), 4000)
      loadVulnerabilities()
      loadStats()
    } catch (err: any) {
      setVerifyMsg({ id: vid, text: err.response?.data?.error || '验证失败', ok: false })
    } finally { setVerifyingId(null) }
  }

  // 服务端已完成筛选/搜索/排序/分页，当前页数据直接用
  const paged = vulnerabilities
  useEffect(() => { setPage(1) }, [activeTab, search])

  const toggleSelect = (id: number) => {
    setSelectedIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n })
  }
  const toggleSelectAll = () => {
    const openVulns = vulnerabilities.filter(v => v.status === 'open')
    const allSelected = openVulns.length > 0 && openVulns.every(v => selectedIds.has(v.id))
    allSelected ? setSelectedIds(new Set()) : setSelectedIds(new Set(openVulns.map(v => v.id)))
  }
  const handleBulkFix = async () => {
    if (selectedIds.size === 0) return
    try {
      await api.post('/scans/vulnerabilities/batch-fix', { ids: Array.from(selectedIds) })
      setSelectedIds(new Set())
      loadVulnerabilities()
      loadStats()
    } catch {}
  }

  const handleDelete = async (id: number, title: string) => {
    if (!confirm(`确定删除漏洞「${title}」？此操作不可撤销。`)) return
    try {
      await api.delete(`/vulnerabilities/${id}`)
      loadVulnerabilities()
      loadStats()
    } catch {}
  }

  const handleBulkDelete = async () => {
    if (selectedIds.size === 0) return
    if (!confirm(`确定删除选中的 ${selectedIds.size} 个漏洞？此操作不可撤销。`)) return
    try {
      await api.post('/scans/vulnerabilities/batch-delete', { ids: Array.from(selectedIds) })
      setSelectedIds(new Set())
      loadVulnerabilities()
      loadStats()
    } catch {}
  }

  const openCount = vulnerabilities.filter(v => v.status === 'open').length
  const allOpenSelected = openCount > 0 && vulnerabilities.filter(v => v.status === 'open').every(v => selectedIds.has(v.id))

  return (
    <div className="max-w-7xl mx-auto">
      <div className="page-header">
        <div>
          <h1 className="page-title">漏洞管理</h1>
          <p className="page-subtitle">全量漏洞追踪、SLA 管理与 AI 修复辅助</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={handleExport} disabled={exporting || total === 0} className="btn-secondary text-xs disabled:opacity-40">
            <Download size={13} className={exporting ? 'animate-pulse' : ''} /> {exporting ? '导出中...' : '导出 CSV'}
          </button>
          <button onClick={() => { loadVulnerabilities(); loadStats() }} className="btn-secondary text-xs">
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> 刷新
          </button>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-7 gap-3 mb-6">
        {[
          { label: '总计', value: stats.total, color: 'border-slate-500/50' },
          { label: 'Critical', value: stats.critical, color: 'border-red-500' },
          { label: 'High', value: stats.high, color: 'border-orange-500' },
          { label: 'Medium', value: stats.medium, color: 'border-yellow-500' },
          { label: 'Low', value: stats.low, color: 'border-blue-500' },
          { label: 'SLA 超时', value: stats.breached, color: 'border-red-600', blink: stats.breached > 0 },
          { label: '已修复', value: stats.fixed, color: 'border-green-500' },
        ].map(item => (
          <div key={item.label} className={`glass-card text-center py-3 border-t-2 ${item.color} ${(item as any).blink ? 'animate-pulse-soft' : ''}`}>
            <span className="text-2xl font-bold text-white block">{item.value}</span>
            <span className="text-slate-500 text-xs">{item.label}</span>
          </div>
        ))}
      </div>

      {/* Toolbar */}
      <div className="flex items-center justify-between mb-4 gap-3 flex-wrap">
        <div className="flex items-center gap-1.5 flex-wrap">
          {filterTabs.map(tab => (
            <button key={tab} onClick={() => setActiveTab(tab)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${activeTab === tab ? 'bg-primary-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-surface-700'}`}>
              {tab}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-3">
          {selectedIds.size > 0 && (
            <div className="flex items-center gap-2">
              <button onClick={handleBulkFix} className="btn-primary text-sm">批量修复 ({selectedIds.size})</button>
              <button onClick={handleBulkDelete} className="text-sm bg-red-600/20 text-red-400 hover:bg-red-600/30 px-3 py-1.5 rounded-lg transition-colors">
                批量删除 ({selectedIds.size})
              </button>
            </div>
          )}
          <input type="text" placeholder="搜索 CVE / 标题 / 路径..." value={search}
            onChange={e => setSearch(e.target.value)} className="input w-56" />
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <div className="glass-card p-6 space-y-3">
          {[1, 2, 3, 4, 5].map(i => (
            <div key={i} className="flex gap-4 items-center">
              <div className="skeleton w-4 h-4 rounded" />
              <div className="skeleton flex-1 h-4" />
              <div className="skeleton w-16 h-5 rounded-full" />
              <div className="skeleton w-20 h-4" />
              <div className="skeleton w-24 h-4" />
            </div>
          ))}
        </div>
      ) : loadError ? (
        <div className="empty-state">
          <div className="empty-state-icon"><Shield size={24} /></div>
          <h3 className="empty-state-title">数据加载失败</h3>
          <p className="empty-state-desc">{loadError}</p>
          <div className="flex gap-2 mt-3">
            <button onClick={() => loadVulnerabilities()}
              className="px-3 py-1.5 rounded bg-surface-800 border border-slate-700 text-xs hover:border-slate-600">
              重试
            </button>
            <button onClick={() => { localStorage.removeItem('sentinel_token'); window.location.href = '/login' }}
              className="px-3 py-1.5 rounded bg-primary-600 text-white text-xs hover:bg-primary-500">
              重新登录
            </button>
          </div>
        </div>
      ) : vulnerabilities.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon"><Shield size={24} /></div>
          <h3 className="empty-state-title">{search.trim() ? '未找到匹配漏洞' : '暂无漏洞数据'}</h3>
          <p className="empty-state-desc">{search.trim() ? '尝试修改搜索关键词' : '执行扫描后，漏洞将显示在这里'}</p>
        </div>
      ) : (
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th className="w-8"><input type="checkbox" onChange={toggleSelectAll} checked={allOpenSelected} className="checkbox" /></th>
                <th>标题 / CVE</th>
                <th>严重程度</th>
                <th className="w-28">SLA 状态</th>
                <th>指派人</th>
                <th>文件路径</th>
                <th>检测工具</th>
                <th>状态</th>
                <th className="w-32">操作</th>
              </tr>
            </thead>
            <tbody>
              {paged.map(v => {
                const sev = severityStyle[v.severity?.toLowerCase()]
                const isOpen = v.status === 'open' || v.status === 'in_progress'
                const slaBreached = v.sla_breached === 1 && v.status === 'open'
                return (
                  <tr key={v.id}
                    className="cursor-pointer hover:bg-primary-500/5 transition-colors"
                    onClick={() => setDrawerVuln(v)}>
                    <td onClick={e => e.stopPropagation()}>
                      {isOpen && <input type="checkbox" checked={selectedIds.has(v.id)} onChange={() => toggleSelect(v.id)} className="checkbox" />}
                    </td>
                    <td>
                      <div className="font-medium text-sm text-white truncate max-w-[220px] group-hover:text-primary-300">{v.title}</div>
                      <div className="font-mono text-xs text-slate-500 mt-0.5">{v.cve_id || '-'}</div>
                    </td>
                    <td>
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded ${sev?.bg || ''} ${sev?.text || ''}`}>
                        {v.severity?.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      {slaBreached ? (
                        <span className="text-xs text-red-400 font-semibold flex items-center gap-1">
                          <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" /> 已超时
                        </span>
                      ) : <span className="text-xs text-slate-600">-</span>}
                    </td>
                    <td className="text-xs text-slate-400">{v.assignee_name || '—'}</td>
                    <td className="font-mono text-xs max-w-[160px] truncate text-slate-500">{v.file_path}</td>
                    <td onClick={e => { e.stopPropagation(); if (v.source_tool) navigate('/tools') }}>
                      <span className="text-xs text-slate-400 hover:text-primary-400 hover:underline cursor-pointer transition-colors">
                        {v.source_tool || '-'}
                      </span>
                    </td>
                    <td>
                      <span className={`text-xs px-2 py-0.5 rounded-md ${statusStyle[v.status] || ''}`}>
                        {statusLabel[v.status] || v.status}
                      </span>
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => setDrawerVuln(v)}
                          className="text-xs bg-primary-600/15 text-primary-400 hover:bg-primary-600/25 px-2 py-1 rounded transition-colors flex items-center gap-1"
                        >
                          <Zap size={10} /> AI 分析
                        </button>
                        <button
                          onClick={() => handleReverify(v.id)}
                          disabled={verifyingId === v.id}
                          className="text-xs bg-indigo-600/15 text-indigo-400 hover:bg-indigo-600/25 px-2 py-1 rounded transition-colors disabled:opacity-50"
                        >
                          {verifyingId === v.id ? '...' : '验证'}
                        </button>
                        <button
                          onClick={() => handleDelete(v.id, v.title)}
                          className="text-xs bg-red-600/15 text-red-400 hover:bg-red-600/25 px-2 py-1 rounded transition-colors flex items-center gap-1"
                        >
                          <Trash2 size={10} /> 删除
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between pt-3 text-xs text-slate-400">
          <span>共 {total} 条 · 第 {page}/{totalPages} 页</span>
          <div className="flex items-center gap-1">
            <button disabled={page <= 1} onClick={() => setPage(page - 1)}
              className="px-2 py-1 rounded bg-surface-800 border border-slate-700 disabled:opacity-30 hover:border-slate-600">上一页</button>
            {(() => {
              // 页码窗口：最多显示 7 个，围绕当前页
              const win = 7
              let start = Math.max(1, page - Math.floor(win / 2))
              let end = Math.min(totalPages, start + win - 1)
              start = Math.max(1, end - win + 1)
              const pages = []
              for (let p = start; p <= end; p++) pages.push(p)
              return pages.map(p => (
                <button key={p} onClick={() => setPage(p)}
                  className={`px-2.5 py-1 rounded text-xs ${p === page ? 'bg-primary-600 text-white' : 'bg-surface-800 border border-slate-700 hover:border-slate-600'}`}>
                  {p}
                </button>
              ))
            })()}
            <button disabled={page >= totalPages} onClick={() => setPage(page + 1)}
              className="px-2 py-1 rounded bg-surface-800 border border-slate-700 disabled:opacity-30 hover:border-slate-600">下一页</button>
          </div>
        </div>
      )}

      {/* Drawer */}
      {drawerVuln && (
        <VulnDrawer
          vuln={drawerVuln}
          users={users}
          onClose={() => setDrawerVuln(null)}
          onStatusChange={handleStatusChange}
          onAssign={handleAssign}
        />
      )}

      {/* Toast */}
      {verifyMsg && (
        <div className={`fixed bottom-6 right-6 px-4 py-3 rounded-lg text-sm shadow-lg z-[60] transition-all ${verifyMsg.ok ? 'bg-green-600 text-white' : 'bg-red-600 text-white'}`}>
          {verifyMsg.text}
        </div>
      )}
    </div>
  )
}
