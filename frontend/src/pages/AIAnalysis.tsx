import { useState, useEffect, useRef } from 'react'
import api from '../api/client'

interface Vulnerability {
  id: number
  cve_id: string
  title: string
  severity: string
  file_path: string
  line: number
  source_tool: string
  status: string
  created_at: string
}

interface AnalysisResult {
  risk_score: number
  analysis: string
  simulated?: boolean
}

interface FixSuggestion {
  root_cause: string
  fix_approaches: string[]
  code_examples: string[]
  verification_steps: string[]
  simulated?: boolean
}

interface ChatMessage {
  role: 'user' | 'ai'
  content: string
}

const severityBadge: Record<string, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
}

function riskScoreColor(score: number): string {
  if (score >= 70) return '#ef4444'
  if (score >= 40) return '#f59e0b'
  return '#22c55e'
}

function renderMarkdown(text: string): JSX.Element[] {
  const lines = text.split('\n')
  const elements: JSX.Element[] = []
  let inCodeBlock = false
  let codeLines: string[] = []

  const flushCode = () => {
    if (codeLines.length > 0) {
      elements.push(
        <pre key={`code-${elements.length}`} className="code-block">
          <code>{codeLines.join('\n')}</code>
        </pre>
      )
      codeLines = []
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]

    if (line.trim().startsWith('```')) {
      if (inCodeBlock) {
        flushCode()
        inCodeBlock = false
      } else {
        inCodeBlock = true
      }
      continue
    }

    if (inCodeBlock) {
      codeLines.push(line)
      continue
    }

    if (line.trim() === '') {
      elements.push(<div key={i} className="h-2" />)
      continue
    }

    const trimmed = line.trim()

    if (trimmed.startsWith('### ')) {
      elements.push(
        <h3 key={i} className="text-lg font-semibold text-white mt-4 mb-2">
          {trimmed.slice(4)}
        </h3>
      )
      continue
    }

    if (trimmed.startsWith('## ')) {
      elements.push(
        <h2 key={i} className="text-xl font-bold text-white mt-4 mb-2">
          {trimmed.slice(3)}
        </h2>
      )
      continue
    }

    if (trimmed.startsWith('# ')) {
      elements.push(
        <h1 key={i} className="text-2xl font-bold text-white mt-4 mb-3">
          {trimmed.slice(2)}
        </h1>
      )
      continue
    }

    if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
      const content = processInlineMarkdown(trimmed.slice(2))
      elements.push(
        <li key={i} className="text-slate-300 ml-4 list-disc">
          {content}
        </li>
      )
      continue
    }

    const match = trimmed.match(/^(\d+)\.\s+(.+)/)
    if (match) {
      const content = processInlineMarkdown(match[2])
      elements.push(
        <li key={i} className="text-slate-300 ml-4 list-decimal">
          {content}
        </li>
      )
      continue
    }

    elements.push(
      <p key={i} className="text-slate-300 leading-relaxed">
        {processInlineMarkdown(trimmed)}
      </p>
    )
  }

  if (inCodeBlock) {
    flushCode()
  }

  return elements
}

function processInlineMarkdown(text: string): JSX.Element {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g)
  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith('**') && part.endsWith('**')) {
          return <strong key={i} className="text-white font-semibold">{part.slice(2, -2)}</strong>
        }
        if (part.startsWith('`') && part.endsWith('`')) {
          return <code key={i} className="code-inline">{part.slice(1, -1)}</code>
        }
        return <span key={i}>{part}</span>
      })}
    </>
  )
}

export default function AIAnalysis() {
  const [mode, setMode] = useState<'analyze' | 'chat'>('analyze')
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
  const [selectedVulnId, setSelectedVulnId] = useState<number | ''>('')
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null)
  const [fixSuggestion, setFixSuggestion] = useState<FixSuggestion | null>(null)
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([])
  const [chatInput, setChatInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [aiEnabled, setAiEnabled] = useState(false)
  const [aiStatusChecked, setAiStatusChecked] = useState(false)
  const [aiReachable, setAiReachable] = useState(false)
  const [attachedVulnId, setAttachedVulnId] = useState<number | null>(null)

  const chatEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    loadVulnerabilities()
    checkAiStatus()
    loadChatHistory()
  }, [])

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [chatMessages])

  const loadVulnerabilities = async () => {
    try {
      const res = await api.get('/scans/vulnerabilities')
      setVulnerabilities(res.data || [])
    } catch {
      setVulnerabilities([])
    }
  }

  const loadChatHistory = async () => {
    try {
      const res = await api.get('/ai/history')
      const rows = res.data?.messages ?? []
      const history: ChatMessage[] = rows.map((m: { role: string; content: string }) => ({
        // 后端存 'assistant'，前端用 'ai'
        role: m.role === 'user' ? 'user' : 'ai',
        content: m.content,
      }))
      setChatMessages(history)
    } catch {
      // 拉取历史失败不影响使用
    }
  }

  const handleClearHistory = async () => {
    if (!window.confirm('确定清空全部历史对话？此操作不可恢复。')) return
    try {
      await api.delete('/ai/history')
      setChatMessages([])
    } catch {
      // ignore
    }
  }

  const checkAiStatus = async () => {
    try {
      const res = await api.get('/ai/status')
      setAiEnabled(res.data?.enabled ?? false)
      setAiReachable(res.data?.reachable ?? false)
    } catch {
      setAiEnabled(false)
      setAiReachable(false)
    } finally {
      setAiStatusChecked(true)
    }
  }

  const selectedVuln = vulnerabilities.find((v) => v.id === selectedVulnId) || null

  const handleAnalyze = async () => {
    if (!selectedVulnId) return
    setLoading(true)
    setAnalysisResult(null)
    setFixSuggestion(null)
    try {
      const res = await api.post('/ai/analyze-vulnerability', {
        vulnerability_id: selectedVulnId,
      })
      setAnalysisResult(res.data)
    } catch {
      // silently ignore
    } finally {
      setLoading(false)
    }
  }

  const handleFixSuggestion = async () => {
    if (!selectedVulnId) return
    setLoading(true)
    setFixSuggestion(null)
    try {
      const res = await api.post('/ai/fix-suggestion', {
        vulnerability_id: selectedVulnId,
      })
      setFixSuggestion(res.data)
    } catch {
      // silently ignore
    } finally {
      setLoading(false)
    }
  }

  const handleSendChat = async () => {
    const message = chatInput.trim()
    if (!message) return

    const userMsg: ChatMessage = { role: 'user', content: message }
    setChatMessages((prev) => [...prev, userMsg])
    setChatInput('')
    setLoading(true)

    try {
      const context: { vulnerability_id?: number } = {}
      if (attachedVulnId) {
        context.vulnerability_id = attachedVulnId
      }

      const res = await api.post('/ai/chat', {
        message,
        context: Object.keys(context).length > 0 ? context : undefined,
      })

      const aiMsg: ChatMessage = {
        role: 'ai',
        content: res.data?.reply ?? res.data?.message ?? '无响应',
      }
      setChatMessages((prev) => [...prev, aiMsg])
    } catch {
      const errorMsg: ChatMessage = {
        role: 'ai',
        content: '请求失败，请稍后重试。',
      }
      setChatMessages((prev) => [...prev, errorMsg])
    } finally {
      setLoading(false)
    }
  }

  const handleChatKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSendChat()
    }
  }

  const attachVulnerabilityContext = () => {
    if (selectedVulnId) {
      setAttachedVulnId(attachedVulnId === selectedVulnId ? null : selectedVulnId)
    }
  }

  const isSimulated = !aiReachable

  return (
    <div className="max-w-7xl mx-auto">
      {/* Header */}
      <div className="page-header">
        <div className="flex items-center gap-3">
          <h1 className="page-title">AI 智能分析</h1>
          {aiStatusChecked && (
            <div className="flex items-center gap-1.5">
              <span
                className={`inline-block w-2 h-2 rounded-full ${
                  aiReachable
                    ? 'bg-green-400 shadow-[0_0_6px_rgba(74,222,128,0.6)]'
                    : aiEnabled
                      ? 'bg-amber-400 shadow-[0_0_6px_rgba(251,191,36,0.4)]'
                      : 'bg-slate-500'
                }`}
              />
              <span className="text-xs text-slate-400">
                {aiReachable ? 'AI 已启用' : aiEnabled ? 'AI 已配置 (未连通)' : 'AI 未配置'}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* AI Disabled / Unreachable Banner */}
      {aiStatusChecked && !aiReachable && (
        <div className={`card border mb-6 p-4 ${aiEnabled ? 'border-amber-500/30 bg-amber-500/5' : 'border-blue-500/30 bg-blue-500/5'}`}>
          <p className={`text-sm ${aiEnabled ? 'text-amber-300' : 'text-blue-300'}`}>
            {aiEnabled
              ? `⚠ AI 服务已配置（${(() => { try { const s = (window as any).__ai_status; return s?.provider || '未知'; } catch { return '未知'; } })()}）但当前不可达。将使用本地规则引擎回复。请检查 AI 服务地址是否正确。`
              : 'AI 服务未配置 — 请设置 SENTINEL_AI_API_KEY 环境变量后启用智能分析。当前将使用本地规则引擎。'
            }
          </p>
        </div>
      )}

      {/* Mode selector */}
      <div className="flex items-center gap-1 mb-6 border-b border-surface-border/50">
        <button
          onClick={() => setMode('analyze')}
          className={`tab px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
            mode === 'analyze'
              ? 'tab-active border-brand-500 text-brand-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          漏洞分析
        </button>
        <button
          onClick={() => setMode('chat')}
          className={`tab px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
            mode === 'chat'
              ? 'tab-active border-brand-500 text-brand-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          AI 安全顾问
        </button>
      </div>

      {/* ==============================
          Mode 1: 漏洞分析
          ============================== */}
      {mode === 'analyze' && (
        <div>
          {/* Vulnerability selector */}
          <div className="card p-5 mb-6">
            <h2 className="text-sm font-semibold text-slate-300 mb-4">选择漏洞进行分析</h2>
            <div className="flex items-end gap-4 flex-wrap">
              <div className="flex-1 min-w-[280px]">
                <label className="block text-xs text-slate-500 mb-1.5">漏洞</label>
                <select
                  value={selectedVulnId}
                  onChange={(e) => {
                    const val = e.target.value
                    setSelectedVulnId(val ? Number(val) : '')
                    setAnalysisResult(null)
                    setFixSuggestion(null)
                  }}
                  className="select w-full"
                >
                  <option value="">-- 选择漏洞 --</option>
                  {vulnerabilities.map((v) => (
                    <option key={v.id} value={v.id}>
                      {v.cve_id || 'N/A'} — {v.title} [{v.severity}]
                    </option>
                  ))}
                </select>
              </div>

              {selectedVuln && (
                <div className="flex items-center gap-2 pb-1">
                  {selectedVuln.cve_id && (
                    <span className="text-slate-300 font-mono text-sm">{selectedVuln.cve_id}</span>
                  )}
                  <span className={`badge ${severityBadge[selectedVuln.severity] || 'badge-info'}`}>
                    {selectedVuln.severity}
                  </span>
                </div>
              )}

              <button
                onClick={handleAnalyze}
                disabled={!selectedVulnId || loading}
                className="btn-primary disabled:opacity-50"
              >
                {loading ? '分析中...' : '智能分析'}
              </button>
            </div>
          </div>

          {/* Analysis result */}
          {analysisResult && (
            <div className="card p-5 mb-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold text-slate-300">分析结果</h2>
                {analysisResult.simulated !== undefined && analysisResult.simulated && (
                  <span className="badge badge-info text-xs">本地分析</span>
                )}
                {isSimulated && analysisResult.simulated === undefined && (
                  <span className="badge badge-info text-xs">本地分析</span>
                )}
              </div>

              {/* Risk score */}
              <div className="flex items-center gap-6 mb-6">
                <div className="flex items-center justify-center w-24 h-24 rounded-full border-4"
                  style={{ borderColor: riskScoreColor(analysisResult.risk_score) }}>
                  <span
                    className="text-3xl font-bold"
                    style={{ color: riskScoreColor(analysisResult.risk_score) }}
                  >
                    {analysisResult.risk_score}
                  </span>
                </div>
                <div>
                  <div className="text-xs text-slate-500 mb-1">风险评分</div>
                  <div className="text-sm text-slate-300">
                    {analysisResult.risk_score >= 70
                      ? '高风险 — 建议立即修复'
                      : analysisResult.risk_score >= 40
                      ? '中等风险 — 建议尽快修复'
                      : '低风险 — 可计划修复'}
                  </div>
                </div>
              </div>

              {/* AI Analysis content */}
              <div className="border-t border-surface-border/50 pt-4">
                <h3 className="text-sm font-medium text-slate-400 mb-3">AI 分析详情</h3>
                <div className="text-sm">{renderMarkdown(analysisResult.analysis)}</div>
              </div>

              {/* Fix suggestion button */}
              <div className="border-t border-surface-border/50 pt-4 mt-4">
                <button
                  onClick={handleFixSuggestion}
                  disabled={loading}
                  className="btn-secondary disabled:opacity-50"
                >
                  {loading ? '获取中...' : '获取修复建议'}
                </button>
              </div>
            </div>
          )}

          {/* Fix suggestion */}
          {fixSuggestion && (
            <div className="card p-5 mb-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold text-slate-300">修复建议</h2>
                {fixSuggestion.simulated !== undefined && fixSuggestion.simulated && (
                  <span className="badge badge-info text-xs">本地分析</span>
                )}
                {isSimulated && fixSuggestion.simulated === undefined && (
                  <span className="badge badge-info text-xs">本地分析</span>
                )}
              </div>

              {/* Root cause */}
              <div className="mb-5">
                <h3 className="text-sm font-medium text-slate-400 mb-2">根因分析</h3>
                <p className="text-sm text-slate-300 leading-relaxed">{fixSuggestion.root_cause}</p>
              </div>

              {/* Fix approaches */}
              {fixSuggestion.fix_approaches && fixSuggestion.fix_approaches.length > 0 && (
                <div className="mb-5">
                  <h3 className="text-sm font-medium text-slate-400 mb-2">修复方案</h3>
                  <ol className="text-sm text-slate-300 space-y-1.5 ml-4 list-decimal">
                    {fixSuggestion.fix_approaches.map((approach, i) => (
                      <li key={i}>{approach}</li>
                    ))}
                  </ol>
                </div>
              )}

              {/* Code examples */}
              {fixSuggestion.code_examples && fixSuggestion.code_examples.length > 0 && (
                <div className="mb-5">
                  <h3 className="text-sm font-medium text-slate-400 mb-2">代码示例</h3>
                  {fixSuggestion.code_examples.map((code, i) => (
                    <pre key={i} className="code-block mb-3">
                      <code>{code}</code>
                    </pre>
                  ))}
                </div>
              )}

              {/* Verification steps */}
              {fixSuggestion.verification_steps && fixSuggestion.verification_steps.length > 0 && (
                <div>
                  <h3 className="text-sm font-medium text-slate-400 mb-2">验证步骤</h3>
                  <ol className="text-sm text-slate-300 space-y-1.5 ml-4 list-decimal">
                    {fixSuggestion.verification_steps.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ol>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ==============================
          Mode 2: AI 安全顾问
          ============================== */}
      {mode === 'chat' && (
        <div className="flex flex-col" style={{ height: 'calc(100vh - 280px)', minHeight: '500px' }}>
          {/* AI status + context bar */}
          <div className="card p-3 mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span
                className={`inline-block w-2.5 h-2.5 rounded-full ${
                  aiReachable
                    ? 'bg-green-400 shadow-[0_0_6px_rgba(74,222,128,0.6)]'
                    : aiEnabled
                      ? 'bg-amber-400'
                      : 'bg-slate-500'
                }`}
              />
              <span className="text-sm text-slate-400">
                {aiReachable ? 'AI 安全顾问已就绪' : aiEnabled ? 'AI 安全顾问 (离线模式)' : '本地规则引擎模式'}
              </span>
            </div>
            <div className="flex items-center gap-3">
              {attachedVulnId && (() => {
                const v = vulnerabilities.find((v) => v.id === attachedVulnId)
                return v ? (
                  <span className="text-xs text-brand-400 bg-brand-500/10 px-2 py-0.5 rounded">
                    已关联: {v.cve_id || v.title}
                  </span>
                ) : null
              })()}
              {selectedVulnId ? (
                <button
                  onClick={attachVulnerabilityContext}
                  className={`text-xs px-2 py-1 rounded transition-colors ${
                    attachedVulnId === selectedVulnId
                      ? 'bg-brand-500/20 text-brand-400 border border-brand-500/30'
                      : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-600'
                  }`}
                >
                  {attachedVulnId === selectedVulnId ? '取消关联' : '关联当前漏洞'}
                </button>
              ) : (
                <span className="text-xs text-slate-600">
                  先在"漏洞分析"中选择漏洞以关联上下文
                </span>
              )}
              {chatMessages.length > 0 && (
                <button
                  onClick={handleClearHistory}
                  className="text-xs px-2 py-1 rounded transition-colors bg-slate-800 text-slate-400 border border-slate-700 hover:border-red-600 hover:text-red-400"
                >
                  清空历史
                </button>
              )}
            </div>
          </div>

          {/* Chat messages */}
          <div className="flex-1 overflow-y-auto mb-4 space-y-4 pr-1">
            {chatMessages.length === 0 && (
              <div className="flex items-center justify-center h-full">
                <div className="text-center">
                  <div className="text-slate-500 text-sm mb-1">
                    {aiReachable
                      ? 'AI 安全顾问 — 请描述您的安全问题'
                      : '本地规则引擎 — 可解答常见安全问题（AI 服务未连通）'}
                  </div>
                  <div className="text-slate-600 text-xs">
                    支持: 漏洞分析、安全最佳实践、代码审计、威胁建模等
                  </div>
                </div>
              </div>
            )}

            {chatMessages.map((msg, i) => (
              <div
                key={i}
                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-[75%] rounded-xl px-4 py-3 text-sm leading-relaxed ${
                    msg.role === 'user'
                      ? 'bg-brand-500/20 text-slate-200 border border-brand-500/30'
                      : 'bg-slate-800/80 text-slate-300 border border-surface-border/50'
                  }`}
                >
                  {msg.role === 'ai' ? renderMarkdown(msg.content) : msg.content}
                </div>
              </div>
            ))}

            {loading && (
              <div className="flex justify-start">
                <div className="bg-slate-800/80 text-slate-300 border border-surface-border/50 rounded-xl px-4 py-3">
                  <span className="loading-dots">思考中</span>
                </div>
              </div>
            )}

            <div ref={chatEndRef} />
          </div>

          {/* Chat input */}
          <div className="card p-3">
            <div className="flex items-end gap-3">
              <textarea
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyDown={handleChatKeyDown}
                placeholder="输入安全问题..."
                rows={2}
                className="input flex-1 resize-none"
                disabled={loading}
              />
              <button
                onClick={handleSendChat}
                disabled={!chatInput.trim() || loading}
                className="btn-primary disabled:opacity-50 h-10 px-5"
              >
                {loading ? '发送中...' : '发送'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
