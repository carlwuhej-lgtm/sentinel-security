import { useState, useEffect } from 'react'
import api from '../api/client'

interface Skill {
  id: string
  name: string
  description: string
  risk: string
  module: string
  source?: string
  approval?: string
  runner?: { type?: string }
}

const SOURCE_LABEL: Record<string, string> = {
  builtin: '内置',
  user: '自定义',
  marketplace: '市场',
  repo: '仓库',
}

const RISK_STYLE: Record<string, string> = {
  low: 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20',
  medium: 'bg-amber-500/10 text-amber-300 border border-amber-500/20',
  high: 'bg-red-500/10 text-red-300 border border-red-500/20',
}

const RISK_LABEL: Record<string, string> = {
  low: '低风险',
  medium: '中风险',
  high: '高风险',
}

const LANGUAGES = [
  { value: 'general', label: '通用' },
  { value: 'java', label: 'Java' },
  { value: 'python', label: 'Python' },
  { value: 'go', label: 'Go' },
  { value: 'javascript', label: 'JavaScript / TypeScript' },
]

export default function Skills() {
  const [skills, setSkills] = useState<Skill[]>([])
  const [isAdmin, setIsAdmin] = useState(false)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState<string | null>(null)
  const [result, setResult] = useState<any>(null)
  const [language, setLanguage] = useState('general')
  const [error, setError] = useState('')

  // 上传技能弹窗状态
  const [uploadOpen, setUploadOpen] = useState(false)
  const [manifestFile, setManifestFile] = useState<File | null>(null)
  const [scriptFile, setScriptFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadMsg, setUploadMsg] = useState('')

  // 接入 MCP 弹窗状态
  const [mcpOpen, setMcpOpen] = useState(false)
  const [mcpForm, setMcpForm] = useState({
    id: '', name: '', description: '', risk: 'low',
    transport: 'stdio', command: '', args: '', url: '', tool: '', timeout: '20',
  })
  const [mcpMsg, setMcpMsg] = useState('')
  const [mcpSubmitting, setMcpSubmitting] = useState(false)

  useEffect(() => { loadSkills() }, [])

  const loadSkills = async () => {
    try {
      const res = await api.get('/skills')
      const data = res.data || {}
      setSkills(data.skills || [])
      setIsAdmin(!!data.is_admin)
    } catch {
      setError('加载技能列表失败')
    } finally {
      setLoading(false)
    }
  }

  const runSkill = async (id: string) => {
    setRunning(id)
    setError('')
    setResult(null)
    try {
      const payload = id === 'code-audit' ? { language } : {}
      const res = await api.post(`/skills/${id}/run`, payload)
      setResult(res.data)
    } catch (e: any) {
      setError(e?.response?.data?.error || '运行失败')
    } finally {
      setRunning(null)
    }
  }

  const approve = async (id: string) => {
    try { await api.post(`/skills/${id}/approve`); loadSkills() }
    catch (e: any) { setError(e?.response?.data?.error || '审批失败') }
  }
  const reject = async (id: string) => {
    try { await api.post(`/skills/${id}/reject`); loadSkills() }
    catch (e: any) { setError(e?.response?.data?.error || '操作失败') }
  }

  const onUpload = async () => {
    if (!manifestFile) { setUploadMsg('请先选择 manifest JSON 文件'); return }
    setUploading(true)
    setUploadMsg('')
    try {
      const fd = new FormData()
      fd.append('manifest', manifestFile)
      if (scriptFile) fd.append('script', scriptFile)
      const res = await api.post('/skills/upload', fd)
      setUploadMsg(res.data?.message || '已提交，等待管理员审批')
      setUploadOpen(false)
      setManifestFile(null)
      setScriptFile(null)
      loadSkills()
    } catch (e: any) {
      setUploadMsg(e?.response?.data?.error || '上传失败')
    } finally {
      setUploading(false)
    }
  }

  const onMcpSubmit = async () => {
    if (!mcpForm.id.trim() || !mcpForm.name.trim() || !mcpForm.tool.trim()) {
      setMcpMsg('请填写 id / 名称 / tool 名称')
      return
    }
    setMcpSubmitting(true)
    setMcpMsg('')
    const runner: any = {
      type: 'mcp',
      transport: mcpForm.transport,
      tool: mcpForm.tool.trim(),
      timeout: Number(mcpForm.timeout) || 20,
    }
    if (mcpForm.transport === 'stdio') {
      runner.command = mcpForm.command.trim()
      runner.args = mcpForm.args.split(',').map(s => s.trim()).filter(Boolean)
    } else {
      runner.url = mcpForm.url.trim()
    }
    const manifest = {
      id: mcpForm.id.trim(),
      name: mcpForm.name.trim(),
      description: mcpForm.description.trim(),
      risk: mcpForm.risk,
      runner,
    }
    try {
      const res = await api.post('/skills/upload', { manifest })
      setMcpMsg(res.data?.message || '已提交，等待管理员审批')
      setMcpOpen(false)
      setMcpForm({ id: '', name: '', description: '', risk: 'low', transport: 'stdio', command: '', args: '', url: '', tool: '', timeout: '20' })
      loadSkills()
    } catch (e: any) {
      setMcpMsg(e?.response?.data?.error || '提交失败')
    } finally {
      setMcpSubmitting(false)
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="page-title">技能中心</h1>
          <p className="text-sm text-slate-400 mt-1">
            把平台安全能力封装为可一键调用的「技能」。自己或第三方上传/接入的技能需管理员审批后上架；平台作为 MCP Client 连接外部 MCP 时不向其注入任何内部密钥。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => { setUploadMsg(''); setUploadOpen(true) }}
            className="btn-primary text-xs whitespace-nowrap"
          >
            + 上传技能
          </button>
          <button
            onClick={() => { setMcpMsg(''); setMcpOpen(true) }}
            className="text-xs px-4 py-2 rounded-lg border border-white/10 text-slate-300 hover:bg-white/5 whitespace-nowrap"
          >
            + 接入 MCP
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl bg-red-500/10 border border-red-500/20 text-red-300 text-sm px-4 py-3">
          {error}
        </div>
      )}

      {loading ? (
        <div className="text-slate-400 text-sm">加载中…</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {skills.map((s) => {
            const approved = s.approval === 'approved'
            const pending = s.approval === 'pending'
            const rejected = s.approval === 'rejected'
            return (
              <div key={s.id} className="rounded-2xl bg-surface-900/80 border border-white/[0.03] p-5 flex flex-col">
                <div className="flex items-start justify-between gap-3">
                  <h3 className="text-base font-semibold text-slate-100">{s.name}</h3>
                  <span className={`text-xs px-2 py-0.5 rounded-full ${RISK_STYLE[s.risk] || RISK_STYLE.low}`}>
                    {RISK_LABEL[s.risk] || '低风险'}
                  </span>
                </div>
                <p className="text-sm text-slate-400 mt-2 flex-1">{s.description}</p>
                <p className="text-xs text-slate-500 mt-2">
                  来源：{SOURCE_LABEL[s.source || ''] || s.source || '内置'}
                  {s.runner?.type === 'mcp' && <span className="text-sky-300"> · MCP（外部）</span>}
                  {pending && <span className="text-amber-300"> · 待审批</span>}
                  {rejected && <span className="text-red-300"> · 已拒绝</span>}
                </p>
                <div className="mt-4 flex items-center gap-3 flex-wrap">
                  {s.id === 'code-audit' && approved && (
                    <select
                      value={language}
                      onChange={(e) => setLanguage(e.target.value)}
                      className="bg-surface-800 border border-white/10 rounded-lg px-2 py-1.5 text-sm text-slate-200"
                    >
                      {LANGUAGES.map((l) => (
                        <option key={l.value} value={l.value}>{l.label}</option>
                      ))}
                    </select>
                  )}
                  {approved ? (
                    <button
                      onClick={() => runSkill(s.id)}
                      disabled={running === s.id}
                      className="btn-primary text-xs"
                    >
                      {running === s.id ? '运行中…' : '运行技能'}
                    </button>
                  ) : (
                    <span className="text-xs text-slate-500">
                      {pending ? '待管理员审批后可运行' : '已拒绝，不可运行'}
                    </span>
                  )}
                  {isAdmin && (pending || rejected) && (
                    <button
                      onClick={() => approve(s.id)}
                      className="text-xs px-3 py-1.5 rounded-lg bg-emerald-500/15 text-emerald-300 border border-emerald-500/20 hover:bg-emerald-500/25"
                    >
                      通过
                    </button>
                  )}
                  {isAdmin && pending && (
                    <button
                      onClick={() => reject(s.id)}
                      className="text-xs px-3 py-1.5 rounded-lg bg-red-500/15 text-red-300 border border-red-500/20 hover:bg-red-500/25"
                    >
                      拒绝
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {result && (
        <div className="rounded-2xl bg-surface-900/80 border border-primary-500/15 p-5">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-emerald-400 text-sm font-medium">✓ 技能运行完成</span>
          </div>

          {result.skill === 'code-audit' && (
            <div className="space-y-2 max-h-80 overflow-auto">
              {result.items.map((it: any, i: number) => (
                <div key={i} className="rounded-lg bg-surface-800/60 border border-white/[0.03] px-3 py-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-primary-300">{it.cwe || '—'}</span>
                    <span className="text-sm text-slate-200">{it.title}</span>
                    <span className="text-xs text-slate-500 ml-auto">{it.category}</span>
                  </div>
                  {it.summary && <p className="text-xs text-slate-400 mt-1">{it.summary}</p>}
                </div>
              ))}
            </div>
          )}

          {result.skill === 'vuln-triage' && (
            <div className="text-sm text-slate-300">
              共处理 <span className="text-slate-100 font-semibold">{result.total}</span> 个漏洞，
              本次修正定级 <span className="text-slate-100 font-semibold">{result.updated}</span> 个。
              前往「漏洞管理」页可看到更新后的 severity 标记。
            </div>
          )}

          {result.external && (
            <div className="space-y-1 max-h-80 overflow-auto">
              <p className="text-xs text-slate-400">外部 MCP 返回（{result.transport} / tool: {result.tool}）：</p>
              {(result.result || []).map((t: string, i: number) => (
                <pre key={i} className="text-[11px] text-slate-300 bg-surface-800/60 border border-white/[0.03] rounded-lg px-3 py-2 whitespace-pre-wrap">{t}</pre>
              ))}
            </div>
          )}

          <pre className="mt-3 text-[11px] text-slate-500 overflow-auto max-h-40">
{JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}

      {/* 上传技能弹窗 */}
      {uploadOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => setUploadOpen(false)}>
          <div
            className="w-full max-w-lg rounded-2xl bg-surface-900 border border-white/10 p-6 space-y-4"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-slate-100">上传技能</h3>
              <button onClick={() => setUploadOpen(false)} className="text-slate-400 hover:text-slate-200 text-lg leading-none">×</button>
            </div>
            <p className="text-xs text-slate-400">
              提交后将进入「待审批」状态，管理员通过后才会在技能中心上架并可供运行。脚本类技能将在服务端运行，请确保来源可信。
            </p>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate-300">技能清单 (manifest.json) <span className="text-red-400">*</span></label>
                <input
                  type="file" accept=".json,application/json"
                  onChange={(e) => setManifestFile(e.target.files?.[0] || null)}
                  className="mt-1 block w-full text-sm text-slate-300 file:mr-3 file:rounded-lg file:border-0 file:bg-primary-500/20 file:px-3 file:py-1.5 file:text-primary-200 hover:file:bg-primary-500/30"
                />
              </div>
              <div>
                <label className="text-xs text-slate-300">脚本 (可选, .py) — runner.type=script 时必填</label>
                <input
                  type="file" accept=".py,text/x-python"
                  onChange={(e) => setScriptFile(e.target.files?.[0] || null)}
                  className="mt-1 block w-full text-sm text-slate-300 file:mr-3 file:rounded-lg file:border-0 file:bg-surface-700 file:px-3 file:py-1.5 file:text-slate-200 hover:file:bg-surface-600"
                />
              </div>
            </div>

            {uploadMsg && (
              <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs px-3 py-2">
                {uploadMsg}
              </div>
            )}

            <div className="flex justify-end gap-3 pt-2">
              <button onClick={() => setUploadOpen(false)} className="text-xs px-4 py-2 rounded-lg border border-white/10 text-slate-300 hover:bg-white/5">
                取消
              </button>
              <button onClick={onUpload} disabled={uploading} className="btn-primary text-xs">
                {uploading ? '上传中…' : '提交审批'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 接入 MCP 弹窗 */}
      {mcpOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => setMcpOpen(false)}>
          <div
            className="w-full max-w-lg rounded-2xl bg-surface-900 border border-white/10 p-6 space-y-4"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-slate-100">接入外部 MCP</h3>
              <button onClick={() => setMcpOpen(false)} className="text-slate-400 hover:text-slate-200 text-lg leading-none">×</button>
            </div>
            <p className="text-xs text-slate-400">
              填写别人写好的 MCP Server 启动方式。提交后进入「待审批」，管理员通过后才上架。平台作为 MCP Client 连接它并调用声明的 tool（不向其注入内部密钥）。
            </p>

            <div className="space-y-3 max-h-[68vh] overflow-auto pr-1">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-slate-300">技能 ID <span className="text-red-400">*</span></label>
                  <input value={mcpForm.id} onChange={(e) => setMcpForm({ ...mcpForm, id: e.target.value })}
                    placeholder="vendor-cve-mcp" className="mt-1 block w-full bg-surface-800 border border-white/10 rounded-lg px-2 py-1.5 text-sm text-slate-200" />
                </div>
                <div>
                  <label className="text-xs text-slate-300">名称 <span className="text-red-400">*</span></label>
                  <input value={mcpForm.name} onChange={(e) => setMcpForm({ ...mcpForm, name: e.target.value })}
                    placeholder="某厂商 CVE 情报" className="mt-1 block w-full bg-surface-800 border border-white/10 rounded-lg px-2 py-1.5 text-sm text-slate-200" />
                </div>
              </div>
              <div>
                <label className="text-xs text-slate-300">描述</label>
                <input value={mcpForm.description} onChange={(e) => setMcpForm({ ...mcpForm, description: e.target.value })}
                  placeholder="一句话说明这个 MCP 做什么" className="mt-1 block w-full bg-surface-800 border border-white/10 rounded-lg px-2 py-1.5 text-sm text-slate-200" />
              </div>
              <div>
                <label className="text-xs text-slate-300">传输方式</label>
                <div className="mt-1 flex gap-2">
                  {(['stdio', 'sse'] as const).map((t) => (
                    <button key={t} onClick={() => setMcpForm({ ...mcpForm, transport: t })}
                      className={`text-xs px-3 py-1.5 rounded-lg border ${mcpForm.transport === t ? 'bg-primary-500/20 text-primary-200 border-primary-500/30' : 'border-white/10 text-slate-300'}`}>
                      {t === 'stdio' ? 'stdio 本地进程' : 'sse 远程'}
                    </button>
                  ))}
                </div>
              </div>
              {mcpForm.transport === 'stdio' ? (
                <>
                  <div>
                    <label className="text-xs text-slate-300">启动命令 command <span className="text-red-400">*</span></label>
                    <input value={mcpForm.command} onChange={(e) => setMcpForm({ ...mcpForm, command: e.target.value })}
                      placeholder="npx" className="mt-1 block w-full bg-surface-800 border border-white/10 rounded-lg px-2 py-1.5 text-sm text-slate-200" />
                  </div>
                  <div>
                    <label className="text-xs text-slate-300">参数 args（逗号分隔）</label>
                    <input value={mcpForm.args} onChange={(e) => setMcpForm({ ...mcpForm, args: e.target.value })}
                      placeholder="-y, @vendor/cve-mcp" className="mt-1 block w-full bg-surface-800 border border-white/10 rounded-lg px-2 py-1.5 text-sm text-slate-200" />
                  </div>
                </>
              ) : (
                <div>
                  <label className="text-xs text-slate-300">连接地址 url (http/https) <span className="text-red-400">*</span></label>
                  <input value={mcpForm.url} onChange={(e) => setMcpForm({ ...mcpForm, url: e.target.value })}
                    placeholder="http://localhost:8000/sse" className="mt-1 block w-full bg-surface-800 border border-white/10 rounded-lg px-2 py-1.5 text-sm text-slate-200" />
                </div>
              )}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-slate-300">要调用的 tool 名 <span className="text-red-400">*</span></label>
                  <input value={mcpForm.tool} onChange={(e) => setMcpForm({ ...mcpForm, tool: e.target.value })}
                    placeholder="get_cve" className="mt-1 block w-full bg-surface-800 border border-white/10 rounded-lg px-2 py-1.5 text-sm text-slate-200" />
                </div>
                <div>
                  <label className="text-xs text-slate-300">超时（秒）</label>
                  <input value={mcpForm.timeout} onChange={(e) => setMcpForm({ ...mcpForm, timeout: e.target.value })}
                    className="mt-1 block w-full bg-surface-800 border border-white/10 rounded-lg px-2 py-1.5 text-sm text-slate-200" />
                </div>
              </div>
            </div>

            {mcpMsg && (
              <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs px-3 py-2">
                {mcpMsg}
              </div>
            )}

            <div className="flex justify-end gap-3 pt-2">
              <button onClick={() => setMcpOpen(false)} className="text-xs px-4 py-2 rounded-lg border border-white/10 text-slate-300 hover:bg-white/5">
                取消
              </button>
              <button onClick={onMcpSubmit} disabled={mcpSubmitting} className="btn-primary text-xs">
                {mcpSubmitting ? '提交中…' : '提交审批'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
