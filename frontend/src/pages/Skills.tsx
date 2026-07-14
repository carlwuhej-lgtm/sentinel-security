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

  // 上传弹窗状态
  const [uploadOpen, setUploadOpen] = useState(false)
  const [manifestFile, setManifestFile] = useState<File | null>(null)
  const [scriptFile, setScriptFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadMsg, setUploadMsg] = useState('')

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

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="page-title">技能中心</h1>
          <p className="text-sm text-slate-400 mt-1">
            把平台安全能力封装为可一键调用的「技能」。自己或第三方上传的技能需管理员审批后上架；当前均为低风险能力，不涉及密钥、不出网、不触碰认证与加密。
          </p>
        </div>
        <button
          onClick={() => { setUploadMsg(''); setUploadOpen(true) }}
          className="btn-primary text-xs whitespace-nowrap"
        >
          + 上传技能
        </button>
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
            <span className="text-emerald-400 text-sm font-medium">✓ {result.message}</span>
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
    </div>
  )
}
