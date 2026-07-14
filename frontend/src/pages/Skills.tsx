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
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState<string | null>(null)
  const [result, setResult] = useState<any>(null)
  const [language, setLanguage] = useState('general')
  const [error, setError] = useState('')

  useEffect(() => { loadSkills() }, [])

  const loadSkills = async () => {
    try {
      const res = await api.get('/skills')
      setSkills(res.data)
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

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="page-title">技能中心</h1>
        <p className="text-sm text-slate-400 mt-1">
          把平台安全能力封装为可一键调用的「技能」。当前均为低风险能力，不涉及密钥、不出网、不触碰认证与加密。
        </p>
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
          {skills.map((s) => (
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
                {s.approval === 'pending' ? ' · 待审批' : ''}
              </p>
              <div className="mt-4 flex items-center gap-3">
                {s.id === 'code-audit' && (
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
                <button
                  onClick={() => runSkill(s.id)}
                  disabled={running === s.id}
                  className="btn-primary text-xs"
                >
                  {running === s.id ? '运行中…' : '运行技能'}
                </button>
              </div>
            </div>
          ))}
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
    </div>
  )
}
