import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search } from 'lucide-react'
import api from '../api/client'

interface ResultItem {
  id: string
  title: string
  subtitle?: string
  group: '页面' | '项目' | '漏洞'
  to: string
  badge?: string
}

const PAGES: { label: string; path: string; keywords: string }[] = [
  { label: '今日概览', path: '/', keywords: 'today overview 概览 首页' },
  { label: '漏洞管理', path: '/vulnerabilities', keywords: 'vuln 漏洞 弱点' },
  { label: '扫描中心', path: '/scans', keywords: 'scan 扫描' },
  { label: '工单中心', path: '/tickets', keywords: 'ticket 工单 任务' },
  { label: '告警中心', path: '/alerts', keywords: 'alert 告警 通知' },
  { label: '事件调查', path: '/investigation', keywords: 'investigation 调查 溯源' },
  { label: 'AI 分析', path: '/ai', keywords: 'ai 分析 大模型' },
  { label: '知识库', path: '/knowledge-base', keywords: 'knowledge 知识 文档' },
  { label: '技能中心', path: '/skills', keywords: 'skill 技能 智能体 封装' },
  { label: '项目管理', path: '/projects', keywords: 'project 项目 仓库' },
  { label: '工具集成', path: '/tools', keywords: 'tool 工具 集成 semgrep' },
  { label: '资产管理', path: '/assets', keywords: 'asset 资产 组件' },
  { label: '规则管理', path: '/rules', keywords: 'rule 规则 忽略' },
  { label: '报告中心', path: '/reports', keywords: 'report 报告 导出' },
  { label: '审计日志', path: '/audit', keywords: 'audit 审计 日志' },
  { label: '用户管理', path: '/users', keywords: 'user 用户 权限' },
  { label: '系统设置', path: '/settings', keywords: 'setting 设置 配置' },
]

export default function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const [projects, setProjects] = useState<ResultItem[]>([])
  const [vulns, setVulns] = useState<ResultItem[]>([])
  const [loaded, setLoaded] = useState(false)
  const [loading, setLoading] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) return
    setQuery('')
    setActive(0)
    setTimeout(() => inputRef.current?.focus(), 0)
    if (loaded) return
    setLoading(true)
    Promise.all([
      api.get('/projects').then(r =>
        (r.data?.items || []).map((p: any) => ({
          id: 'p' + p.id, title: p.name, subtitle: p.repo_url || p.repo_path || '',
          group: '项目' as const, to: '/projects',
        }))
      ).catch(() => [] as ResultItem[]),
      api.get('/scans/vulnerabilities').then(r =>
        (Array.isArray(r.data) ? r.data : []).slice(0, 200).map((v: any) => ({
          id: 'v' + v.id, title: v.title,
          subtitle: [v.project_name, v.severity, v.status].filter(Boolean).join(' · '),
          group: '漏洞' as const, to: `/investigation?vuln=${v.id}`, badge: v.severity,
        }))
      ).catch(() => [] as ResultItem[]),
    ]).then(([p, v]) => {
      setProjects(p); setVulns(v); setLoaded(true); setLoading(false)
    })
  }, [open, loaded])

  const results = useMemo(() => {
    const q = query.trim().toLowerCase()
    const pageResults: ResultItem[] = PAGES
      .filter(p => !q || p.label.toLowerCase().includes(q) || p.keywords.toLowerCase().includes(q))
      .map(p => ({ id: 'pg' + p.path, title: p.label, group: '页面' as const, to: p.path }))
    const filt = (arr: ResultItem[]) =>
      !q ? arr : arr.filter(i => i.title.toLowerCase().includes(q) || (i.subtitle || '').toLowerCase().includes(q))
    return [...pageResults, ...filt(projects), ...filt(vulns)]
  }, [query, projects, vulns])

  useEffect(() => { setActive(0) }, [query])

  const go = (item?: ResultItem) => {
    const it = item || results[active]
    if (!it) return
    onClose()
    navigate(it.to)
  }

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive(a => Math.min(a + 1, results.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(a => Math.max(a - 1, 0)) }
    else if (e.key === 'Enter') { e.preventDefault(); go() }
    else if (e.key === 'Escape') { e.preventDefault(); onClose() }
  }

  if (!open) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh] px-4 bg-black/50 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl bg-surface-900 border border-white/[0.06] rounded-2xl shadow-2xl overflow-hidden"
        onClick={e => e.stopPropagation()}
        onKeyDown={onKey}
      >
        <div className="flex items-center gap-3 px-4 border-b border-white/[0.05]">
          <Search size={18} className="text-slate-500 flex-shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="搜索页面、项目或漏洞…"
            className="flex-1 bg-transparent py-3.5 text-sm text-slate-100 placeholder:text-slate-500 outline-none"
          />
          <kbd className="text-[10px] text-slate-500 border border-white/10 rounded px-1.5 py-0.5">ESC</kbd>
        </div>

        <div className="max-h-[50vh] overflow-y-auto py-2">
          {loading && results.length === 0 && (
            <div className="px-4 py-6 text-center text-sm text-slate-500">加载中…</div>
          )}
          {!loading && results.length === 0 && (
            <div className="px-4 py-6 text-center text-sm text-slate-500">没有匹配的结果</div>
          )}
          {results.map((r, i) => (
            <button
              key={r.id}
              onMouseEnter={() => setActive(i)}
              onClick={() => go(r)}
              className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                i === active ? 'bg-primary-500/10' : 'hover:bg-surface-800/60'
              }`}
            >
              <span className={`text-[10px] px-1.5 py-0.5 rounded flex-shrink-0 ${
                r.group === '页面' ? 'bg-slate-500/15 text-slate-300'
                : r.group === '项目' ? 'bg-blue-500/15 text-blue-300'
                : 'bg-red-500/15 text-red-300'
              }`}>{r.group}</span>
              <div className="flex-1 min-w-0">
                <div className="text-sm text-slate-100 truncate">{r.title}</div>
                {r.subtitle && <div className="text-[11px] text-slate-500 truncate">{r.subtitle}</div>}
              </div>
              {r.group === '漏洞' && r.badge && (
                <span className={`badge badge-${r.badge === 'critical' ? 'critical' : r.badge === 'high' ? 'high' : r.badge === 'medium' ? 'warning' : 'info'} text-[10px]`}>
                  {r.badge}
                </span>
              )}
              {i === active && <span className="text-[10px] text-primary-400">↵</span>}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-4 px-4 py-2 border-t border-white/[0.05] text-[11px] text-slate-500">
          <span>↑↓ 选择</span>
          <span>↵ 打开</span>
          <span>esc 关闭</span>
          <span className="ml-auto">{results.length} 个结果</span>
        </div>
      </div>
    </div>
  )
}
