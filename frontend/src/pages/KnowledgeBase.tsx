import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'
import { BookOpen, Search, TrendingUp, Clock, Plus, Tag, Folder, Eye, Lightbulb, ArrowRight, AlertTriangle, Download, Upload } from 'lucide-react'

interface Article {
  id: number
  title: string
  category: string
  category_label: string
  tags: string[]
  author_name: string
  view_count: number
  summary: string
  created_at: string
  updated_at: string
}

interface Meta {
  categories: { key: string; label: string; count: number }[]
  tags: string[]
}

interface Recommendation {
  cwe_id: string
  severity: string
  count: number
  last_seen: string
}

const PAGE_SIZE = 12

export default function KnowledgeBase() {
  const navigate = useNavigate()
  const [articles, setArticles] = useState<Article[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const [sort, setSort] = useState('updated_at')
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [meta, setMeta] = useState<Meta>({ categories: [], tags: [] })
  const [popular, setPopular] = useState<Article[]>([])
  const [recent, setRecent] = useState<Article[]>([])
  const [recommendations, setRecommendations] = useState<Recommendation[]>([])
  const [importing, setImporting] = useState(false)
  const [importMsg, setImportMsg] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)
  const currentUser = (() => { try { return JSON.parse(localStorage.getItem('sentinel_user') || 'null') } catch { return null } })()
  const isAdmin = currentUser?.role === 'admin'

  useEffect(() => {
    loadMeta()
    loadPopular()
    loadRecent()
    loadRecommendations()
  }, [])

  useEffect(() => {
    setPage(1)
    loadArticles()
  }, [search, category, sort])

  useEffect(() => { loadArticles() }, [page])

  const loadMeta = async () => {
    try {
      const res = await api.get('/knowledge-base/meta')
      setMeta(res.data)
    } catch { /* ignore */ }
  }

  const loadArticles = async () => {
    setLoading(true)
    try {
      const params: Record<string, string | number> = { page, per_page: PAGE_SIZE, sort, order: 'desc' }
      if (search) params.search = search
      if (category) params.category = category
      const res = await api.get('/knowledge-base', { params })
      setArticles(res.data.items)
      setTotal(res.data.total)
    } catch { /* ignore */ }
    setLoading(false)
  }

  const loadPopular = async () => {
    try {
      const res = await api.get('/knowledge-base/popular')
      setPopular(res.data)
    } catch { /* ignore */ }
  }

  const loadRecent = async () => {
    try {
      const res = await api.get('/knowledge-base/recent')
      setRecent(res.data)
    } catch { /* ignore */ }
  }

  const loadRecommendations = async () => {
    try {
      const res = await api.get('/knowledge-base/recommendations', { params: { days: 30 } })
      setRecommendations(res.data.recommendations || [])
    } catch { /* ignore */ }
  }

  const handleExport = async (format: 'json' | 'csv') => {
    try {
      const token = localStorage.getItem('sentinel_token')
      const res = await fetch(`/api/knowledge-base/export?format=${format}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!res.ok) {
        setImportMsg(`导出失败（${res.status}）`)
        return
      }
      const blob = await res.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const cd = res.headers.get('content-disposition') || ''
      const m = cd.match(/filename=([^;]+)/)
      a.download = m ? m[1].replace(/['"]/g, '') : `knowledge-base-export.${format}`
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.URL.revokeObjectURL(url)
    } catch (err: any) {
      setImportMsg(`导出失败：${err?.message || '网络错误'}`)
    }
  }

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setImporting(true)
    setImportMsg('')
    try {
      const token = localStorage.getItem('sentinel_token')
      const formData = new FormData()
      formData.append('file', file)
      const res = await fetch('/api/knowledge-base/import', {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: formData,
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setImportMsg(`导入失败（${res.status}）：${data?.message || '服务器错误'}`)
      } else {
        setImportMsg(`导入完成：新增 ${data?.imported ?? 0}，跳过 ${data?.skipped ?? 0}，失败 ${data?.errors ?? 0}`)
        loadArticles()
        loadMeta()
      }
    } catch (err: any) {
      setImportMsg(`导入失败：${err?.message || '网络错误'}`)
    } finally {
      setImporting(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const handleSearchKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') loadArticles()
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">知识库</h1>
          <p className="page-subtitle">安全知识沉淀与复用，从漏洞修复指南到最佳实践</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => handleExport('json')} title="导出为 JSON" className="px-2.5 py-1.5 rounded-lg text-xs font-medium border border-slate-700/50 text-slate-300 hover:text-primary-300 hover:border-primary-500/30 transition-colors bg-surface-800/40 flex items-center gap-1">
            <Download size={14} /> JSON
          </button>
          <button onClick={() => handleExport('csv')} title="导出为 CSV" className="px-2.5 py-1.5 rounded-lg text-xs font-medium border border-slate-700/50 text-slate-300 hover:text-primary-300 hover:border-primary-500/30 transition-colors bg-surface-800/40 flex items-center gap-1">
            <Download size={14} /> CSV
          </button>
          {isAdmin && (
            <button onClick={() => fileInputRef.current?.click()} disabled={importing} title="导入文章（仅管理员）" className="px-2.5 py-1.5 rounded-lg text-xs font-medium border border-slate-700/50 text-slate-300 hover:text-primary-300 hover:border-primary-500/30 transition-colors bg-surface-800/40 flex items-center gap-1 disabled:opacity-50">
              <Upload size={14} /> {importing ? '导入中…' : '导入'}
            </button>
          )}
          <button onClick={() => navigate('/knowledge-base/new')} className="btn-primary text-xs flex items-center gap-1">
            <Plus size={14} />
            写文章
          </button>
          <input ref={fileInputRef} type="file" accept=".json,.csv" className="hidden" onChange={handleImportFile} />
        </div>
      </div>

      {importMsg && (
        <div className={`text-xs px-3 py-2 rounded-lg border ${importMsg.includes('失败') ? 'border-red-500/30 text-red-400 bg-red-500/5' : 'border-emerald-500/30 text-emerald-400 bg-emerald-500/5'}`}>
          {importMsg}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* ── Sidebar ── */}
        <aside className="lg:col-span-1 space-y-5">
          {/* Search */}
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              onKeyDown={handleSearchKeyDown}
              placeholder="搜索文章..."
              className="w-full bg-surface-800/60 border border-slate-700/50 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-slate-500 focus:border-primary-500/50 focus:outline-none transition-colors"
            />
          </div>

          {/* Categories */}
          <div className="bg-surface-800/30 border border-slate-700/40 rounded-xl p-4">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Folder size={13} /> 分类
            </h3>
            <div className="space-y-0.5">
              <button
                onClick={() => setCategory('')}
                className={`w-full text-left px-3 py-1.5 rounded-lg text-xs transition-colors ${!category ? 'bg-primary-500/10 text-primary-300 font-medium' : 'text-slate-400 hover:text-slate-200 hover:bg-surface-800/50'}`}
              >
                全部 ({total})
              </button>
              {meta.categories.map(c => (
                <button
                  key={c.key}
                  onClick={() => setCategory(c.key)}
                  className={`w-full text-left px-3 py-1.5 rounded-lg text-xs transition-colors flex items-center justify-between ${category === c.key ? 'bg-primary-500/10 text-primary-300 font-medium' : 'text-slate-400 hover:text-slate-200 hover:bg-surface-800/50'}`}
                >
                  <span>{c.label}</span>
                  <span className="text-[10px] opacity-60">{c.count}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Tags */}
          {Array.isArray(meta.tags) && meta.tags.length > 0 && (
            <div className="bg-surface-800/30 border border-slate-700/40 rounded-xl p-4">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Tag size={13} /> 标签
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {meta.tags.map(t => (
                  <button
                    key={t}
                    onClick={() => { setSearch(t); setCategory('') }}
                    className="px-2 py-1 rounded-md text-[10px] bg-surface-800 border border-slate-700/40 text-slate-400 hover:text-primary-300 hover:border-primary-500/30 transition-colors"
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Popular */}
          {popular.length > 0 && (
            <div className="bg-surface-800/30 border border-slate-700/40 rounded-xl p-4">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <TrendingUp size={13} /> 热门文章
              </h3>
              <div className="space-y-2">
                {popular.slice(0, 5).map((a, idx) => (
                  <button
                    key={a.id}
                    onClick={() => navigate(`/knowledge-base/${a.id}`)}
                    className="w-full text-left group"
                  >
                    <div className="flex items-start gap-2">
                      <span className="text-[10px] font-bold text-slate-600 mt-0.5 w-4 shrink-0">{idx + 1}</span>
                      <div className="min-w-0">
                        <p className="text-xs text-slate-300 group-hover:text-primary-300 truncate transition-colors">{a.title}</p>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-[10px] text-slate-500">{a.category_label}</span>
                          <span className="text-[10px] text-slate-600 flex items-center gap-0.5"><Eye size={10} />{a.view_count}</span>
                        </div>
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Recent */}
          {recent.length > 0 && (
            <div className="bg-surface-800/30 border border-slate-700/40 rounded-xl p-4">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Clock size={13} /> 最新发布
              </h3>
              <div className="space-y-2">
                {recent.slice(0, 5).map(a => (
                  <button
                    key={a.id}
                    onClick={() => navigate(`/knowledge-base/${a.id}`)}
                    className="w-full text-left"
                  >
                    <p className="text-xs text-slate-300 hover:text-primary-300 truncate transition-colors">{a.title}</p>
                    <p className="text-[10px] text-slate-500 mt-0.5">{a.created_at?.slice(0, 10)}</p>
                  </button>
                ))}
              </div>
            </div>
          )}
        </aside>

        {/* ── Main content ── */}
        <div className="lg:col-span-3 space-y-4">
          {/* Sort */}
          <div className="flex items-center gap-3">
            {['updated_at', 'view_count', 'created_at'].map(s => (
              <button
                key={s}
                onClick={() => setSort(s)}
                className={`px-3 py-1.5 rounded-lg text-xs transition-colors ${sort === s ? 'bg-primary-500/10 text-primary-300 border border-primary-500/20' : 'text-slate-400 hover:text-slate-200 border border-transparent'}`}
              >
                {s === 'updated_at' ? '最近更新' : s === 'view_count' ? '最多浏览' : '最新发布'}
              </button>
            ))}
            <span className="text-xs text-slate-500 ml-auto">{total} 篇文章</span>
          </div>

          {/* Writing Recommendations */}
          {recommendations.length > 0 && (
            <div className="bg-amber-500/5 border border-amber-500/15 rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-medium text-amber-400">
                <Lightbulb size={13} />
                推荐撰写 — 以下漏洞类型高频出现但知识库尚未覆盖
              </div>
              <div className="flex flex-wrap gap-2">
                {recommendations.slice(0, 4).map(r => {
                  const sevColors: Record<string, string> = {
                    CRITICAL: 'border-red-500/30 text-red-400 bg-red-500/5',
                    HIGH: 'border-orange-500/30 text-orange-400 bg-orange-500/5',
                    MEDIUM: 'border-yellow-500/30 text-yellow-400 bg-yellow-500/5',
                    LOW: 'border-blue-500/30 text-blue-400 bg-blue-500/5',
                  }
                  return (
                    <button
                      key={r.cwe_id}
                      onClick={() => navigate(`/knowledge-base/new?category=web_security&cwe=${r.cwe_id}`)}
                      className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] border transition-colors hover:border-amber-500/40 ${sevColors[r.severity] || 'border-slate-500/30 text-slate-400 bg-slate-500/5'}`}
                    >
                      <AlertTriangle size={10} />
                      {r.cwe_id} ({r.count}次)
                      <ArrowRight size={10} />
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          {/* Article grid */}
          {loading ? (
            <div className="text-center py-16 text-slate-500">加载中...</div>
          ) : articles.length === 0 ? (
            <div className="text-center py-16">
              <BookOpen size={40} className="mx-auto mb-3 text-slate-600" />
              <p className="text-sm text-slate-500">暂无文章</p>
              <p className="text-xs text-slate-600 mt-1">搜索范围太窄，或尝试其他分类</p>
            </div>
          ) : (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {articles.map(a => (
                  <button
                    key={a.id}
                    onClick={() => navigate(`/knowledge-base/${a.id}`)}
                    className="text-left bg-surface-800/30 border border-slate-700/40 rounded-xl p-5 hover:border-primary-500/20 hover:bg-surface-800/50 transition-all group"
                  >
                    {/* Category badge */}
                    <span className="inline-block px-2 py-0.5 rounded-md text-[10px] font-medium bg-primary-500/10 text-primary-300 border border-primary-500/15 mb-3">
                      {a.category_label}
                    </span>

                    <h3 className="text-sm font-semibold text-white group-hover:text-primary-300 transition-colors mb-2 line-clamp-2">
                      {a.title}
                    </h3>

                    {a.summary && (
                      <p className="text-xs text-slate-400 leading-relaxed line-clamp-2 mb-3">{a.summary}</p>
                    )}

                    {/* Tags */}
                    {Array.isArray(a.tags) && a.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mb-3">
                        {a.tags.slice(0, 4).map(t => (
                          <span key={String(t)} className="px-1.5 py-0.5 rounded text-[10px] bg-surface-700/50 text-slate-500 border border-slate-700/30">
                            {t}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Meta */}
                    <div className="flex items-center gap-3 text-[10px] text-slate-500">
                      {a.author_name && <span>{a.author_name}</span>}
                      <span className="flex items-center gap-1"><Eye size={10} />{a.view_count}</span>
                      <span>{a.updated_at?.slice(0, 10)}</span>
                    </div>
                  </button>
                ))}
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between pt-3 text-xs text-slate-400">
                  <span>共 {total} 篇</span>
                  <div className="flex items-center gap-1">
                    <button disabled={page <= 1} onClick={() => setPage(page - 1)}
                      className="px-2 py-1 rounded bg-surface-800 border border-slate-700 disabled:opacity-30 hover:border-slate-600">
                      上一页
                    </button>
                    {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                      const start = Math.max(1, Math.min(page - 3, totalPages - 6))
                      const p = start + i
                      if (p > totalPages) return null
                      return (
                        <button key={p} onClick={() => setPage(p)}
                          className={`px-2.5 py-1 rounded text-xs ${p === page
                            ? 'bg-primary-600 text-white' : 'bg-surface-800 border border-slate-700 hover:border-slate-600'}`}>
                          {p}
                        </button>
                      )
                    })}
                    <button disabled={page >= totalPages} onClick={() => setPage(page + 1)}
                      className="px-2 py-1 rounded bg-surface-800 border border-slate-700 disabled:opacity-30 hover:border-slate-600">
                      下一页
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
