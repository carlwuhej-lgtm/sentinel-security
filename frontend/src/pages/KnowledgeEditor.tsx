import { useState, useEffect } from 'react'
import { useParams, useNavigate, useSearchParams } from 'react-router-dom'
import api from '../api/client'
import { ArrowLeft, Save, Eye, Folder, AlertTriangle } from 'lucide-react'

const CATEGORIES: Record<string, string> = {
  web_security: 'Web 安全',
  supply_chain: '供应链安全',
  data_security: '数据安全',
  ops_process: '运维与流程',
  tool_guide: '工具指南',
  incident_case: '事件案例',
  compliance: '合规与标准',
  general: '综合',
}

export default function KnowledgeEditor() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const isEdit = Boolean(id)

  // 从 URL 参数预填分类和标题
  const presetCategory = searchParams.get('category') || ''
  const presetCwe = searchParams.get('cwe') || ''
  const presetToolType = searchParams.get('from_tool_type') || ''

  // 工具类型 → 知识库分类映射
  const TOOL_TO_CATEGORY: Record<string, string> = {
    'SAST': 'web_security',
    'DAST': 'web_security',
    'SCA': 'supply_chain',
    'SECRET': 'web_security',
    'IAST': 'web_security',
    'FUZZ': 'web_security',
    'CONTAINER': 'ops_process',
  }

  // 确定初始分类：工具类型映射 > URL category 参数 > 默认 general
  const initialCategory = (presetToolType && TOOL_TO_CATEGORY[presetToolType]) 
    || presetCategory 
    || 'general'

  const [form, setForm] = useState({
    title: presetCwe ? `${presetCwe} 漏洞修复指南` : '',
    content: '',
    category: initialCategory,
    tags: [] as string[],
    summary: '',
    is_published: true,
  })
  const [tagInput, setTagInput] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [loadingArticle, setLoadingArticle] = useState(isEdit)
  const [preview, setPreview] = useState(false)
  const [vulnStats, setVulnStats] = useState<{
    total: number
    by_severity: Record<string, number>
    by_tool: Record<string, number>
    top_cwe: { cwe_id: string; count: number }[]
  } | null>(null)

  // 加载关联漏洞统计（按 category 过滤）
  useEffect(() => {
    loadVulnStats()
  }, [form.category])

  const loadVulnStats = async () => {
    try {
      // 用 title 和 category 关键词查询
      const keywords = [form.title, CATEGORIES[form.category] || ''].filter(Boolean).join(',')
      const res = await api.get('/knowledge-base/vuln-stats', {
        params: { keywords, category: form.category },
      })
      setVulnStats(res.data)
    } catch {
      setVulnStats(null)
    }
  }

  useEffect(() => {
    if (isEdit && id) {
      loadArticle(Number(id))
    }
  }, [id])

  const loadArticle = async (aid: number) => {
    try {
      const res = await api.get(`/knowledge-base/${aid}`)
      const a = res.data
      setForm({
        title: a.title || '',
        content: a.content || '',
        category: a.category || 'general',
        tags: Array.isArray(a.tags) ? a.tags : [],
        summary: a.summary || '',
        is_published: a.is_published !== 0,
      })
    } catch (e: any) {
      setError(e?.response?.data?.error || '加载失败')
    }
    setLoadingArticle(false)
  }

  const addTag = () => {
    const t = tagInput.trim().toLowerCase()
    if (t && !form.tags.includes(t)) {
      setForm({ ...form, tags: [...form.tags, t] })
    }
    setTagInput('')
  }

  const removeTag = (t: string) => {
    setForm({ ...form, tags: form.tags.filter(x => x !== t) })
  }

  const handleTagKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      addTag()
    }
  }

  const handleSave = async () => {
    if (!form.title.trim()) {
      setError('标题不能为空')
      return
    }
    setError('')
    setSaving(true)
    try {
      const payload = { ...form, title: form.title.trim() }
      if (isEdit) {
        await api.put(`/knowledge-base/${id}`, payload)
      } else {
        const res = await api.post('/knowledge-base', payload)
        navigate(`/knowledge-base/${res.data.id}`, { replace: true })
        return
      }
      navigate(`/knowledge-base/${id}`)
    } catch (e: any) {
      setError(e?.response?.data?.error || '保存失败')
    }
    setSaving(false)
  }

  if (loadingArticle) return (
    <div className="max-w-3xl mx-auto text-center py-16 text-slate-500">加载文章中...</div>
  )

  return (
    <div className="max-w-3xl mx-auto space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <button onClick={() => navigate(isEdit ? `/knowledge-base/${id}` : '/knowledge-base')} className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-white transition-colors">
          <ArrowLeft size={16} />
          {isEdit ? '取消编辑' : '返回知识库'}
        </button>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPreview(!preview)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-colors ${preview ? 'bg-primary-500/10 text-primary-300 border border-primary-500/20' : 'text-slate-400 border border-slate-700 hover:text-slate-200'}`}
          >
            <Eye size={13} /> {preview ? '编辑' : '预览'}
          </button>
          <button onClick={handleSave} disabled={saving || !form.title.trim()} className="flex items-center gap-1.5 btn-primary text-xs">
            <Save size={13} /> {saving ? '保存中...' : '保存'}
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-2.5 text-sm text-red-400">{error}</div>
      )}

      {preview ? (
        /* ── Preview mode ── */
        <div className="bg-surface-800/30 border border-slate-700/40 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-700/40">
            <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-primary-500/10 text-primary-300 border border-primary-500/15">
              {CATEGORIES[form.category] || form.category}
            </span>
            <div className="flex gap-1">
              {form.tags.map(t => (
                <span key={t} className="px-1.5 py-0.5 rounded text-[10px] bg-surface-700/50 text-slate-500">{t}</span>
              ))}
            </div>
          </div>
          <h1 className="text-lg font-bold text-white">{form.title || '无标题'}</h1>
          {form.summary && <p className="text-sm text-slate-400">{form.summary}</p>}
          <div className="pt-3 border-t border-slate-700/40">
            <pre className="text-xs text-slate-300 whitespace-pre-wrap font-sans leading-relaxed">{form.content || '(无内容)'}</pre>
          </div>
        </div>
      ) : (
        /* ── Edit mode ── */
        <div className="space-y-4">
          {/* Title */}
          <div>
            <input
              value={form.title}
              onChange={e => setForm({ ...form, title: e.target.value })}
              placeholder="文章标题"
              className="w-full bg-transparent text-xl font-bold text-white placeholder-slate-600 focus:outline-none"
              autoFocus
            />
          </div>

          {/* Category & Publish */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Folder size={14} className="text-slate-500" />
              <select
                value={form.category}
                onChange={e => setForm({ ...form, category: e.target.value })}
                className="bg-surface-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:border-primary-500/50 focus:outline-none"
              >
                {Object.entries(CATEGORIES).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </div>
            <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
              <input
                type="checkbox"
                checked={form.is_published}
                onChange={e => setForm({ ...form, is_published: e.target.checked })}
                className="rounded border-slate-600"
              />
              发布
            </label>
          </div>

          {/* Vuln Stats Panel */}
          {vulnStats && vulnStats.total > 0 && (
            <div className="bg-surface-800/40 border border-white/[0.06] rounded-xl p-3.5 space-y-2">
              <div className="flex items-center gap-2 text-xs font-medium text-slate-400">
                <AlertTriangle size={12} className="text-yellow-400" />
                系统中存在 <span className="text-yellow-400 font-bold">{vulnStats.total}</span> 个待处理的相关漏洞
              </div>
              <div className="flex flex-wrap gap-2">
                {Object.entries(vulnStats.by_severity).filter(([, c]) => c > 0).map(([sev, count]) => {
                  const color: Record<string, string> = {
                    critical: 'bg-red-500/10 text-red-400 border-red-500/20',
                    high: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
                    medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
                    low: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
                  }
                  return (
                    <span key={sev} className={`text-[10px] px-2 py-0.5 rounded-md border ${color[sev] || 'bg-slate-500/10 text-slate-400 border-slate-500/20'}`}>
                      {sev.toUpperCase()}: {count}
                    </span>
                  )
                })}
              </div>
              {vulnStats.top_cwe.length > 0 && (
                <div className="text-[10px] text-slate-500">
                  Top CWE: {vulnStats.top_cwe.slice(0, 3).map(c => `${c.cwe_id}(${c.count})`).join(', ')}
                </div>
              )}
            </div>
          )}

          {/* Summary */}
          <div>
            <input
              value={form.summary}
              onChange={e => setForm({ ...form, summary: e.target.value })}
              placeholder="摘要（可选，留空自动生成）"
              className="w-full bg-surface-800/40 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-slate-300 placeholder-slate-600 focus:border-primary-500/50 focus:outline-none"
            />
          </div>

          {/* Tags */}
          <div>
            <div className="flex items-center gap-2 mb-2">
              <input
                value={tagInput}
                onChange={e => setTagInput(e.target.value)}
                onKeyDown={handleTagKeyDown}
                placeholder="添加标签（回车确认）"
                className="flex-1 bg-surface-800/40 border border-slate-700/50 rounded-lg px-3 py-1.5 text-xs text-slate-300 placeholder-slate-600 focus:border-primary-500/50 focus:outline-none"
              />
              <button onClick={addTag} className="px-3 py-1.5 rounded-lg text-xs text-slate-400 bg-surface-800 border border-slate-700 hover:border-primary-500/30 hover:text-primary-300 transition-colors">
                添加
              </button>
            </div>
            {form.tags.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {form.tags.map(t => (
                  <span key={t} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] bg-primary-500/10 text-primary-300 border border-primary-500/15">
                    {t}
                    <button onClick={() => removeTag(t)} className="hover:text-red-400 ml-0.5">&times;</button>
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Content */}
          <div>
            <textarea
              value={form.content}
              onChange={e => setForm({ ...form, content: e.target.value })}
              placeholder="正文（支持 Markdown 格式）&#10;&#10;## 标题&#10;- 列表项&#10;```python&#10;代码块&#10;```"
              rows={20}
              className="w-full bg-surface-800/40 border border-slate-700/50 rounded-xl px-4 py-3 text-sm text-slate-200 placeholder-slate-600 focus:border-primary-500/50 focus:outline-none resize-y font-mono leading-relaxed"
            />
          </div>
        </div>
      )}

      {/* Bottom actions */}
      <div className="flex justify-end gap-3 pt-2 pb-8">
        <button
          onClick={() => navigate(isEdit ? `/knowledge-base/${id}` : '/knowledge-base')}
          className="px-4 py-2 text-sm text-slate-400 hover:text-white transition-colors"
        >
          取消
        </button>
        <button onClick={handleSave} disabled={saving || !form.title.trim()} className="btn-primary text-sm">
          <Save size={14} /> {saving ? '保存中...' : '保存文章'}
        </button>
      </div>
    </div>
  )
}
