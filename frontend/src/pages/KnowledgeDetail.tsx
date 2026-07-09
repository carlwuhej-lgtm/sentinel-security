import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import api from '../api/client'
import MarkdownRenderer from '../components/MarkdownRenderer'
import { ArrowLeft, Eye, Clock, Tag, Folder, Edit3, Trash2, ShieldAlert } from 'lucide-react'

interface Article {
  id: number
  title: string
  content: string
  category: string
  category_label: string
  tags: string[]
  author_name: string
  view_count: number
  summary: string
  created_at: string
  updated_at: string
}

interface RelatedArticle {
  id: number
  title: string
  category_label: string
  summary: string
}

// Search params for related vulns
function useQuery() {
  return new URLSearchParams(window.location.search)
}

export default function KnowledgeDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const query = useQuery()
  const [article, setArticle] = useState<Article | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [related, setRelated] = useState<RelatedArticle[]>([])

  // If came from a vulnerability page, load related articles
  const vulnId = query.get('vuln')

  useEffect(() => {
    loadArticle()
  }, [id])

  useEffect(() => {
    if (vulnId) {
      loadRelated()
    }
  }, [vulnId])

  const loadArticle = async () => {
    setLoading(true)
    try {
      const res = await api.get(`/knowledge-base/${id}`)
      setArticle(res.data)
      setError('')
    } catch (e: any) {
      setError(e?.response?.data?.error || '加载失败')
    }
    setLoading(false)
  }

  const loadRelated = async () => {
    try {
      const res = await api.get(`/knowledge-base/related/${vulnId}`)
      setRelated(res.data.filter((a: RelatedArticle) => a.id !== Number(id)))
    } catch { /* ignore */ }
  }

  const handleDelete = async () => {
    if (!confirm('确定删除这篇文章？')) return
    try {
      await api.delete(`/knowledge-base/${id}`)
      navigate('/knowledge-base')
    } catch { /* ignore */ }
  }

  const currentUser = (() => {
    try {
      const raw = localStorage.getItem('sentinel_user')
      return raw ? JSON.parse(raw) : null
    } catch { return null }
  })()

  const canEdit = currentUser?.role === 'admin' || currentUser?.role === 'security_analyst'

  if (loading) return (
    <div className="max-w-4xl mx-auto text-center py-16 text-slate-500">加载中...</div>
  )

  if (error || !article) return (
    <div className="max-w-4xl mx-auto text-center py-16">
      <ShieldAlert size={48} className="mx-auto mb-4 text-slate-600" />
      <p className="text-slate-400">{error || '文章不存在'}</p>
      <button onClick={() => navigate('/knowledge-base')} className="mt-4 text-sm text-primary-400 hover:underline">返回知识库</button>
    </div>
  )

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Back + Actions */}
      <div className="flex items-center justify-between">
        <button onClick={() => navigate('/knowledge-base')} className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-white transition-colors">
          <ArrowLeft size={16} />
          返回知识库
        </button>
        {canEdit && (
          <div className="flex items-center gap-2">
            <button onClick={() => navigate(`/knowledge-base/${id}/edit`)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-300 bg-surface-800 border border-slate-700 hover:border-primary-500/30 hover:text-primary-300 transition-colors">
              <Edit3 size={13} /> 编辑
            </button>
            <button onClick={handleDelete} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-red-400 bg-red-500/5 border border-red-500/15 hover:bg-red-500/10 transition-colors">
              <Trash2 size={13} /> 删除
            </button>
          </div>
        )}
      </div>

      {/* Article header */}
      <div>
        {/* Category badge */}
        <div className="flex items-center gap-3 mb-3">
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-medium bg-primary-500/10 text-primary-300 border border-primary-500/15">
            <Folder size={12} /> {article.category_label}
          </span>
        </div>

        <h1 className="text-xl font-bold text-white mb-3">{article.title}</h1>

        {article.summary && (
          <p className="text-sm text-slate-400 leading-relaxed mb-4">{article.summary}</p>
        )}

        {/* Tags */}
        {Array.isArray(article.tags) && article.tags.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-4">
            {article.tags.map(t => (
              <span key={String(t)} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] text-slate-400 bg-surface-800 border border-slate-700/30">
                <Tag size={10} /> {t}
              </span>
            ))}
          </div>
        )}

        {/* Meta */}
        <div className="flex items-center gap-4 text-xs text-slate-500 pb-5 border-b border-slate-700/40">
          {article.author_name && <span>作者: {article.author_name}</span>}
          <span className="flex items-center gap-1"><Eye size={12} /> {article.view_count} 次浏览</span>
          <span className="flex items-center gap-1"><Clock size={12} /> 更新于 {article.updated_at?.slice(0, 16)}</span>
        </div>
      </div>

      {/* Content */}
      <div className="bg-surface-800/20 border border-slate-700/30 rounded-xl p-6">
        <MarkdownRenderer content={article.content} />
      </div>

      {/* Related articles (when coming from vulnerability) */}
      {related.length > 0 && (
        <div className="bg-surface-800/30 border border-slate-700/40 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
            <ShieldAlert size={14} className="text-primary-400" />
            相关文章
          </h3>
          <div className="space-y-2">
            {related.map(a => (
              <button
                key={a.id}
                onClick={() => navigate(`/knowledge-base/${a.id}${vulnId ? `?vuln=${vulnId}` : ''}`)}
                className="w-full text-left p-3 rounded-lg bg-surface-800/50 border border-slate-700/30 hover:border-primary-500/20 transition-colors group"
              >
                <p className="text-sm text-slate-200 group-hover:text-primary-300 transition-colors">{a.title}</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-[10px] text-slate-500">{a.category_label}</span>
                  {a.summary && <span className="text-[10px] text-slate-600 truncate">— {a.summary.slice(0, 60)}</span>}
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Footer */}
      <div className="text-center pb-8 pt-4">
        <p className="text-xs text-slate-600">
          创建于 {article.created_at?.slice(0, 10)} · 最后更新于 {article.updated_at?.slice(0, 10)}
        </p>
      </div>
    </div>
  )
}
