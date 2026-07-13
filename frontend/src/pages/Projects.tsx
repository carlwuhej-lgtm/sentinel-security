import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'

interface Project {
  id: number
  name: string
  repo_url: string
  target_url: string
  local_path: string
  language: string
  project_type: string
  description: string
  created_at: string
}

interface ProjectForm {
  name: string
  repo_url: string
  target_url: string
  local_path: string
  language: string
  project_type: string
  description: string
}

const emptyForm: ProjectForm = {
  name: '',
  repo_url: '',
  target_url: '',
  local_path: '',
  language: 'python',
  project_type: 'web',
  description: '',
}

const languageOptions = ['python', 'javascript', 'java', 'go', 'php', 'ruby', '其他']

const langLabel = (lang: string) => {
  const map: Record<string, string> = {
    python: 'Python',
    javascript: 'JavaScript',
    java: 'Java',
    go: 'Go',
    php: 'PHP',
    ruby: 'Ruby',
  }
  return map[lang.toLowerCase()] || lang
}

const langColor = (lang: string) => {
  const map: Record<string, string> = {
    python: 'bg-blue-500/20 text-blue-400',
    javascript: 'bg-yellow-500/20 text-yellow-400',
    java: 'bg-red-500/20 text-red-400',
    go: 'bg-cyan-500/20 text-cyan-400',
    php: 'bg-indigo-500/20 text-indigo-400',
    ruby: 'bg-red-600/20 text-red-300',
  }
  return map[lang.toLowerCase()] || 'bg-slate-500/20 text-slate-400'
}

const projectTypeOptions = [
  { value: 'web', label: 'Web' },
  { value: 'api', label: 'API' },
  { value: 'mobile', label: 'Mobile' },
  { value: 'infra', label: 'Infra' },
  { value: 'other', label: '其他' },
]

const typeLabel: Record<string, string> = {
  web: 'Web',
  api: 'API',
  mobile: '移动端',
  infra: '基础设施',
  other: '其他',
}

const typeBadgeClass = (type: string) => {
  const colors: Record<string, string> = {
    web: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    api: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
    mobile: 'bg-green-500/10 text-green-400 border-green-500/20',
    infra: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  }
  return `inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold border transition-colors ${colors[type] || 'bg-slate-500/10 text-slate-400 border-slate-500/20'}`
}

const PAGE_SIZE = 12

// 生成带省略号的页码窗口
function getPageWindow(current: number, total: number): (number | string)[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1)
  const pages: (number | string)[] = [1]
  const start = Math.max(2, current - 1)
  const end = Math.min(total - 1, current + 1)
  if (start > 2) pages.push('...')
  for (let p = start; p <= end; p++) pages.push(p)
  if (end < total - 1) pages.push('...')
  pages.push(total)
  return pages
}

export default function Projects() {
  const navigate = useNavigate()
  const [projects, setProjects] = useState<Project[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [formData, setFormData] = useState<ProjectForm>(emptyForm)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [deleteConfirmId, setDeleteConfirmId] = useState<number | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [totalPages, setTotalPages] = useState(1)

  useEffect(() => { loadProjects() }, [page])

  const loadProjects = async () => {
    setLoading(true)
    try {
      const res = await api.get('/projects', { params: { page, per_page: PAGE_SIZE } })
      setProjects(res.data?.items || [])
      setTotal(res.data?.total ?? (res.data?.items?.length || 0))
      setTotalPages(Math.max(1, res.data?.pages ?? 1))
    } catch {
      setProjects([])
    } finally {
      setLoading(false)
    }
  }

  const openCreateModal = () => {
    setEditingId(null)
    setFormData(emptyForm)
    setShowModal(true)
  }

  const openEditModal = (project: Project) => {
    setEditingId(project.id)
    setFormData({
      name: project.name,
      repo_url: project.repo_url || '',
      target_url: project.target_url || '',
      local_path: project.local_path || '',
      language: project.language || 'python',
      project_type: project.project_type || 'web',
      description: project.description || '',
    })
    setShowModal(true)
  }

  const closeModal = () => {
    setShowModal(false)
    setEditingId(null)
  }

  const handleSubmit = async () => {
    if (!formData.name.trim()) return

    // URL 自动规范化：逐行修复缺少 // 的 URL（支持多个目标，每行一个）
    const targetUrl = formData.target_url
      .split(/[\n\r,;]+/)
      .map((u) => u.trim())
      .filter(Boolean)
      .map((u) => (u.match(/^https?:[^/]/) ? u.replace(/^http(s?):/, 'http$1://') : u))
      .join('\n')
    const submitData = { ...formData, target_url: targetUrl }

    setSubmitting(true)
    try {
      if (editingId) {
        await api.put(`/projects/${editingId}`, submitData)
      } else {
        await api.post('/projects', submitData)
      }
      setShowModal(false)
      setEditingId(null)
      setFormData(emptyForm)
      if (!editingId && page !== 1) {
        setPage(1)  // 新建后跳到第一页（按 created_at DESC 排序，新项目在首页）
      } else {
        await loadProjects()
      }
    } catch {
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (id: number) => {
    try {
      await api.delete(`/projects/${id}`)
      setDeleteConfirmId(null)
      // 删的是当前页最后一条且不在首页时，回退一页
      if (projects.length === 1 && page > 1) {
        setPage(page - 1)
      } else {
        await loadProjects()
      }
    } catch {}
  }

  const formatDate = (dateStr: string) => {
    try {
      return new Date(dateStr).toLocaleDateString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
      })
    } catch {
      return dateStr?.slice(0, 10) || '-'
    }
  }

  return (
    <div className="max-w-7xl mx-auto">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">项目管理</h1>
          <p className="page-subtitle">管理安全扫描项目，配置代码仓库与语言类型</p>
        </div>
        <button onClick={openCreateModal} className="btn-primary text-xs">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
            <path d="M12 5v14M5 12h14"/>
          </svg>
          新建项目
        </button>
      </div>

      {/* Loading Skeleton */}
      {loading && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="card space-y-3">
              <div className="skeleton h-5 w-3/5" />
              <div className="flex gap-2">
                <div className="skeleton h-5 w-16 rounded-md" />
                <div className="skeleton h-5 w-12 rounded-md" />
              </div>
              <div className="skeleton h-4 w-full" />
              <div className="skeleton h-4 w-4/5" />
              <div className="skeleton h-3 w-2/3" />
              <div className="flex gap-2 mt-2">
                <div className="skeleton h-8 w-14 rounded-lg" />
                <div className="skeleton h-8 w-14 rounded-lg" />
                <div className="skeleton h-8 w-14 rounded-lg" />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Empty State */}
      {!loading && projects.length === 0 && (
        <div className="empty-state">
          <div className="empty-state-icon">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
            </svg>
          </div>
          <div className="empty-state-title">还没有项目</div>
          <div className="empty-state-desc mb-6">创建第一个项目来开始安全扫描</div>
          <button onClick={openCreateModal} className="btn-primary text-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
              <path d="M12 5v14M5 12h14"/>
            </svg>
            新建项目
          </button>
        </div>
      )}

      {/* Project Cards Grid */}
      {!loading && projects.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {projects.map((p) => (
            <div key={p.id} className="card-hover flex flex-col">
              {/* Project Name */}
              <h3 className="text-white font-semibold text-base mb-2 truncate">{p.name}</h3>

              {/* Badges */}
              <div className="flex flex-wrap gap-2 mb-3">
                <span className={`text-xs px-2 py-0.5 rounded font-medium ${langColor(p.language)}`}>
                  {langLabel(p.language)}
                </span>
                <span className={typeBadgeClass(p.project_type)}>
                  {typeLabel[p.project_type] || p.project_type || '其他'}
                </span>
              </div>

              {/* Description */}
              <p className="text-slate-400 text-xs leading-relaxed line-clamp-2 min-h-[2.25rem] mb-3">
                {p.description || '暂无描述'}
              </p>

              {/* Repo URL */}
              {p.repo_url && (
                <div className="flex items-center gap-1.5 mb-2">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-slate-500 flex-shrink-0">
                    <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/>
                    <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/>
                  </svg>
                  <span className="text-xs text-slate-500 truncate">SAST: {p.repo_url}</span>
                </div>
              )}

              {/* Target URL (DAST) */}
              {p.target_url && (
                <div className="flex items-center gap-1.5 mb-2">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="text-orange-500 flex-shrink-0">
                    <circle cx="12" cy="12" r="10"/>
                    <path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>
                  </svg>
                  <span className="text-xs text-orange-400 truncate">
                    {(() => {
                      const urls = p.target_url.split(/[\n\r,;]+/).map((u) => u.trim()).filter(Boolean)
                      return urls.length > 1 ? `DAST: ${urls.length} 个目标` : `DAST: ${urls[0] || p.target_url}`
                    })()}
                  </span>
                </div>
              )}

              {/* Local Path (SAST) */}
              {p.local_path && (
                <div className="flex items-center gap-1.5 mb-2">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="text-green-500 flex-shrink-0">
                    <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
                  </svg>
                  <span className="text-xs text-green-400 truncate">本地: {p.local_path}</span>
                </div>
              )}

              {/* Created Date */}
              <div className="text-xs text-slate-600 mb-4 mt-auto pt-1">
                {formatDate(p.created_at)}
              </div>

              {/* Action Buttons */}
              <div className="flex gap-2">
                <button
                  onClick={() => navigate(`/scans?project_id=${p.id}`)}
                  className="btn-primary btn-sm flex-1"
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                  </svg>
                  扫描
                </button>
                <button
                  onClick={() => openEditModal(p)}
                  className="btn-secondary btn-sm"
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
                    <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
                  </svg>
                  编辑
                </button>
                <button
                  onClick={() => setDeleteConfirmId(p.id)}
                  className="btn-danger btn-sm"
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                  </svg>
                  删除
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Pagination */}
      {!loading && total > PAGE_SIZE && (
        <div className="flex items-center justify-between pt-5 text-xs text-slate-400">
          <span>共 {total} 个项目 · 第 {page} / {totalPages} 页</span>
          <div className="flex items-center gap-1">
            <button disabled={page <= 1} onClick={() => setPage(page - 1)}
              className="px-2 py-1 rounded bg-surface-800 border border-slate-700 disabled:opacity-30 hover:border-slate-600">
              上一页
            </button>
            {getPageWindow(page, totalPages).map((p, i) =>
              p === '...' ? (
                <span key={`e${i}`} className="px-1.5 text-slate-600">…</span>
              ) : (
                <button key={p} onClick={() => setPage(p as number)}
                  className={`px-2.5 py-1 rounded text-xs ${p === page
                    ? 'bg-primary-600 text-white' : 'bg-surface-800 border border-slate-700 hover:border-slate-600'}`}>
                  {p}
                </button>
              )
            )}
            <button disabled={page >= totalPages} onClick={() => setPage(page + 1)}
              className="px-2 py-1 rounded bg-surface-800 border border-slate-700 disabled:opacity-30 hover:border-slate-600">
              下一页
            </button>
          </div>
        </div>
      )}

      {/* Create / Edit Modal */}
      {showModal && (
        <div className="modal-overlay" onClick={closeModal}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="text-lg font-semibold text-white">
                {editingId ? '编辑项目' : '新建项目'}
              </h2>
              <button
                onClick={closeModal}
                className="text-slate-500 hover:text-slate-300 transition-colors p-0.5"
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                  <path d="M18 6L6 18M6 6l12 12"/>
                </svg>
              </button>
            </div>

            <div className="modal-body space-y-4">
              <div className="input-group">
                <label className="input-label">项目名称 *</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="输入项目名称"
                  className="input"
                />
              </div>

              <div className="input-group">
                <label className="input-label">仓库地址</label>
                <input
                  type="text"
                  value={formData.repo_url}
                  onChange={(e) => setFormData({ ...formData, repo_url: e.target.value })}
                  placeholder="https://github.com/... (SAST 扫描用)"
                  className="input"
                />
              </div>

              <div className="input-group">
                <label className="input-label">目标 URL (DAST 扫描)</label>
                <textarea
                  value={formData.target_url}
                  onChange={(e) => setFormData({ ...formData, target_url: e.target.value })}
                  placeholder={"https://example.com\nhttps://api.example.com\n（支持多个：每行一个 URL，DAST 会逐个扫描）"}
                  rows={4}
                  className="input"
                  style={{ resize: 'vertical', fontFamily: 'inherit' }}
                />
                <span className="text-xs text-slate-500 mt-1 block">
                  支持批量：一行填一个 URL，DAST 扫描会对每个目标各跑一遍并合并结果
                </span>
              </div>

              <div className="input-group">
                <label className="input-label">本地路径 (SAST 扫描)</label>
                <input
                  type="text"
                  value={formData.local_path}
                  onChange={(e) => setFormData({ ...formData, local_path: e.target.value })}
                  placeholder="/path/to/code (本地 SAST 扫描)"
                  className="input"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="input-group">
                  <label className="input-label">语言</label>
                  <select
                    value={formData.language}
                    onChange={(e) => setFormData({ ...formData, language: e.target.value })}
                    className="select"
                  >
                    {languageOptions.map((opt) => (
                      <option key={opt} value={opt}>
                        {langLabel(opt)}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="input-group">
                  <label className="input-label">项目类型</label>
                  <select
                    value={formData.project_type}
                    onChange={(e) => setFormData({ ...formData, project_type: e.target.value })}
                    className="select"
                  >
                    {projectTypeOptions.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="input-group">
                <label className="input-label">描述</label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="项目描述..."
                  rows={3}
                  className="input resize-none"
                />
              </div>
            </div>

            <div className="modal-footer">
              <button onClick={closeModal} className="btn-secondary text-sm">
                取消
              </button>
              <button
                onClick={handleSubmit}
                disabled={!formData.name.trim() || submitting}
                className="btn-primary text-sm disabled:opacity-50"
              >
                {submitting ? (
                  <>
                    <span className="spinner w-4 h-4" />
                    {editingId ? '保存中...' : '创建中...'}
                  </>
                ) : editingId ? (
                  '保存'
                ) : (
                  '创建'
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      {deleteConfirmId !== null && (
        <div className="modal-overlay" onClick={() => setDeleteConfirmId(null)}>
          <div className="modal max-w-sm" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="text-lg font-semibold text-white">确认删除</h2>
            </div>
            <div className="modal-body">
              <p className="text-slate-300 text-sm">
                确定要删除此项目吗？此操作不可撤销，项目关联的扫描记录也将被删除。
              </p>
            </div>
            <div className="modal-footer">
              <button
                onClick={() => setDeleteConfirmId(null)}
                className="btn-secondary text-sm"
              >
                取消
              </button>
              <button
                onClick={() => handleDelete(deleteConfirmId)}
                className="btn-danger text-sm"
              >
                确认删除
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
