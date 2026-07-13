import { useState, useEffect, useCallback, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import api from '../api/client'
import { Trash2 } from 'lucide-react'

interface Project {
  id: number
  name: string
}

interface Vulnerability {
  cve_id: string
  title: string
  severity: string
  file_path: string
  line: number
}

interface Scan {
  id: number
  project_id: number
  project_name: string
  tool_type: string
  status: string
  vuln_count: number
  vulnerability_count?: number  // 兼容旧版
  progress?: number
  progress_message?: string
  error?: string
  created_at: string
  vulnerabilities?: Vulnerability[]
}

const toolOptions = [
  { value: 'SAST', label: 'SAST' },
  { value: 'SCA', label: 'SCA' },
  { value: 'DAST', label: 'DAST' },
  { value: 'SECRET', label: 'Secret' },
]

const toolBadge: Record<string, string> = {
  SAST: 'badge-info',
  SCA: 'badge-success',
  DAST: 'badge-warning',
  SECRET: 'badge-critical',
}

const statusBadge: Record<string, string> = {
  pending: 'badge-neutral',
  running: 'badge-warning',
  completed: 'badge-success',
  failed: 'badge-critical',
}

const statusLabel: Record<string, string> = {
  pending: '已调度',
  running: '扫描中',
  completed: '已完成',
  failed: '失败',
}

const PAGE_SIZE = 10

// 生成带省略号的页码窗口，避免页数过多时按钮排成一长条
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

const severityBadge: Record<string, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
}

// CI/CD 配置代码（在组件外定义，避免 JSX 花括号冲突）
const gitlabCiCode = `# .gitlab-ci.yml
sentinel-scan:
  stage: test
  script:
    - curl -X POST "\${SENTINEL_URL}/api/webhooks/scan?token=\${SENTINEL_TOKEN}" \\
        -H "Content-Type: application/json" \\
        -d '{"project_name":"\${CI_PROJECT_NAME}","tool_type":"SAST","ref":"\${CI_COMMIT_REF_NAME}"}'
  allow_failure: false`

const githubActionsCode = `# .github/workflows/security.yml
- name: Sentinel Scan
  run: |
    curl -X POST "\${SENTINEL_URL}/api/webhooks/scan?token=\${SENTINEL_TOKEN}" \\
      -H "Content-Type: application/json" \\
      -d '{"project_name":"\${GITHUB_REPOSITORY}","tool_type":"SAST","ref":"\${GITHUB_REF_NAME}"}'`

const jenkinsCode = `// Jenkinsfile
stage('Sentinel Scan') {
  steps {
    sh '''
      curl -X POST "\${SENTINEL_URL}/api/webhooks/scan?token=\${SENTINEL_TOKEN}" \\
        -H "Content-Type: application/json" \\
        -d '{"project_name":"\${JOB_NAME}","tool_type":"SAST","ref":"\${GIT_BRANCH}"}'
    '''
  }
}`

const gateResponseCode = `// POST /api/webhooks/scan 返回
{
  "scan_id": 42,
  "status": "completed",
  "vuln_count": 3,
  "gate": {
    "decision": "block",          // block | warn | pass
    "reasons": ["发现 2 个 Critical 级别漏洞"]
  },
  "vulnerabilities": [
    { "cve_id": "...", "title": "...", "severity": "critical", ... }
  ]
}

// CI/CD 根据 gate.decision 决定是否继续构建
// "block" → exit 1   "warn" → 发通知但继续   "pass" → 继续`

export default function Scans() {
  const [searchParams] = useSearchParams()
  const preselectedProjectId = searchParams.get('project_id')

  const [projects, setProjects] = useState<Project[]>([])
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [filterProjectId, setFilterProjectId] = useState(preselectedProjectId || '')
  const [showNewScan, setShowNewScan] = useState(false)
  const [showCiCd, setShowCiCd] = useState(false)
  const [webhookToken, setWebhookToken] = useState('')
  const [page, setPage] = useState(1)
  const [scanTotal, setScanTotal] = useState(0)
  const [totalPages, setTotalPages] = useState(1)

  // ─── 定时扫描调度 ───
  interface ScanSchedule {
    id: number
    project_id: number
    project_name: string
    tool_type: string
    schedule_type: string
    cron_expression: string
    interval_hours: number
    enabled: number
    last_run_at: string
    last_run_status: string
    next_run_at: string
    created_at: string
  }
  const [schedules, setSchedules] = useState<ScanSchedule[]>([])
  const [showSchedules, setShowSchedules] = useState(false)
  const [scheduleForm, setScheduleForm] = useState({
    project_id: 0, tool_type: 'SAST', schedule_type: 'cron',
    cron_expression: '0 2 * * *', interval_hours: 24, enabled: 1,
  })
  const [scheduleEditing, setScheduleEditing] = useState<number | null>(null)

  // Detail panel
  const [selectedScan, setSelectedScan] = useState<number | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  // New scan form（支持多项目 + 多工具）
  const [selectedProjects, setSelectedProjects] = useState<string[]>(
    preselectedProjectId ? [preselectedProjectId] : []
  )
  const [selectedTools, setSelectedTools] = useState<string[]>(['SAST'])
  const [submitting, setSubmitting] = useState(false)

  // Toast 通知
  interface Toast { id: number; msg: string; type: 'success' | 'error' | 'info' }
  const [toasts, setToasts] = useState<Toast[]>([])
  const showToast = useCallback((msg: string, type: 'success' | 'error' | 'info' = 'info') => {
    const id = Date.now() + Math.random()
    setToasts((prev) => [...prev, { id, msg, type }])
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 4500)
  }, [])

  // 记录上一次各扫描状态，用于检测跃迁弹 toast
  const statusesRef = useRef<Record<number, string>>({})

  // Auto-refresh
  const autoRefreshRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const hasRunningScans = scans.some((s) => s.status === 'running' || s.status === 'pending')

  useEffect(() => {
    loadProjects()
    loadWebhookConfig()
  }, [])

  useEffect(() => {
    loadScans()
  }, [filterProjectId, page])

  useEffect(() => {
    if (hasRunningScans) {
      autoRefreshRef.current = setInterval(loadScans, 3000)
    } else {
      if (autoRefreshRef.current) {
        clearInterval(autoRefreshRef.current)
        autoRefreshRef.current = null
      }
    }
    return () => {
      if (autoRefreshRef.current) clearInterval(autoRefreshRef.current)
    }
  }, [hasRunningScans])

  const loadProjects = async () => {
    try {
      const res = await api.get('/projects')
      setProjects(res.data?.items || [])
    } catch {
      setProjects([])
    }
  }

  const loadWebhookConfig = async () => {
    try {
      const res = await api.get('/webhooks/config')
      setWebhookToken(res.data.token || '')
    } catch {}
  }

  // ─── 定时扫描管理 ───
  const loadSchedules = async () => {
    try {
      const res = await api.get('/schedules')
      setSchedules(res.data || [])
    } catch {}
  }

  const handleCreateSchedule = async () => {
    if (!scheduleForm.project_id) return
    try {
      if (scheduleEditing) {
        await api.put(`/schedules/${scheduleEditing}`, scheduleForm)
      } else {
        await api.post('/schedules', scheduleForm)
      }
      setScheduleEditing(null)
      setScheduleForm({ project_id: 0, tool_type: 'SAST', schedule_type: 'cron', cron_expression: '0 2 * * *', interval_hours: 24, enabled: 1 })
      loadSchedules()
    } catch (e: any) {
      alert(e?.response?.data?.error || '操作失败')
    }
  }

  const handleDeleteSchedule = async (id: number) => {
    if (!confirm('确定删除此定时扫描？')) return
    try {
      await api.delete(`/schedules/${id}`)
      loadSchedules()
    } catch {}
  }

  const handleTriggerSchedule = async (id: number) => {
    try {
      await api.post(`/schedules/${id}/run`)
      loadSchedules()
      loadScans()
    } catch {}
  }

  const handleToggleSchedule = async (schedule: ScanSchedule) => {
    try {
      await api.put(`/schedules/${schedule.id}`, { enabled: schedule.enabled ? 0 : 1 })
      loadSchedules()
    } catch {}
  }

  const startEditSchedule = (s: ScanSchedule) => {
    setScheduleEditing(s.id)
    setScheduleForm({
      project_id: s.project_id, tool_type: s.tool_type,
      schedule_type: s.schedule_type, cron_expression: s.cron_expression,
      interval_hours: s.interval_hours, enabled: s.enabled,
    })
  }

  const cronPresets = [
    { label: '每天凌晨2点', value: '0 2 * * *' },
    { label: '每天上午9点', value: '0 9 * * *' },
    { label: '工作日9:30', value: '30 9 * * 1-5' },
    { label: '每周一8:00', value: '0 8 * * 1' },
    { label: '每小时', value: '0 * * * *' },
  ]

  const loadScans = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, any> = { page, per_page: PAGE_SIZE }
      if (filterProjectId) params.project_id = filterProjectId
      const res = await api.get('/scans', { params })
      const items: Scan[] = res.data?.items || []
      setScanTotal(res.data?.total ?? items.length)
      setTotalPages(Math.max(1, res.data?.pages ?? 1))

      // 检测状态跃迁：running/pending → completed/failed 时弹提示
      const prev = statusesRef.current
      const next: Record<number, string> = {}
      for (const s of items) {
        next[s.id] = s.status
        const before = prev[s.id]
        if (before && before !== s.status) {
          if (s.status === 'completed') {
            showToast(
              `扫描 #${s.id}（${s.project_name || '项目'} · ${s.tool_type}）已完成，发现 ${s.vuln_count ?? s.vulnerability_count ?? 0} 个漏洞`,
              'success'
            )
          } else if (s.status === 'failed') {
            showToast(`扫描 #${s.id}（${s.project_name || '项目'} · ${s.tool_type}）失败`, 'error')
          }
        }
      }
      statusesRef.current = next

      setScans(items)
    } catch {
      setScans([])
    } finally {
      setLoading(false)
    }
  }, [filterProjectId, page, showToast])

  const pagedScans = scans  // 服务端已分页，当前页数据直接用

  // Reset page when filter changes
  useEffect(() => { setPage(1) }, [filterProjectId])

  const toggleProject = (id: string) =>
    setSelectedProjects((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    )

  const toggleTool = (v: string) =>
    setSelectedTools((prev) =>
      prev.includes(v) ? prev.filter((x) => x !== v) : [...prev, v]
    )

  const handleCreateBatch = async () => {
    if (selectedProjects.length === 0 || selectedTools.length === 0) return
    setSubmitting(true)
    try {
      const res = await api.post('/scans/batch', {
        project_ids: selectedProjects.map(Number),
        tool_types: selectedTools,
      })
      const ok = res.data?.count ?? 0
      const total = res.data?.total ?? ok
      setShowNewScan(false)
      setSelectedProjects(preselectedProjectId ? [preselectedProjectId] : [])
      setSelectedTools(['SAST'])
      await loadScans()
      showToast(
        ok === total
          ? `已提交 ${ok} 个扫描任务`
          : `已提交 ${ok}/${total} 个扫描任务（部分项目或工具不可用）`,
        ok > 0 ? 'success' : 'error'
      )
    } catch (e: any) {
      const msg = e?.response?.data?.error || '批量扫描创建失败，请检查工具是否已启用'
      alert(msg)
    } finally {
      setSubmitting(false)
    }
  }

  const handleDeleteScan = async (id: number) => {
    if (!confirm('确定删除该扫描任务？此操作不可撤销。')) return
    try {
      await api.delete(`/scans/${id}`)
      await loadScans()
    } catch {}
  }

  const handleRowClick = async (scan: Scan) => {
    if (selectedScan === scan.id) {
      setSelectedScan(null)
      return
    }

    if (scan.vulnerabilities) {
      setSelectedScan(scan.id)
      return
    }

    setDetailLoading(true)
    try {
      const res = await api.get(`/scans/${scan.id}`)
      const detail: Scan = res.data
      setScans((prev) =>
        prev.map((s) =>
          s.id === scan.id ? { ...s, vulnerabilities: detail.vulnerabilities } : s
        )
      )
      setSelectedScan(scan.id)
    } catch {
    } finally {
      setDetailLoading(false)
    }
  }

  const openNewScan = () => {
    setSelectedProjects(filterProjectId ? [filterProjectId] : (preselectedProjectId ? [preselectedProjectId] : []))
    setSelectedTools(['SAST'])
    setShowNewScan(true)
  }

  const expandedScan = selectedScan !== null ? scans.find((s) => s.id === selectedScan) : null

  return (
    <div className="max-w-7xl mx-auto">
      {/* Toast 通知 */}
      <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`px-4 py-2.5 rounded-lg shadow-lg text-sm border max-w-sm pointer-events-auto ${
              t.type === 'success'
                ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                : t.type === 'error'
                ? 'bg-red-500/15 border-red-500/30 text-red-300'
                : 'bg-surface-800 border-slate-700 text-slate-200'
            }`}
          >
            {t.msg}
          </div>
        ))}
      </div>

      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">扫描中心</h1>
          <p className="page-subtitle">管理安全扫描任务，查看扫描结果与漏洞详情</p>
        </div>
        <div className="flex items-center gap-3">
          {hasRunningScans && (
            <button onClick={loadScans} className="btn-secondary text-xs">
              刷新
            </button>
          )}
          <button onClick={openNewScan} className="btn-primary text-xs">
            新建扫描
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-3 mb-4">
        <label className="text-slate-400 text-xs">筛选项目：</label>
        <select
          value={filterProjectId}
          onChange={(e) => setFilterProjectId(e.target.value)}
          className="select w-auto min-w-[180px]"
        >
          <option value="">全部项目</option>
          {projects.map((p) => (
            <option key={p.id} value={String(p.id)}>
              {p.name}
            </option>
          ))}
        </select>
      </div>

      {/* Content */}
      {loading ? (
        <div className="text-slate-500 text-sm">加载中...</div>
      ) : scans.length === 0 ? (
        <div className="card text-center py-12">
          <div className="text-slate-500 text-sm mb-4">暂无扫描记录</div>
          <button onClick={openNewScan} className="btn-primary text-sm">
            发起首次扫描
          </button>
        </div>
      ) : (
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>项目名称</th>
                <th>工具类型</th>
                <th>状态</th>
                <th>漏洞数</th>
                <th>创建时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {pagedScans.map((scan) => (
                <tr
                  key={scan.id}
                  onClick={() => handleRowClick(scan)}
                  className="cursor-pointer"
                >
                  <td className="text-white font-medium">
                    {scan.project_name || `项目 #${scan.project_id}`}
                  </td>
                  <td>
                    <span className={`badge ${toolBadge[scan.tool_type] || 'badge-info'}`}>
                      {scan.tool_type}
                    </span>
                  </td>
                  <td>
                    {(scan.status === 'running' || scan.status === 'pending') ? (
                      <div className="flex flex-col gap-1 min-w-[170px]">
                        <div className="flex items-center justify-between gap-2">
                          <span className={`badge ${statusBadge[scan.status] || 'badge-neutral'}`}>
                            {statusLabel[scan.status] || scan.status}
                          </span>
                          <span className="text-xs font-semibold text-primary-400 tabular-nums">
                            {scan.progress || 0}%
                          </span>
                        </div>
                        <div className="w-full h-2 rounded-full bg-slate-700/50 overflow-hidden">
                          <div
                            className="h-full rounded-full bg-primary-500 transition-all duration-700"
                            style={{ width: `${scan.progress || 0}%` }}
                          />
                        </div>
                        {scan.progress_message && (
                          <span className="text-xs text-slate-400 truncate max-w-[200px]" title={scan.progress_message}>
                            {scan.progress_message}
                          </span>
                        )}
                      </div>
                    ) : (
                      <div className="flex flex-col gap-0.5 min-w-[120px]">
                        <span className={`badge ${statusBadge[scan.status] || 'badge-neutral'}`}>
                          {statusLabel[scan.status] || scan.status}
                        </span>
                        {scan.status === 'failed' && scan.error && (
                          <span className="text-[9px] text-red-400/70 truncate max-w-[180px]" title={scan.error}>
                            {scan.error.length > 50 ? scan.error.slice(0, 50) + '...' : scan.error}
                          </span>
                        )}
                      </div>
                    )}
                  </td>
                  <td>
                    {scan.status === 'completed'
                      ? (scan.vuln_count ?? scan.vulnerability_count ?? '-')
                      : '-'}
                  </td>
                  <td className="text-xs">{scan.created_at?.slice(0, 16)}</td>
                  <td onClick={e => e.stopPropagation()}>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-slate-500">
                        {selectedScan === scan.id ? '收起' : '展开'}
                      </span>
                      <button
                        onClick={() => handleDeleteScan(scan.id)}
                        className="text-xs text-red-400 hover:text-red-300 px-1.5 py-0.5 flex items-center gap-1"
                        title="删除"
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {scanTotal > PAGE_SIZE && (
        <div className="flex items-center justify-between pt-3 text-xs text-slate-400">
          <span>共 {scanTotal} 条 · 第 {page} / {totalPages} 页</span>
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

      {/* Detail panel */}
      {expandedScan && (
        <div className="card mt-4">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-white font-medium">
                {expandedScan.project_name || `项目 #${expandedScan.project_id}`}
                <span className="text-slate-500 text-xs font-normal ml-2">
                  {expandedScan.tool_type} 扫描详情
                </span>
              </h3>
              <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
                <span>状态：<span className={`badge ${statusBadge[expandedScan.status] || 'badge-neutral'}`}>{statusLabel[expandedScan.status] || expandedScan.status}</span></span>
                <span>创建时间：{expandedScan.created_at?.slice(0, 16)}</span>
                <span>漏洞数：{expandedScan.vuln_count ?? expandedScan.vulnerability_count ?? 0}</span>
              </div>
            </div>
            <button
              onClick={() => setSelectedScan(null)}
              className="btn-secondary text-xs"
            >
              收起
            </button>
          </div>

          {detailLoading ? (
            <div className="text-slate-500 text-sm">加载漏洞数据...</div>
          ) : !expandedScan.vulnerabilities || expandedScan.vulnerabilities.length === 0 ? (
            <div className="text-slate-500 text-sm">未发现漏洞</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="table">
                <thead>
                  <tr>
                    <th>CVE ID</th>
                    <th>标题</th>
                    <th>严重程度</th>
                    <th>文件路径</th>
                  </tr>
                </thead>
                <tbody>
                  {expandedScan.vulnerabilities.map((v, idx) => (
                    <tr key={v.cve_id || idx}>
                      <td className="font-mono text-xs">{v.cve_id || '-'}</td>
                      <td>{v.title}</td>
                      <td>
                        <span className={`badge ${severityBadge[v.severity] || 'badge-info'}`}>
                          {v.severity}
                        </span>
                      </td>
                      <td className="font-mono text-xs max-w-[400px] truncate">{v.file_path}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* New Scan Modal */}
      {showNewScan && (
        <div
          className="modal-overlay"
          onClick={() => setShowNewScan(false)}
        >
          <div
            className="modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-header">
              <h2 className="text-lg font-semibold text-white">新建扫描</h2>
              <button
                onClick={() => setShowNewScan(false)}
                className="text-slate-500 hover:text-slate-300 text-sm"
              >
                ✕
              </button>
            </div>

            <div className="modal-body space-y-4">
              {/* 多选项目 */}
              <div className="input-group">
                <div className="flex items-center justify-between">
                  <label className="input-label">项目 *（可多选，已选 {selectedProjects.length} 个）</label>
                  <div className="flex gap-2">
                    <button type="button" onClick={() => setSelectedProjects(projects.map((p) => String(p.id)))}
                      className="text-xs text-primary-400 hover:underline">全选</button>
                    <button type="button" onClick={() => setSelectedProjects([])}
                      className="text-xs text-slate-400 hover:underline">清空</button>
                  </div>
                </div>
                <div className="max-h-48 overflow-y-auto rounded-lg border border-slate-700/50 bg-surface-800 p-2 space-y-1">
                  {projects.length === 0 ? (
                    <div className="text-slate-500 text-xs px-2 py-1.5">暂无项目，请先在「项目管理」中创建</div>
                  ) : projects.map((p) => {
                    const checked = selectedProjects.includes(String(p.id))
                    return (
                      <label key={p.id} className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-surface-700 cursor-pointer text-sm">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleProject(String(p.id))}
                          className="accent-primary-500 w-4 h-4"
                        />
                        <span className="text-slate-200">{p.name}</span>
                      </label>
                    )
                  })}
                </div>
              </div>

              {/* 多选工具 */}
              <div className="input-group">
                <label className="input-label">扫描工具 *（可多选，已选 {selectedTools.length} 个）</label>
                <div className="grid grid-cols-2 gap-2 mt-1.5">
                  {toolOptions.map((opt) => {
                    const checked = selectedTools.includes(opt.value)
                    return (
                      <button
                        key={opt.value}
                        type="button"
                        onClick={() => toggleTool(opt.value)}
                        className={`text-left px-3 py-2 rounded-lg border text-sm transition-colors ${
                          checked
                            ? 'border-primary-500 bg-primary-500/10 text-primary-400'
                            : 'border-slate-700/50 bg-surface-800 text-slate-400 hover:border-slate-500'
                        }`}
                      >
                        <span className={`badge ${toolBadge[opt.value]}`}>{opt.label}</span>
                        {checked && <span className="ml-1.5 text-primary-400">✓</span>}
                      </button>
                    )
                  })}
                </div>
                <p className="text-slate-600 text-xs mt-2">
                  将发起 {selectedProjects.length * selectedTools.length} 个并行扫描任务
                  {selectedProjects.length * selectedTools.length > 1 ? '（每个项目 × 每种工具）' : ''}
                </p>
              </div>
            </div>

            <div className="modal-footer">
              <button
                onClick={() => setShowNewScan(false)}
                className="btn-secondary text-sm"
              >
                取消
              </button>
              <button
                onClick={handleCreateBatch}
                disabled={selectedProjects.length === 0 || selectedTools.length === 0 || submitting}
                className="btn-primary text-sm disabled:opacity-50"
              >
                {submitting
                  ? '提交中...'
                  : `开始扫描${selectedProjects.length > 1 || selectedTools.length > 1 ? '（批量）' : ''}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── CI/CD 集成面板 ─── */}
      <div className="mt-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="text-indigo-400">
              <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>
            </svg>
            CI/CD 安全门禁
          </h2>
          <button onClick={() => setShowCiCd(!showCiCd)} className="btn-secondary text-sm">
            {showCiCd ? '收起' : '配置'}
          </button>
        </div>

        {showCiCd && (
          <div className="card space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* GitLab CI */}
              <div className="bg-surface-900 rounded-xl p-5 border border-surface-700">
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-8 h-8 rounded-lg bg-orange-500/20 flex items-center justify-center">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="#f97316"><path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 01-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 014.82 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0118.6 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.51L23 13.45a.84.84 0 01-.35.94z"/></svg>
                  </div>
                  <span className="text-white font-semibold text-sm">GitLab CI</span>
                </div>
                <pre className="bg-surface-950 text-slate-300 text-xs p-4 rounded-lg overflow-x-auto font-mono leading-relaxed">{gitlabCiCode}</pre>
              </div>

              {/* GitHub Actions */}
              <div className="bg-surface-900 rounded-xl p-5 border border-surface-700">
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-8 h-8 rounded-lg bg-slate-500/20 flex items-center justify-center">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="#94a3b8"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                  </div>
                  <span className="text-white font-semibold text-sm">GitHub Actions</span>
                </div>
                <pre className="bg-surface-950 text-slate-300 text-xs p-4 rounded-lg overflow-x-auto font-mono leading-relaxed">{githubActionsCode}</pre>
              </div>

              {/* Jenkins */}
              <div className="bg-surface-900 rounded-xl p-5 border border-surface-700">
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="#ef4444"><rect x="3" y="3" width="8" height="8" rx="1"/><rect x="13" y="3" width="8" height="8" rx="1"/><rect x="3" y="13" width="8" height="8" rx="1"/><rect x="13" y="13" width="8" height="8" rx="1"/></svg>
                  </div>
                  <span className="text-white font-semibold text-sm">Jenkins</span>
                </div>
                <pre className="bg-surface-950 text-slate-300 text-xs p-4 rounded-lg overflow-x-auto font-mono leading-relaxed">{jenkinsCode}</pre>
              </div>
            </div>

            {/* Webhook 配置区 */}
            <div className="border-t border-surface-700 pt-5">
              <div className="flex items-center gap-4 flex-wrap">
                <div className="flex-1 min-w-[300px]">
                  <label className="input-label mb-1.5">Webhook Token</label>
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      value={webhookToken || '(未配置 — 开发模式允许所有请求)'}
                      readOnly
                      className="input flex-1 font-mono text-xs"
                    />
                    <button
                      onClick={async () => {
                        try {
                          const res = await api.post('/webhooks/regenerate-token')
                          setWebhookToken(res.data.token)
                        } catch {}
                      }}
                      className="btn-secondary text-xs whitespace-nowrap"
                    >
                      重新生成
                    </button>
                  </div>
                  <p className="text-slate-600 text-xs mt-1.5">
                    Webhook URL: <code className="text-primary-400">POST {window.location.origin}/api/webhooks/scan?token=YOUR_TOKEN</code>
                  </p>
                </div>
                <div className="flex items-end gap-2">
                  <div className="px-3 py-2 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-xs text-indigo-400">
                    <span className="font-semibold">门禁规则</span>
                    <div className="mt-1 space-y-0.5">
                      <div><span className="inline-block w-12">Critical</span> → <span className="text-red-400 font-semibold">阻断</span></div>
                      <div><span className="inline-block w-12">High</span> → <span className="text-orange-400 font-semibold">告警</span></div>
                      <div><span className="inline-block w-12">Medium</span> → <span className="text-green-400">放行</span></div>
                      <div><span className="inline-block w-12">Low</span> → <span className="text-green-400">放行</span></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="border-t border-surface-700 pt-4">
              <h4 className="text-sm font-semibold text-white mb-3">安全门禁响应示例</h4>
              <pre className="bg-surface-950 text-slate-300 text-xs p-4 rounded-lg overflow-x-auto font-mono leading-relaxed">{gateResponseCode}</pre>
            </div>
          </div>
        )}
      </div>

      {/* ─── 定时扫描调度 ─── */}
      <div className="mt-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="text-emerald-400">
              <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
            </svg>
            定时扫描
          </h2>
          <button onClick={() => { setShowSchedules(!showSchedules); if (!showSchedules) loadSchedules() }} className="btn-secondary text-sm">
            {showSchedules ? '收起' : '管理'}
          </button>
        </div>

        {showSchedules && (
          <div className="card space-y-6">
            {/* 新建/编辑表单 */}
            <div className="bg-surface-900 rounded-xl p-5 border border-surface-700">
              <h4 className="text-sm font-semibold text-white mb-4">
                {scheduleEditing ? '编辑定时扫描' : '新建定时扫描'}
              </h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                <div>
                  <label className="input-label mb-1.5">项目</label>
                  <select
                    value={scheduleForm.project_id || ''}
                    onChange={e => setScheduleForm({ ...scheduleForm, project_id: Number(e.target.value) })}
                    className="input"
                  >
                    <option value="">选择项目</option>
                    {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                  </select>
                </div>
                <div>
                  <label className="input-label mb-1.5">工具类型</label>
                  <select
                    value={scheduleForm.tool_type}
                    onChange={e => setScheduleForm({ ...scheduleForm, tool_type: e.target.value })}
                    className="input"
                  >
                    {toolOptions.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="input-label mb-1.5">调度类型</label>
                  <select
                    value={scheduleForm.schedule_type}
                    onChange={e => setScheduleForm({ ...scheduleForm, schedule_type: e.target.value })}
                    className="input"
                  >
                    <option value="cron">Cron 表达式</option>
                    <option value="interval">固定间隔</option>
                  </select>
                </div>
                <div>
                  <label className="input-label mb-1.5">
                    {scheduleForm.schedule_type === 'cron' ? 'Cron 表达式' : '间隔（小时）'}
                  </label>
                  {scheduleForm.schedule_type === 'cron' ? (
                    <select
                      value={scheduleForm.cron_expression}
                      onChange={e => setScheduleForm({ ...scheduleForm, cron_expression: e.target.value })}
                      className="input"
                    >
                      {cronPresets.map(cp => <option key={cp.value} value={cp.value}>{cp.label} ({cp.value})</option>)}
                    </select>
                  ) : (
                    <select
                      value={scheduleForm.interval_hours}
                      onChange={e => setScheduleForm({ ...scheduleForm, interval_hours: Number(e.target.value) })}
                      className="input"
                    >
                      <option value={6}>每 6 小时</option>
                      <option value={12}>每 12 小时</option>
                      <option value={24}>每天</option>
                      <option value={48}>每 2 天</option>
                      <option value={168}>每周</option>
                    </select>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-3">
                <button onClick={handleCreateSchedule} className="btn-primary text-sm">
                  {scheduleEditing ? '更新' : '创建'}
                </button>
                {scheduleEditing && (
                  <button onClick={() => { setScheduleEditing(null); setScheduleForm({ project_id: 0, tool_type: 'SAST', schedule_type: 'cron', cron_expression: '0 2 * * *', interval_hours: 24, enabled: 1 }) }} className="btn-secondary text-sm">
                    取消
                  </button>
                )}
              </div>
            </div>

            {/* 调度列表 */}
            {schedules.length === 0 ? (
              <p className="text-slate-500 text-sm text-center py-4">暂无定时扫描任务</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="table">
                  <thead>
                    <tr>
                      <th>项目</th>
                      <th>工具</th>
                      <th>调度</th>
                      <th>状态</th>
                      <th>上次执行</th>
                      <th>下次执行</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {schedules.map(s => (
                      <tr key={s.id}>
                        <td className="font-medium text-white text-sm">{s.project_name}</td>
                        <td><span className={`badge ${toolBadge[s.tool_type] || 'badge-neutral'}`}>{s.tool_type}</span></td>
                        <td className="text-slate-300 text-xs">
                          {s.schedule_type === 'cron'
                            ? `Cron: ${s.cron_expression}`
                            : `每 ${s.interval_hours}h`}
                        </td>
                        <td>
                          <button
                            onClick={() => handleToggleSchedule(s)}
                            className={`badge cursor-pointer ${s.enabled ? 'badge-success' : 'badge-neutral'}`}
                          >
                            {s.enabled ? '启用' : '停用'}
                          </button>
                        </td>
                        <td className="text-slate-400 text-xs">
                          {s.last_run_at ? (
                            <span>
                              {s.last_run_at.slice(0, 16).replace('T', ' ')}
                              <span className={`ml-1 ${s.last_run_status === 'completed' ? 'text-green-400' : 'text-red-400'}`}>
                                {s.last_run_status === 'completed' ? '✓' : '✗'}
                              </span>
                            </span>
                          ) : '—'}
                        </td>
                        <td className="text-slate-400 text-xs">
                          {s.next_run_at ? s.next_run_at.slice(0, 16).replace('T', ' ') : '—'}
                        </td>
                        <td>
                          <div className="flex items-center gap-1.5">
                            <button onClick={() => handleTriggerSchedule(s.id)} className="text-xs text-emerald-400 hover:text-emerald-300 px-1.5 py-0.5" title="立即执行">
                              ▶
                            </button>
                            <button onClick={() => startEditSchedule(s)} className="text-xs text-blue-400 hover:text-blue-300 px-1.5 py-0.5" title="编辑">
                              编辑
                            </button>
                            <button onClick={() => handleDeleteSchedule(s.id)} className="text-xs text-red-400 hover:text-red-300 px-1.5 py-0.5" title="删除">
                              删除
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
