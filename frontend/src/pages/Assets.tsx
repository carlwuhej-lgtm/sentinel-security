import { useState, useEffect } from 'react'
import api from '../api/client'

interface Asset {
  id: number; name: string; asset_type: string; project_id: number | null
  tech_stack: string[]; environment: string
  owner: string; owner_email: string; risk_score: number; risk_level: string
  status: string; last_scan_date: string; last_vuln_count: number
  description: string; created_at: string; updated_at: string
}

const TYPE_LABELS: Record<string, string> = { web_api: 'Web API', mobile_app: '移动端', microservice: '微服务', library: '组件库', infrastructure: '基础设施' }
const ENV_LABELS: Record<string, string> = { production: '生产环境', staging: '预发', development: '开发', test: '测试', unknown: '未知' }
const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
}
const RISK_DOT: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500',
  low: 'bg-blue-500', info: 'bg-slate-500',
}

const PAGE_SIZE = 10

export default function Assets() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [loading, setLoading] = useState(true)
  const [viewMode, setViewMode] = useState<'table' | 'card'>('card')
  const [search, setSearch] = useState('')
  const [filterRisk, setFilterRisk] = useState('')
  const [filterType, setFilterType] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [page, setPage] = useState(1)
  const [showModal, setShowModal] = useState(false)
  const [detailAsset, setDetailAsset] = useState<Asset | null>(null)
  const [stats, setStats] = useState<any>(null)
  const [form, setForm] = useState({
    name: '', asset_type: 'web_api', tech_stack: [] as string[],
    environment: 'unknown', owner: '', owner_email: '', description: '',
  })

  useEffect(() => { loadAssets(); loadStats() }, [])

  const loadAssets = async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = {}
      if (filterRisk) params.risk_level = filterRisk
      if (filterType) params.type = filterType
      if (filterStatus) params.status = filterStatus
      if (search) params.search = search
      const res = await api.get('/assets', { params })
      setAssets(res.data.items || [])
    } catch {}
    setLoading(false)
  }

  const loadStats = async () => {
    try {
      const res = await api.get('/assets/stats')
      setStats(res.data)
    } catch {}
  }

  const totalPages = Math.max(1, Math.ceil(assets.length / PAGE_SIZE))
  const pagedAssets = assets.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  // Reset page when filters change
  useEffect(() => { setPage(1) }, [filterRisk, filterType, filterStatus, search])

  const openDetail = async (a: Asset) => {
    try {
      const res = await api.get(`/assets/${a.id}`)
      setDetailAsset(res.data)
    } catch {}
  }

  const handleCreate = async () => {
    if (!form.name.trim()) return
    try {
      await api.post('/assets', form)
      setShowModal(false); setForm({ name:'', asset_type:'web_api', tech_stack:[], environment:'unknown', owner:'', owner_email:'', description:'' })
      loadAssets(); loadStats()
    } catch {}
  }

  const syncFromProjects = async () => {
    try {
      const res = await api.post('/assets/sync-from-projects')
      alert(`同步完成：新建 ${res.data.created}，更新 ${res.data.updated}`)
      loadAssets(); loadStats()
    } catch {}
  }

  const recalcRisk = async (id: number) => {
    try {
      await api.post(`/assets/${id}/recalc-risk`)
      loadAssets()
    } catch {}
  }

  const deleteAsset = async (id: number) => {
    if (!confirm('确定删除该资产？')) return
    try { await api.delete(`/assets/${id}`); loadAssets(); loadStats() } catch {}
  }

  // Stats display
  const statCards = stats ? [
    { label: '总资产数', value: stats.total_assets, color: 'text-white' },
    { label: '活跃资产', value: stats.active_assets, color: 'text-green-400' },
    { label: '高风险', value: stats.high_risk_assets, color: 'text-red-400' },
    { label: '平均风险分', value: String(stats.avg_risk_score), color: 'text-orange-400' },
  ] : []

  const riskBarWidth = (score: number) => Math.min(100, score)

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">资产管理</h1>
          <p className="page-subtitle">资产发现、清单管理、风险评分与追踪</p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={syncFromProjects} className="btn-secondary text-xs">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
            从项目同步
          </button>
          <button onClick={() => setShowModal(true)} className="btn-primary text-xs">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 4v16m8-8H4"/></svg>
            新增资产
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {statCards.map(s => (
          <div key={s.label} className="bg-surface-800/50 border border-slate-700/50 rounded-xl p-4">
            <div className={`text-2xl font-bold tabular-nums ${s.color}`}>{s.value}</div>
            <div className="text-xs text-slate-400 mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Risk distribution bar */}
      {stats?.by_risk && Object.keys(stats.by_risk).length > 0 && (
        <div className="bg-surface-800/50 border border-slate-700/50 rounded-xl p-4">
          <div className="text-xs text-slate-400 mb-3">风险等级分布</div>
          <div className="flex gap-1 h-6 rounded-md overflow-hidden">
            {Object.entries(stats.by_risk).map(([level, count]: [string, any]) => (
              <div key={level} title={`${level}: ${count}`} className={`flex items-center justify-center text-[10px] font-bold text-white ${RISK_DOT[level] || 'bg-slate-600'}`}
                style={{ width: `${Math.max(5, count / Math.max(stats.total_assets, 1) * 100)}%` }}>
                {count > 0 ? count : ''}
              </div>
            ))}
          </div>
          <div className="flex gap-4 mt-2 flex-wrap">
            {Object.entries(stats.by_risk).map(([level, count]: [string, any]) => (
              <span key={level} className="flex items-center gap-1.5 text-[10px] text-slate-400">
                <span className={`w-2 h-2 rounded-sm ${RISK_DOT[level] || 'bg-slate-600'}`} />
                {level}: {count}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Controls */}
      <div className="flex items-center gap-3 flex-wrap">
        <input value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => e.key === 'Enter' && loadAssets()}
          placeholder='搜索资产名称 / 负责人...' className="flex-1 min-w-[200px] bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-primary-500 outline-none placeholder:text-slate-500" />
        <select value={filterRisk} onChange={e => setFilterRisk(e.target.value)} className="bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300 outline-none">
          <option value="">全部风险</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option><option value="info">信息</option>
        </select>
        <select value={filterType} onChange={e => setFilterType(e.target.value)} className="bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300 outline-none">
          <option value="">全部类型</option>{Object.entries(TYPE_LABELS).map(([k,v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <div className="flex bg-surface-800 rounded-lg border border-slate-700 overflow-hidden ml-auto">
          <button onClick={() => setViewMode('table')} className={`px-3 py-1.5 text-xs ${viewMode === 'table' ? 'bg-primary-600 text-white' : 'text-slate-400 hover:text-white'}`}>表格</button>
          <button onClick={() => setViewMode('card')} className={`px-3 py-1.5 text-xs ${viewMode === 'card' ? 'bg-primary-600 text-white' : 'text-slate-400 hover:text-white'}`}>卡片</button>
        </div>
        <button onClick={loadAssets} className="text-xs text-slate-400 hover:text-white px-2">刷新</button>
      </div>

      {/* Card View */}
      {!loading && viewMode === 'card' && assets.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {assets.map(a => (
            <div key={a.id} onClick={() => openDetail(a)}
              className="bg-surface-800/40 border border-slate-700/50 rounded-xl p-5 cursor-pointer hover:border-primary-500/30 hover:bg-surface-800/60 transition-all group">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="font-semibold text-white group-hover:text-primary-400 transition-colors">{a.name}</div>
                  <div className="text-xs text-slate-500 mt-0.5">{TYPE_LABELS[a.asset_type] || a.asset_type} · {ENV_LABELS[a.environment] || a.environment}</div>
                </div>
                <span className={`inline-flex px-2 py-0.5 rounded-md text-[10px] font-semibold border uppercase ${RISK_COLORS[a.risk_level] || ''}`}>
                  {a.risk_level}
                </span>
              </div>

              {/* Risk score bar */}
              <div className="mb-3">
                <div className="flex justify-between text-[10px] text-slate-500 mb-1">
                  <span>风险评分</span><span>{a.risk_score}/100</span>
                </div>
                <div className="w-full h-1.5 bg-surface-900 rounded-full overflow-hidden">
                  <div className={`h-full rounded-full transition-all ${
                    a.risk_score >= 80 ? 'bg-red-500' : a.risk_score >= 60 ? 'bg-orange-500' :
                    a.risk_score >= 35 ? 'bg-yellow-500' : 'bg-blue-500'
                  }`} style={{ width: `${riskBarWidth(a.risk_score)}%` }} />
                </div>
              </div>

              {/* Tech stack tags */}
              {(Array.isArray(a.tech_stack) ? a.tech_stack : []).length > 0 && (
                <div className="flex gap-1 flex-wrap mb-3">
                  {(Array.isArray(a.tech_stack) ? a.tech_stack : []).slice(0, 4).map((t, i) =>
                    <span key={i} className="px-1.5 py-0.5 bg-surface-900 rounded text-[10px] text-slate-400">{String(t)}</span>
                  )}
                </div>
              )}

              {/* Meta row */}
              <div className="flex items-center justify-between text-[10px] text-slate-500 pt-3 border-t border-slate-700/30">
                <span>{a.owner || '-'}</span>
                <span>{a.last_vuln_count} 开放漏洞</span>
                <div className="flex items-center gap-1.5">
                  <span>{a.last_scan_date ? String(a.last_scan_date).slice(0, 10) : '未扫描'}</span>
                  <button onClick={e => { e.stopPropagation(); deleteAsset(a.id) }}
                    className="text-slate-500 hover:text-red-400 transition-colors" title="删除">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2m3 0v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6h14"/></svg>
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Table View */}
      {(!loading && viewMode === 'table') || (viewMode !== 'card') ? (
        <div className="bg-surface-800/30 border border-slate-700/50 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead><tr className="bg-surface-800/80 text-left text-xs text-slate-400 uppercase tracking-wider">
              <th className="px-4 py-3">资产名称</th><th className="px-4 py-3">类型</th><th className="px-4 py-3">技术栈</th>
              <th className="px-4 py-3">环境</th><th className="px-4 py-3">负责人</th>
              <th className="px-4 py-3">风险</th><th className="px-4 py-3">漏洞</th><th className="px-4 py-3">操作</th>
            </tr></thead>
            <tbody className="divide-y divide-slate-700/40">
              {loading ? (<tr><td colSpan={8} className="px-4 py-12 text-center text-slate-500">加载中...</td></tr>) :
               assets.length === 0 ? (<tr><td colSpan={8} className="px-4 py-12 text-center text-slate-500">暂无资产数据</td></tr>) :
               pagedAssets.map(a => (
                 <tr key={a.id} className="hover:bg-surface-800/30 transition-colors">
                   <td className="px-4 py-3 font-medium text-white">{a.name}</td>
                   <td className="px-4 py-3 text-slate-300">{TYPE_LABELS[a.asset_type] || a.asset_type}</td>
                   <td className="px-4 py-3">
                     {(Array.isArray(a.tech_stack) ? a.tech_stack : []).slice(0, 3).map((t, i) =>
                       <span key={i} className="mr-1 px-1.5 py-0.5 bg-surface-900 rounded text-[10px] text-slate-400">{String(t)}</span>
                     )}
                   </td>
                   <td className="px-4 py-3 text-slate-300">{ENV_LABELS[a.environment] || a.environment}</td>
                   <td className="px-4 py-3 text-slate-400">{a.owner || '-'}</td>
                   <td className="px-4 py-3">
                     <div className="flex items-center gap-2">
                       <div className="w-14 h-1.5 bg-surface-900 rounded-full overflow-hidden">
                         <div className={`h-full rounded-full ${a.risk_score >= 80 ? 'bg-red-500' : a.risk_score >= 60 ? 'bg-orange-500' : a.risk_score >= 35 ? 'bg-yellow-500' : 'bg-blue-500'}`}
                           style={{ width: `${riskBarWidth(a.risk_score)}%` }} />
                       </div>
                       <span className={`text-[10px] font-semibold ${RISK_COLORS[a.risk_level]?.split(' ')[1] || ''}`}>{a.risk_level}</span>
                     </div>
                   </td>
                   <td className="px-4 py-3 tabular-nums">{a.last_vuln_count}</td>
                   <td className="px-4 py-3">
                     <div className="flex items-center gap-1">
                       <button onClick={() => openDetail(a)} className="text-slate-400 hover:text-primary-400 p-1 text-xs">详情</button>
                       <button onClick={() => recalcRisk(a.id)} className="text-slate-400 hover:text-yellow-400 p-1 text-xs">重算</button>
                       <button onClick={() => deleteAsset(a.id)} className="text-slate-400 hover:text-red-400 p-1 text-xs">删除</button>
                     </div>
                   </td>
                 </tr>
               ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {/* Pagination — table view only */}
      {!loading && viewMode === 'table' && assets.length > PAGE_SIZE && (
        <div className="flex items-center justify-between pt-3 text-xs text-slate-400">
          <span>共 {assets.length} 条</span>
          <div className="flex items-center gap-1">
            <button disabled={page <= 1} onClick={() => setPage(page - 1)}
              className="px-2 py-1 rounded bg-surface-800 border border-slate-700 disabled:opacity-30 hover:border-slate-600">
              上一页
            </button>
            {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
              <button key={p} onClick={() => setPage(p)}
                className={`px-2.5 py-1 rounded text-xs ${p === page
                  ? 'bg-primary-600 text-white' : 'bg-surface-800 border border-slate-700 hover:border-slate-600'}`}>
                {p}
              </button>
            ))}
            <button disabled={page >= totalPages} onClick={() => setPage(page + 1)}
              className="px-2 py-1 rounded bg-surface-800 border border-slate-700 disabled:opacity-30 hover:border-slate-600">
              下一页
            </button>
          </div>
        </div>
      )}

      {/* Detail Modal */}
      {detailAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setDetailAsset(null)}>
          <div className="bg-surface-900 border border-slate-700 rounded-2xl shadow-2xl w-full max-w-2xl mx-4 max-h-[85vh] overflow-y-auto p-6" onClick={e => e.stopPropagation()}>
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-lg font-bold text-white">{detailAsset.name}</h3>
                <div className="text-xs text-slate-400 mt-1">{TYPE_LABELS[detailAsset.asset_type]} · {ENV_LABELS[detailAsset.environment]}</div>
              </div>
              <button onClick={() => setDetailAsset(null)} className="text-slate-500 hover:text-white"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 18L18 6M6 6l12 12"/></svg></button>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-4">
              {[
                ['风险分', `${detailAsset.risk_score}/100 (${detailAsset.risk_level})`],
                ['状态', detailAsset.status],
                ['负责人', detailAsset.owner || '-'],
                ['开放漏洞', String(detailAsset.last_vuln_count)],
                ['最后扫描', detailAsset.last_scan_date || '-'],
                ['创建时间', detailAsset.created_at || '-'],
                ['技术栈', (Array.isArray(detailAsset.tech_stack) ? detailAsset.tech_stack.join(', ') : '-')],
                ['描述', detailAsset.description || '-'],
              ].map(([k, v]) => (
                <div key={String(k)} className="bg-surface-800/50 rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase tracking-wider">{k}</div>
                  <div className="text-sm text-slate-200 mt-1">{v}</div>
                </div>
              ))}
            </div>

            {'open_vulnerabilities' in detailAsset && Array.isArray(detailAsset.open_vulnerabilities) && detailAsset.open_vulnerabilities.length > 0 && (
              <div>
                <h4 className="text-sm font-semibold text-white mb-2">关联开放漏洞</h4>
                <div className="space-y-1 max-h-48 overflow-y-auto">
                  {detailAsset.open_vulnerabilities.map((v: any, i: number) => (
                    <div key={i} className="flex items-center justify-between bg-surface-800/50 rounded-lg px-3 py-2 text-xs">
                      <div className="truncate flex-1 mr-2">
                        <span className={`font-semibold ${
                          v.severity === 'critical' ? 'text-red-400' : v.severity === 'high' ? 'text-orange-400' : v.severity === 'medium' ? 'text-yellow-400' : 'text-slate-300'
                        }`}>{v.title}</span>
                        {v.cve_id && <span className="ml-2 text-slate-500">{v.cve_id}</span>}
                      </div>
                      <span className="text-slate-500 shrink-0">{v.file_path?.split('/').pop() || '-'}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex justify-end mt-4 pt-4 border-t border-slate-700/50">
              <button onClick={() => recalcRisk(detailAsset!.id)} className="px-3 py-1.5 text-xs bg-surface-800 hover:bg-surface-700 text-slate-300 rounded-lg mr-2 transition-colors">重新计算风险分</button>
              <button onClick={() => { if (confirm('确定删除该资产？')) { deleteAsset(detailAsset!.id); setDetailAsset(null) } }} className="px-3 py-1.5 text-xs bg-red-600/20 hover:bg-red-600/40 text-red-400 rounded-lg mr-2 transition-colors">删除资产</button>
              <button onClick={() => setDetailAsset(null)} className="px-4 py-1.5 text-xs bg-primary-600 hover:bg-primary-500 text-white rounded-lg transition-colors">关闭</button>
            </div>
          </div>
        </div>
      )}

      {/* Create Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setShowModal(false)}>
          <div className="bg-surface-900 border border-slate-700 rounded-2xl shadow-2xl w-full max-w-lg mx-4 p-6" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-bold text-white mb-4">新增资产</h3>
            <div className="space-y-4">
              <div><label className="block text-xs text-slate-400 mb-1">资产名称 *</label>
                <input value={form.name} onChange={e => setForm({...form, name: e.target.value})} placeholder="如：用户服务 API、支付网关" className="w-full bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-primary-500 outline-none" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div><label className="block text-xs text-slate-400 mb-1">类型</label>
                  <select value={form.asset_type} onChange={e => setForm({...form, asset_type: e.target.value})} className="w-full bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white outline-none">
                    {Object.entries(TYPE_LABELS).map(([k,v]) => <option key={k} value={k}>{v}</option>)}
                  </select></div>
                <div><label className="block text-xs text-slate-400 mb-1">环境</label>
                  <select value={form.environment} onChange={e => setForm({...form, environment: e.target.value})} className="w-full bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white outline-none">
                    {Object.entries(ENV_LABELS).map(([k,v]) => <option key={k} value={k}>{v}</option>)}
                  </select></div>
              </div>
              <div><label className="block text-xs text-slate-400 mb-1">技术栈（逗号分隔）</label>
                <input value={form.tech_stack.join(',')} onChange={e => setForm({...form, tech_stack: e.target.value.split(',').map(s=>s.trim()).filter(Boolean)})} placeholder="Python, Flask, PostgreSQL, Redis" className="w-full bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white font-mono focus:border-primary-500 outline-none" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div><label className="block text-xs text-slate-400 mb-1">负责人</label>
                  <input value={form.owner} onChange={e => setForm({...form, owner: e.target.value})} placeholder="姓名或团队" className="w-full bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-primary-500 outline-none" /></div>
                <div><label className="block text-xs text-slate-400 mb-1">邮箱</label>
                  <input value={form.owner_email} onChange={e => setForm({...form, owner_email: e.target.value})} placeholder="" className="w-full bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-primary-500 outline-none" /></div>
              </div>
              <div><label className="block text-xs text-slate-400 mb-1">描述</label>
                <textarea value={form.description} onChange={e => setForm({...form, description: e.target.value})} rows={2} placeholder="简要描述该资产的用途和范围" className="w-full bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-primary-500 outline-none resize-none" />
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-slate-700/50">
              <button onClick={() => setShowModal(false)} className="px-4 py-2 text-sm text-slate-400 hover:text-white transition-colors">取消</button>
              <button onClick={handleCreate} disabled={!form.name.trim()} className="px-4 py-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-40 rounded-lg text-sm font-medium text-white transition-colors">创建</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
