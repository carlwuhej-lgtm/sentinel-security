import { useState, useEffect } from 'react'
import api from '../api/client'

interface Rule {
  id: number; name: string; rule_type: string; category: string
  pattern: string; severity_filter: string[]; description: string
  enabled: boolean; scope: string; project_id: number | null
  created_by: number | null; created_at: string; updated_at: string
}

const TYPE_LABELS: Record<string, string> = { custom_scan: '自定义扫描规则', ignore: '忽略/白名单' }
const TYPE_COLORS: Record<string, string> = { custom_scan: 'bg-blue-500/15 text-blue-400 border-blue-500/20', ignore: 'bg-amber-500/15 text-amber-400 border-amber-500/20' }
const CAT_LABELS: Record<string, string> = { sast: 'SAST', sca: 'SCA', secret: '密钥', dast: 'DAST', generic: '通用' }
const SEV_OPTIONS = ['critical', 'high', 'medium', 'low']
const SEV_LABELS: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危' }

const PAGE_SIZE = 10

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([])
  const [loading, setLoading] = useState(true)
  const [filterType, setFilterType] = useState('')
  const [filterCat, setFilterCat] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [page, setPage] = useState(1)
  const [editRule, setEditRule] = useState<Rule | null>(null)
  const [form, setForm] = useState({ name: '', rule_type: 'custom_scan', category: 'generic', pattern: '', description: '', enabled: true, scope: 'global', severity_filter: SEV_OPTIONS })

  useEffect(() => { loadRules() }, [filterType, filterCat])

  const loadRules = async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = {}
      if (filterType) params.type = filterType
      if (filterCat) params.category = filterCat
      const res = await api.get('/rules', { params })
      setRules(res.data.items || [])
    } catch {}
    setLoading(false)
  }

  const totalPages = Math.max(1, Math.ceil(rules.length / PAGE_SIZE))
  const pagedRules = rules.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  // Reset page when filters change
  useEffect(() => { setPage(1) }, [filterType, filterCat])

  const openCreate = () => {
    setEditRule(null); setForm({ name: '', rule_type: 'custom_scan', category: 'generic', pattern: '', description: '', enabled: true, scope: 'global', severity_filter: [...SEV_OPTIONS] }); setShowModal(true)
  }

  const openEdit = (r: Rule) => {
    setEditRule(r); setForm({
      name: r.name, rule_type: r.rule_type, category: r.category,
      pattern: r.pattern, description: r.description, enabled: r.enabled,
      scope: r.scope, severity_filter: Array.isArray(r.severity_filter) ? r.severity_filter : SEV_OPTIONS,
    }); setShowModal(true)
  }

  const handleSave = async () => {
    if (!form.name.trim()) return
    try {
      if (editRule) {
        await api.put(`/rules/${editRule.id}`, form)
      } else {
        await api.post('/rules', form)
      }
      setShowModal(false); loadRules()
    } catch {}
  }

  const toggleEnable = async (r: Rule) => {
    try {
      await api.post(`/rules/${r.id}/toggle`)
      loadRules()
    } catch {}
  }

  const deleteRule = async (id: number) => {
    if (!confirm('确定删除该规则？')) return
    try { await api.delete(`/rules/${id}`); loadRules() } catch {}
  }

  const toggleSev = (sev: string) => {
    setForm(prev => ({
      ...prev,
      severity_filter: prev.severity_filter.includes(sev)
        ? prev.severity_filter.filter(s => s !== sev)
        : [...prev.severity_filter, sev]
    }))
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">规则管理</h1>
          <p className="page-subtitle">自定义扫描规则、忽略白名单、门禁策略配置</p>
        </div>
        <button onClick={openCreate} className="btn-primary text-xs">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 4v16m8-8H4"/></svg>
          新建规则
        </button>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: '总规则数', value: rules.length, color: 'text-white' },
          { label: '已启用', value: rules.filter(r => r.enabled).length, color: 'text-green-400' },
          { label: '自定义扫描', value: rules.filter(r => r.rule_type === 'custom_scan').length, color: 'text-blue-400' },
          { label: '忽略/白名单', value: rules.filter(r => r.rule_type === 'ignore').length, color: 'text-amber-400' },
        ].map(s => (
          <div key={s.label} className="bg-surface-800/50 border border-slate-700/50 rounded-xl p-4">
            <div className={`text-2xl font-bold tabular-nums ${s.color}`}>{s.value}</div>
            <div className="text-xs text-slate-400 mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <select value={filterType} onChange={e => setFilterType(e.target.value)} className="bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300 focus:border-primary-500 focus:outline-none">
          <option value="">全部类型</option>
          <option value="custom_scan">自定义扫描</option>
          <option value="ignore">忽略/白名单</option>
        </select>
        <select value={filterCat} onChange={e => setFilterCat(e.target.value)} className="bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300 focus:border-primary-500 focus:outline-none">
          <option value="">全部分类</option>
          {Object.entries(CAT_LABELS).map(([k,v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <span className="text-xs text-slate-500 ml-auto">{rules.length} 条规则</span>
      </div>

      {/* Table */}
      <div className="bg-surface-800/30 border border-slate-700/50 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead><tr className="bg-surface-800/80 text-left text-xs text-slate-400 uppercase tracking-wider">
            <th className="px-4 py-3">规则名称</th><th className="px-4 py-3">类型</th><th className="px-4 py-3">分类</th>
            <th className="px-4 py-3">适用严重度</th><th className="px-4 py-3">范围</th><th className="px-4 py-3">状态</th><th className="px-4 py-3">操作</th>
          </tr></thead>
          <tbody className="divide-y divide-slate-700/40">
            {loading ? (
              <tr><td colSpan={7} className="px-4 py-12 text-center text-slate-500">加载中...</td></tr>
            ) : rules.length === 0 ? (
              <tr><td colSpan={7} className="px-4 py-12 text-center text-slate-500">暂无规则，点击"新建规则"开始配置</td></tr>
            ) : pagedRules.map(rule => (
              <tr key={rule.id} className="hover:bg-surface-800/30 transition-colors">
                <td className="px-4 py-3">
                  <div className="font-medium text-white">{rule.name}</div>
                  <div className="text-xs text-slate-500 truncate max-w-xs mt-0.5">{rule.description || '-'}</div>
                </td>
                <td className="px-4 py-3">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium border ${TYPE_COLORS[rule.rule_type] || ''}`}>
                    {TYPE_LABELS[rule.rule_type] || rule.rule_type}
                  </span>
                </td>
                <td className="px-4 py-3 text-slate-300">{CAT_LABELS[rule.category] || rule.category}</td>
                <td className="px-4 py-3">
                  {(Array.isArray(rule.severity_filter) ? rule.severity_filter : []).map(s =>
                    <span key={s} className={`inline-block mr-1 mb-1 px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                      s === 'critical' ? 'bg-red-500/20 text-red-400' :
                      s === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      s === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-slate-500/20 text-slate-400'
                    }`}>{SEV_LABELS[s]}</span>
                  )}
                </td>
                <td className="px-4 py-3 text-slate-400 text-xs">{rule.scope}</td>
                <td className="px-4 py-3">
                  <button onClick={() => toggleEnable(rule)} className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${rule.enabled ? 'bg-green-600' : 'bg-slate-600'}`}>
                    <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${rule.enabled ? 'translate-x-5' : 'translate-x-1'}`} />
                  </button>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <button onClick={() => openEdit(rule)} className="text-slate-400 hover:text-primary-400 p-1" title="编辑"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
                    <button onClick={() => deleteRule(rule.id)} className="text-slate-400 hover:text-red-400 p-1" title="删除"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {rules.length > PAGE_SIZE && (
        <div className="flex items-center justify-between pt-3 text-xs text-slate-400">
          <span>共 {rules.length} 条</span>
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

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setShowModal(false)}>
          <div className="bg-surface-900 border border-slate-700 rounded-2xl shadow-2xl w-full max-w-lg mx-4 p-6" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-bold text-white mb-4">{editRule ? '编辑规则' : '新建规则'}</h3>

            <div className="space-y-4">
              <div><label className="block text-xs text-slate-400 mb-1">名称 *</label>
                <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="如：禁止使用 eval()" className="w-full bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-primary-500 focus:outline-none" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div><label className="block text-xs text-slate-400 mb-1">类型</label>
                  <select value={form.rule_type} onChange={e => setForm({ ...form, rule_type: e.target.value })} className="w-full bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-primary-500 outline-none">
                    <option value="custom_scan">自定义扫描规则</option>
                    <option value="ignore">忽略 / 白名单</option>
                  </select></div>
                <div><label className="block text-xs text-slate-400 mb-1">分类</label>
                  <select value={form.category} onChange={e => setForm({ ...form, category: e.target.value })} className="w-full bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-primary-500 outline-none">
                    {Object.entries(CAT_LABELS).map(([k,v]) => <option key={k} value={k}>{v}</option>)}
                  </select></div>
              </div>
              <div><label className="block text-xs text-slate-400 mb-1">适用严重度（多选）</label>
                <div className="flex gap-2 flex-wrap">
                  {SEV_OPTIONS.map(sev => (
                    <button key={sev} type="button" onClick={() => toggleSev(sev)}
                      className={`px-3 py-1 rounded-md text-xs font-medium border transition-colors ${
                        form.severity_filter.includes(sev)
                          ? sev === 'critical' ? 'bg-red-500/20 border-red-500/40 text-red-300'
                            : sev === 'high' ? 'bg-orange-500/20 border-orange-500/40 text-orange-300'
                            : sev === 'medium' ? 'bg-yellow-500/20 border-yellow-500/40 text-yellow-300'
                            : 'bg-slate-500/20 border-slate-500/40 text-slate-300'
                          : 'border-slate-700 text-slate-500 hover:border-slate-600'
                      }`}>{SEV_LABELS[sev]}</button>
                  ))}
                </div>
              </div>
              <div><label className="block text-xs text-slate-400 mb-1">模式 / 规则表达式</label>
                <input value={form.pattern} onChange={e => setForm({ ...form, pattern: e.target.value })} placeholder='如：regex 或 Semgrep YAML 引用路径' className="w-full bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white font-mono focus:border-primary-500 outline-none" />
              </div>
              <div><label className="block text-xs text-slate-400 mb-1">说明</label>
                <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} rows={2} placeholder="描述这条规则的用途和适用场景" className="w-full bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-primary-500 outline-none resize-none" />
              </div>
              <div className="flex items-center gap-4">
                <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
                  <input type="checkbox" checked={form.enabled} onChange={e => setForm({...form, enabled: e.target.checked})} className="rounded border-slate-600" />
                  启用
                </label>
                <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
                  <input type="radio" checked={form.scope === 'global'} onChange={() => setForm({...form, scope:'global'})} className="accent-primary-500" /> 全局
                </label>
                <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
                  <input type="radio" checked={form.scope === 'project'} onChange={() => setForm({...form, scope:'project'})} className="accent-primary-500" /> 项目级
                </label>
              </div>
            </div>

            <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-slate-700/50">
              <button onClick={() => setShowModal(false)} className="px-4 py-2 text-sm text-slate-400 hover:text-white transition-colors">取消</button>
              <button onClick={handleSave} disabled={!form.name.trim()} className="px-4 py-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-40 rounded-lg text-sm font-medium text-white transition-colors">保存</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
