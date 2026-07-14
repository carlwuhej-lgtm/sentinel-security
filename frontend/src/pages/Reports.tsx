import { useState, useEffect } from 'react'
import api from '../api/client'

interface Report {
  id: number; report_type: string; title: string; format_type: string
  status: string; file_size: number; created_at: string
  generator_name?: string
}

const REPORT_TYPES = [
  { value: 'security_summary', label: '安全总览报告', desc: '项目概要、漏洞分布、TOP 高危' },
  { value: 'vuln_detail', label: '漏洞明细报告', desc: '每条漏洞的完整信息列表' },
  { value: 'sla_report', label: 'SLA 合规报告', desc: '超时/即将到期/正常/修复率统计' },
  { value: 'trend', label: '趋势分析报告', desc: '月度扫描与漏洞发现趋势' },
  { value: 'compliance', label: '合规检查清单', desc: 'OWASP ASVS 简化版合规检查项' },
]

const FORMAT_OPTIONS = [
  { value: 'json', label: 'JSON（结构化数据）' },
  { value: 'markdown', label: 'Markdown（可读报告）' },
  { value: 'csv', label: 'CSV（表格导出）' },
]

const TYPE_LABELS: Record<string, string> = {
  security_summary: '安全总览', vuln_detail: '漏洞明细',
  sla_report: 'SLA 合规', trend: '趋势分析', compliance: '合规检查',
}
const TYPE_COLORS: Record<string, string> = {
  security_summary: 'bg-blue-500/15 text-blue-400 border-blue-500/20',
  vuln_detail: 'bg-red-500/15 text-red-400 border-red-500/20',
  sla_report: 'bg-orange-500/15 text-orange-400 border-orange-500/20',
  trend: 'bg-purple-500/15 text-purple-400 border-purple-500/20',
  compliance: 'bg-green-500/15 text-green-400 border-green-500/20',
}

const PAGE_SIZE = 10

function Pagination({ page, totalPages, total, onChange }: {
  page: number; totalPages: number; total: number; onChange: (p: number) => void
}) {
  return (
    <div className="flex items-center justify-between pt-3 text-xs text-slate-400">
      <span>共 {total} 条</span>
      <div className="flex items-center gap-1">
        <button disabled={page <= 1} onClick={() => onChange(page - 1)}
          className="px-2 py-1 rounded bg-surface-800 border border-slate-700 disabled:opacity-30 hover:border-slate-600">
          上一页
        </button>
        {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
          <button key={p} onClick={() => onChange(p)}
            className={`px-2.5 py-1 rounded text-xs ${p === page
              ? 'bg-primary-600 text-white' : 'bg-surface-800 border border-slate-700 hover:border-slate-600'}`}>
            {p}
          </button>
        ))}
        <button disabled={page >= totalPages} onClick={() => onChange(page + 1)}
          className="px-2 py-1 rounded bg-surface-800 border border-slate-700 disabled:opacity-30 hover:border-slate-600">
          下一页
        </button>
      </div>
    </div>
  )
}

export default function Reports() {
  const [reports, setReports] = useState<Report[]>([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [filterType, setFilterType] = useState('')
  const [showGenerate, setShowGenerate] = useState(true)
  const [selectedReport, setSelectedReport] = useState<Report | null>(null)
  const [reportDetail, setReportDetail] = useState<any>(null)
  const [detailLoading, setDetailLoading] = useState(false)

  // Pagination
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [total, setTotal] = useState(0)

  // Generate form
  const [genForm, setGenForm] = useState({
    report_type: 'security_summary',
    format_type: 'json',
    title: '',
  })

  useEffect(() => { loadReports() }, [filterType])

  const loadReports = async () => {
    setLoading(true)
    try {
      const params: Record<string, string | number> = { limit: 500, type: filterType }
      const res = await api.get('/reports', { params })
      const allItems = res.data?.items || []
      setTotal(allItems.length)
      setTotalPages(Math.max(1, Math.ceil(allItems.length / PAGE_SIZE)))
      const start = (page - 1) * PAGE_SIZE
      setReports(allItems.slice(start, start + PAGE_SIZE))
    } catch { setReports([]) }
    setLoading(false)
  }

  useEffect(() => { loadReports() }, [page])

  const handleGenerate = async () => {
    setGenerating(true)
    try {
      const res = await api.post('/reports/generate', genForm)
      await loadReports()
      alert('报告已生成：' + (res.data.title || res.data.report_type))
      setShowGenerate(false)
    } catch (e) {
      console.error(e)
      alert('生成失败，请检查参数')
    }
    setGenerating(false)
  }

  const openDetail = async (r: Report) => {
    setSelectedReport(r)
    setDetailLoading(true)
    setReportDetail(null)
    try {
      const res = await api.get(`/reports/${r.id}`)
      const detail = res.data
      // Parse content_json if string
      if (typeof detail.content_json === 'string') {
        try { detail.content_json = JSON.parse(detail.content_json) } catch {}
      }
      setReportDetail(detail)
    } catch { setReportDetail(null) }
    setDetailLoading(false)
  }

  const downloadFile = async (r: Report, fmt: string, isPdf: boolean = false, isHtml: boolean = false) => {
    try {
      const url = isPdf
        ? `/reports/${r.id}/pdf`
        : isHtml
          ? `/reports/${r.id}/html`
          : `/reports/${r.id}/download?format=${fmt}`
      const resp = await api.get(url, { responseType: 'blob' })
      const blob = resp.data
      const objUrl = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = objUrl
      const extMap: Record<string, string> = { json: '.json', csv: '.csv', markdown: '.md', pdf: '.pdf', html: '.html' }
      const ext = isPdf ? 'pdf' : isHtml ? 'html' : (fmt || 'json')
      a.download = `sentinel-report-${r.report_type}-${(r.created_at || '').slice(0, 10)}${extMap[ext] || '.json'}`
      a.click()
      URL.revokeObjectURL(objUrl)
    } catch (err: any) {
      const msg = err?.response?.data
      if (msg instanceof Blob) {
        try {
          const text = await msg.text()
          const parsed = JSON.parse(text)
          alert(parsed.error || parsed.message || '下载失败')
        } catch { alert('下载失败') }
      } else {
        alert('下载失败: ' + (err?.message || '未知错误'))
      }
    }
  }

  const deleteReport = async (id: number) => {
    if (!confirm('确定删除该报告？')) return
    try { await api.delete(`/reports/${id}`); loadReports() } catch {}
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">报告中心</h1>
          <p className="page-subtitle">一键生成安全报告，支持 JSON / Markdown / CSV / PDF 导出</p>
        </div>
        <button onClick={() => setShowGenerate(!showGenerate)} className={showGenerate ? 'btn-secondary text-xs' : 'btn-primary text-xs'}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 4v16m8-8H4"/></svg>
          {showGenerate ? '收起' : '生成新报告'}
        </button>
      </div>

      {/* Quick stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: '总报告数', value: total, color: 'text-white' },
          { label: '安全总览', value: reports.filter(r => r.report_type === 'security_summary').length, color: 'text-blue-400' },
          { label: 'SLA 报告', value: reports.filter(r => r.report_type === 'sla_report').length, color: 'text-orange-400' },
          { label: '漏洞明细', value: reports.filter(r => r.report_type === 'vuln_detail').length, color: 'text-red-400' },
        ].map(s => (
          <div key={s.label} className="bg-surface-800/50 border border-slate-700/50 rounded-xl p-4">
            <div className={`text-2xl font-bold tabular-nums ${s.color}`}>{s.value}</div>
            <div className="text-xs text-slate-400 mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Generate Panel */}
      {showGenerate && (
        <div className="bg-surface-800/50 border border-primary-500/30 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-white mb-4">配置报告</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label className="block text-xs text-slate-400 uppercase tracking-wider">报告类型</label>
              <div className="space-y-2">
                {REPORT_TYPES.map(rt => (
                  <button key={rt.value} type="button"
                    onClick={() => setGenForm({...genForm, report_type: rt.value})}
                    className={`w-full text-left px-4 py-3 rounded-lg border transition-all ${
                      genForm.report_type === rt.value
                        ? 'border-primary-500 bg-primary-500/10 shadow-sm'
                        : 'border-slate-700 bg-surface-900/50 hover:border-slate-600'
                    }`}>
                    <div className="flex items-center gap-3">
                      <span className={`w-3 h-3 rounded-full ${genForm.report_type === rt.value ? 'bg-primary-500' : 'bg-slate-600'}`} />
                      <div>
                        <div className={`text-sm font-medium ${genForm.report_type === rt.value ? 'text-white' : 'text-slate-300'}`}>{rt.label}</div>
                        <div className="text-xs text-slate-500 mt-0.5">{rt.desc}</div>
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-4">
              <div><label className="block text-xs text-slate-400 mb-1.5 uppercase tracking-wider">输出格式</label>
                <div className="space-y-2">
                  {FORMAT_OPTIONS.map(fmt => (
                    <label key={fmt.value} className={`flex items-center gap-3 px-4 py-2.5 rounded-lg border cursor-pointer transition-all ${
                      genForm.format_type === fmt.value
                        ? 'border-primary-500 bg-primary-500/10' : 'border-slate-700 bg-surface-900/50 hover:border-slate-600'
                    }`}>
                      <input type="radio" checked={genForm.format_type === fmt.value} onChange={() => setGenForm({...genForm, format_type: fmt.value})} className="accent-primary-500" />
                      <span className={`text-sm ${genForm.format_type === fmt.value ? 'text-white' : 'text-slate-300'}`}>{fmt.label}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div><label className="block text-xs text-slate-400 mb-1.5">自定义标题（可选）</label>
                <input value={genForm.title} onChange={e => setGenForm({...genForm, title: e.target.value})}
                  placeholder="如：2026年Q2安全审计报告" className="w-full bg-surface-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-primary-500 outline-none placeholder:text-slate-500" />
              </div>

              <button onClick={handleGenerate} disabled={generating}
                className="w-full py-3 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-sm font-semibold text-white transition-colors flex items-center justify-center gap-2">
                {generating ? (
                  <>
                    <svg className="animate-spin" width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" opacity="0.25"/><path d="M4 12a8 8 0 018-8" stroke="currentColor" strokeWidth="3" strokeLinecap="round"/></svg>
                    正在生成...
                  </>
                ) : (
                  <>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                    生成并下载报告
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Filter + Pagination top */}
      <div className="flex items-center gap-3">
        <select value={filterType} onChange={e => { setFilterType(e.target.value); setPage(1) }}
          className="bg-surface-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-300 focus:border-primary-500 outline-none">
          <option value="">全部类型</option>
          {REPORT_TYPES.map(rt => <option key={rt.value} value={rt.value}>{rt.label}</option>)}
        </select>
        <span className="text-xs text-slate-500 ml-auto">{total} 条记录 | 第 {page}/{totalPages} 页</span>
      </div>

      {/* Reports table */}
      <div className="bg-surface-800/30 border border-slate-700/50 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead><tr className="bg-surface-800/80 text-left text-xs text-slate-400 uppercase tracking-wider">
            <th className="px-4 py-3">报告标题</th><th className="px-4 py-3">类型</th><th className="px-4 py-3">格式</th>
            <th className="px-4 py-3">大小</th><th className="px-4 py-3">创建时间</th><th className="px-4 py-3 w-64">操作</th>
          </tr></thead>
          <tbody className="divide-y divide-slate-700/40">
            {loading ? (<tr><td colSpan={6} className="px-4 py-12 text-center text-slate-500">加载中...</td></tr>) :
             reports.length === 0 ? (<tr><td colSpan={6} className="px-4 py-12 text-center text-slate-500">暂无报告记录，点击上方按钮生成第一份报告</td></tr>) :
             reports.map(rep => (
               <tr key={rep.id} className="hover:bg-surface-800/30 transition-colors">
                 <td className="px-4 py-3">
                   <div className="font-medium text-white">{rep.title || TYPE_LABELS[rep.report_type] || rep.report_type}</div>
                 </td>
                 <td className="px-4 py-3">
                   <span className={`inline-flex px-2 py-0.5 rounded-md text-[11px] font-medium border ${TYPE_COLORS[rep.report_type] || ''}`}>
                     {TYPE_LABELS[rep.report_type] || rep.report_type}
                   </span>
                 </td>
                 <td className="px-4 py-3 text-slate-300 uppercase text-xs">{rep.format_type}</td>
                 <td className="px-4 py-3 text-slate-400 tabular-nums">{rep.file_size > 1024 ? `${(rep.file_size/1024).toFixed(1)}KB` : `${rep.file_size}B`}</td>
                 <td className="px-4 py-3 text-slate-500 text-xs">{rep.created_at || '-'}</td>
                 <td className="px-4 py-3">
                   <div className="flex items-center gap-1.5 flex-wrap">
                    <button onClick={() => openDetail(rep)} className="px-2 py-1 text-xs rounded bg-surface-800 text-slate-300 hover:text-white hover:bg-surface-700 transition-colors">查看</button>
                    <button onClick={() => downloadFile(rep, '', false, true)} className="px-2 py-1 text-xs rounded bg-cyan-600/25 text-cyan-300 font-semibold hover:bg-cyan-600/40 transition-colors ring-1 ring-cyan-500/40">HTML</button>
                    <button onClick={() => downloadFile(rep, rep.format_type === 'json' ? 'json' : rep.format_type)} className="px-2 py-1 text-xs rounded bg-green-600/20 text-green-400 hover:bg-green-600/30 transition-colors">JSON</button>
                    <button onClick={() => downloadFile(rep, 'markdown')} className="px-2 py-1 text-xs rounded bg-purple-600/20 text-purple-400 hover:bg-purple-600/30 transition-colors">MD</button>
                    <button onClick={() => downloadFile(rep, 'csv')} className="px-2 py-1 text-xs rounded bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors">CSV</button>
                    <button onClick={() => downloadFile(rep, '', true)} className="px-2 py-1 text-xs rounded bg-red-600/20 text-red-400 hover:bg-red-600/30 transition-colors">PDF</button>
                    <button onClick={() => deleteReport(rep.id)} className="px-2 py-1 text-xs rounded bg-slate-600/20 text-slate-400 hover:text-red-400 transition-colors">删除</button>
                   </div>
                 </td>
               </tr>
             ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <Pagination page={page} totalPages={totalPages} total={total} onChange={setPage} />

      {/* Detail Modal */}
      {selectedReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => { setSelectedReport(null); setReportDetail(null) }}>
          <div className="bg-surface-900 border border-slate-700 rounded-2xl shadow-2xl w-full max-w-5xl mx-4 max-h-[85vh] overflow-y-auto p-6" onClick={e => e.stopPropagation()}>
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-lg font-bold text-white">{selectedReport.title || TYPE_LABELS[selectedReport.report_type]}</h3>
                <div className="text-xs text-slate-400 mt-1">
                  {TYPE_LABELS[selectedReport.report_type]} · {selectedReport.format_type.toUpperCase()} · {selectedReport.created_at}
                </div>
              </div>
              <button onClick={() => { setSelectedReport(null); setReportDetail(null) }} className="text-slate-500 hover:text-white">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 18L18 6M6 6l12 12"/></svg>
              </button>
            </div>

            {detailLoading ? (
              <div className="text-center text-slate-500 py-8">加载中...</div>
            ) : !reportDetail ? (
              <div className="text-center text-slate-500 py-8">加载失败</div>
            ) : (() => {
              const content = reportDetail.content_json || reportDetail
              if (!content || typeof content !== 'object') return <div className="text-center text-slate-500 py-8">报告内容为空</div>

              return (
                <div className="space-y-4">
                    {/* Summary */}
                  {content.summary && typeof content.summary === 'object' && (
                    <div className="grid grid-cols-5 gap-3">
                      {Object.entries(content.summary).map(([k, v]: [string, any]) => (
                        <div key={k} className="bg-surface-800/50 rounded-lg p-3 text-center">
                          <div className="text-lg font-bold tabular-nums text-white">{typeof v === 'number' ? v : String(v)}</div>
                          <div className="text-[10px] text-slate-500 mt-1">{k.replace(/_/g, ' ')}</div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Risk Assessment */}
                  {content.risk_assessment && typeof content.risk_assessment === 'object' && (
                    <div className={`rounded-lg p-4 border ${
                      content.risk_assessment.level === '严重' ? 'bg-red-500/10 border-red-500/30 text-red-400' :
                      content.risk_assessment.level === '高' ? 'bg-orange-500/10 border-orange-500/30 text-orange-400' :
                      content.risk_assessment.level === '中' ? 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400' :
                      'bg-green-500/10 border-green-500/30 text-green-400'
                    }`}>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-lg font-bold">风险等级: {content.risk_assessment.level}</span>
                        {content.risk_assessment.critical_open > 0 && <span className="text-xs">严重开放: {content.risk_assessment.critical_open}</span>}
                        {content.risk_assessment.high_open > 0 && <span className="text-xs">高危开放: {content.risk_assessment.high_open}</span>}
                      </div>
                      <div className="text-xs opacity-80">{content.risk_assessment.recommendation}</div>
                    </div>
                  )}

                  {/* Fix Rate */}
                  {content.fix_rate && typeof content.fix_rate === 'object' && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">修复率分析</h4>
                      <div className="grid grid-cols-4 gap-3">
                        {Object.entries(content.fix_rate).map(([k, v]: [string, any]) => (
                          <div key={k} className="bg-surface-800/50 rounded-lg p-3 text-center">
                            <div className="text-lg font-bold tabular-nums text-primary-400">{v}%</div>
                            <div className="text-[10px] text-slate-500 mt-1">{k}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Tool Coverage */}
                  {content.tool_coverage && typeof content.tool_coverage === 'object' && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">工具覆盖情况</h4>
                      <div className="grid grid-cols-5 gap-3">
                        {Object.entries(content.tool_coverage).map(([k, v]: [string, any]) => (
                          <div key={k} className="bg-surface-800/50 rounded-lg p-3 text-center">
                            <div className="text-lg font-bold tabular-nums text-blue-400">{typeof v === 'number' ? v : String(v)}</div>
                            <div className="text-[10px] text-slate-500 mt-1">{k.replace(/_/g, ' ')}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Knowledge Base Stats */}
                  {content.knowledge_base_stats && typeof content.knowledge_base_stats === 'object' && content.knowledge_base_stats.total_articles > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">知识库统计</h4>
                      <div className="grid grid-cols-3 gap-3">
                        <div className="bg-surface-800/50 rounded-lg p-3 text-center">
                          <div className="text-lg font-bold tabular-nums text-green-400">{content.knowledge_base_stats.total_articles}</div>
                          <div className="text-[10px] text-slate-500 mt-1">总文章数</div>
                        </div>
                        <div className="bg-surface-800/50 rounded-lg p-3 text-center">
                          <div className="text-lg font-bold tabular-nums text-green-400">{content.knowledge_base_stats.categories}</div>
                          <div className="text-[10px] text-slate-500 mt-1">分类数</div>
                        </div>
                        <div className="bg-surface-800/50 rounded-lg p-3 text-center">
                          {content.knowledge_base_stats.by_category && Object.entries(content.knowledge_base_stats.by_category).slice(0,3).map(([k, v]: [string, any]) => (
                            <div key={k} className="text-xs text-slate-400">{k}: {v}</div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* CWE Distribution */}
                  {content.cwe_distribution && typeof content.cwe_distribution === 'object' && Object.keys(content.cwe_distribution).length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">Top CWE 类型分布</h4>
                      <div className="space-y-1">
                        {Object.entries(content.cwe_distribution).slice(0, 10).map(([cwe, count]: [string, any]) => (
                          <div key={cwe} className="flex items-center justify-between bg-surface-800/50 rounded-lg px-3 py-1.5 text-xs">
                            <span className="text-slate-300">{cwe}</span>
                            <span className="text-slate-400 tabular-nums font-semibold">{count}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* CVSS Distribution */}
                  {content.cvss_distribution && typeof content.cvss_distribution === 'object' && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">CVSS 分档统计</h4>
                      <div className="grid grid-cols-5 gap-2">
                        {Object.entries(content.cvss_distribution).map(([k, v]: [string, any]) => (
                          <div key={k} className="bg-surface-800/50 rounded-lg p-2 text-center">
                            <div className="text-sm font-bold tabular-nums text-purple-400">{v}</div>
                            <div className="text-[9px] text-slate-500 mt-0.5 leading-tight">{k}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Tool Source */}
                  {content.tool_source && typeof content.tool_source === 'object' && Object.keys(content.tool_source).length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">扫描工具来源</h4>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(content.tool_source).map(([tool, count]: [string, any]) => (
                          <span key={tool} className="px-2.5 py-1 rounded-lg bg-surface-800 border border-slate-700 text-xs text-slate-300">
                            {tool}: <span className="font-semibold text-blue-400">{count}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Affected Assets */}
                  {content.affected_assets && Array.isArray(content.affected_assets) && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">受影响资产</h4>
                      <div className="grid grid-cols-4 gap-3">
                        {content.affected_assets.map((a: any, i: number) => (
                          <div key={i} className="bg-surface-800/50 rounded-lg p-3 text-center">
                            <div className="text-sm font-semibold text-white truncate">{a.project}</div>
                            <div className="text-[10px] text-slate-500 mt-1">{a.file_count} 个文件</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Assignee Performance */}
                  {content.assignee_performance && Array.isArray(content.assignee_performance) && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">处理人 SLA 表现</h4>
                      <div className="max-h-48 overflow-y-auto">
                        <table className="w-full text-xs">
                          <thead><tr className="text-left text-slate-500">
                            <th className="py-1.5 px-2">处理人</th><th className="py-1.5 px-2">总数</th>
                            <th className="py-1.5 px-2">超时</th><th className="py-1.5 px-2">已修</th>
                            <th className="py-1.5 px-2">SLA率</th>
                          </tr></thead>
                          <tbody>
                            {content.assignee_performance.map((a: any, i: number) => (
                              <tr key={i} className="border-t border-slate-700/30">
                                <td className="py-1.5 px-2 text-slate-300">{a.assignee}</td>
                                <td className="py-1.5 px-2 tabular-nums">{a.total}</td>
                                <td className="py-1.5 px-2 text-red-400 tabular-nums">{a.breached}</td>
                                <td className="py-1.5 px-2 text-green-400 tabular-nums">{a.fixed}</td>
                                <td className="py-1.5 px-2 font-semibold tabular-nums" style={{color: a.sla_rate >= 80 ? '#4ade80' : a.sla_rate >= 50 ? '#fbbf24' : '#f87171'}}>{a.sla_rate}%</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* Avg Time to Fix */}
                  {content.avg_time_to_fix && typeof content.avg_time_to_fix === 'object' && (
                    <div className="grid grid-cols-3 gap-3">
                      <div className="bg-surface-800/50 rounded-lg p-3 text-center">
                        <div className="text-lg font-bold tabular-nums text-blue-400">{content.avg_time_to_fix.hours}</div>
                        <div className="text-[10px] text-slate-500">平均修复（小时）</div>
                      </div>
                      <div className="bg-surface-800/50 rounded-lg p-3 text-center">
                        <div className="text-lg font-bold tabular-nums text-primary-400">{content.avg_time_to_fix.days}</div>
                        <div className="text-[10px] text-slate-500">平均修复（天）</div>
                      </div>
                      <div className="bg-surface-800/50 rounded-lg p-3 text-center">
                        <div className="text-lg font-bold tabular-nums text-slate-400">{content.avg_time_to_fix.samples}</div>
                        <div className="text-[10px] text-slate-500">样本数</div>
                      </div>
                    </div>
                  )}

                  {/* Fix Rate Trend */}
                  {content.fix_rate_trend && Array.isArray(content.fix_rate_trend) && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">修复率趋势</h4>
                      <div className="flex items-end gap-1 h-32 bg-surface-800/30 rounded-lg p-3">
                        {(content.fix_rate_trend as any[]).map((m: any, i: number) => {
                          const h = Math.max((m.fix_rate || 0), 2)
                          return (
                            <div key={i} className="flex-1 flex flex-col items-center gap-1 group">
                              <div className="relative w-full flex justify-center">
                                <div className="absolute -top-5 bg-surface-950 text-[9px] text-green-400 px-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-10">{m.fix_rate}%</div>
                                <div className="w-full max-w-[28px] bg-green-500/60 hover:bg-green-500 rounded-t transition-colors" style={{ height: `${h}%` }} />
                              </div>
                              <span className="text-[8px] text-slate-500">{(m.month || '').slice(5)}</span>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {/* Tool Usage Trend */}
                  {content.tool_usage && typeof content.tool_usage === 'object' && Object.keys(content.tool_usage).length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">工具使用趋势</h4>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(content.tool_usage).map(([tool, data]: [string, any]) => (
                          <span key={tool} className="px-2 py-1 rounded bg-surface-800 border border-slate-700 text-xs text-slate-300">
                            <span className="font-semibold text-purple-400">{tool}</span>: {Array.isArray(data) ? data.length + '个月' : ''}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Top vulns */}
                  {content.top_vulnerabilities && Array.isArray(content.top_vulnerabilities) && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">TOP 高危漏洞预览</h4>
                      <div className="max-h-64 overflow-y-auto space-y-1">
                        {content.top_vulnerabilities.slice(0, 10).map((v: any, i: number) => (
                          <div key={i} className="flex items-center justify-between bg-surface-800/50 rounded-lg px-3 py-2 text-xs">
                            <div className="truncate flex-1 mr-3">
                              <span className={`font-semibold ${v.severity === 'critical' ? 'text-red-400' : v.severity === 'high' ? 'text-orange-400' : 'text-slate-300'}`}>[{v.severity?.toUpperCase()}]</span> {v.title}
                              {v.cve_id && <span className="ml-2 text-slate-500">{v.cve_id}</span>}
                              {v.sla_breached && <span className="ml-2 text-red-400 font-semibold">SLA超时</span>}
                            </div>
                            <span className="text-slate-500 shrink-0">{v.file_path?.split('/').pop()}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Items table for vuln_detail */}
                  {content.items && Array.isArray(content.items) && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">漏洞明细 ({content.total || content.items.length} 条)</h4>
                      <div className="max-h-64 overflow-y-auto space-y-1">
                        {content.items.slice(0, 15).map((v: any, i: number) => (
                          <div key={i} className="flex items-center justify-between bg-surface-800/50 rounded-lg px-3 py-2 text-xs">
                            <div className="truncate flex-1 mr-3">
                              <span className={`font-semibold ${v.severity === 'critical'?'text-red-400':v.severity==='high'?'text-orange-400':'text-slate-300'}`}>{v.title}</span>
                            </div>
                            <span className="text-slate-500 shrink-0">{v.file_path?.split('/').pop()}:{v.line}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* SLA sections */}
                  {content.breached && (
                    <div className="grid grid-cols-4 gap-3">
                      {[
                        { title: '已超时 SLA', data: content.breached, cls: 'text-red-400' },
                        { title: '即将到期 <24h', data: content.urgent, cls: 'text-orange-400' },
                        { title: '正常跟踪', data: content.on_track, cls: 'text-green-400' },
                        { title: '已关闭/修复', data: content.closed_or_fixed, cls: 'text-blue-400' },
                      ].filter(d => d.data).map(({ title, data, cls }) => (
                        <div key={title} className="bg-surface-800/50 rounded-lg p-3">
                          <div className="text-[10px] text-slate-500">{title}</div>
                          <div className={`text-lg font-bold tabular-nums ${cls}`}>{data?.count ?? 0}</div>
                        </div>
                      ))}
                    </div>
                  )}
                  {content.summary && content.summary.compliance_rate !== undefined && (
                    <div className="bg-surface-800/50 rounded-lg p-3 text-center">
                      <div className="text-[10px] text-slate-500">SLA 合规率</div>
                      <div className="text-2xl font-bold tabular-nums text-primary-400">{content.summary.compliance_rate}%</div>
                    </div>
                  )}

                  {/* Trend chart */}
                  {content.monthly_scans && Array.isArray(content.monthly_scans) && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">月度扫描趋势</h4>
                      <div className="flex items-end gap-1 h-32 bg-surface-800/30 rounded-lg p-3">
                        {(content.monthly_scans as any[]).map((m: any, i: number) => {
                          const maxScan = Math.max(...(content.monthly_scans as any[]).map((x: any) => x.scan_count || 0), 1)
                          const h = ((m.scan_count || 0) / maxScan) * 100
                          return (
                            <div key={i} className="flex-1 flex flex-col items-center gap-1 group">
                              <div className="relative w-full flex justify-center">
                                <div className="absolute -top-5 bg-surface-950 text-[9px] text-slate-300 px-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-10">{m.scan_count} 次</div>
                                <div className="w-full max-w-[28px] bg-primary-500/60 hover:bg-primary-500 rounded-t transition-colors" style={{ height: `${Math.max(h, 2)}%` }} />
                              </div>
                              <span className="text-[8px] text-slate-500">{(m.month || '').slice(5)}</span>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {/* Compliance overview */}
                  {content.summary && content.summary.total_checks !== undefined && (
                    <div className="grid grid-cols-4 gap-3">
                      <div className="bg-surface-800/50 rounded-lg p-3 text-center">
                        <div className="text-lg font-bold tabular-nums text-white">{content.summary.total_checks}</div>
                        <div className="text-[10px] text-slate-500">检查项</div>
                      </div>
                      <div className="bg-surface-800/50 rounded-lg p-3 text-center">
                        <div className="text-lg font-bold tabular-nums text-green-400">{content.summary.passed}</div>
                        <div className="text-[10px] text-slate-500">已通过</div>
                      </div>
                      <div className="bg-surface-800/50 rounded-lg p-3 text-center">
                        <div className="text-lg font-bold tabular-nums text-yellow-400">{content.summary.warning}</div>
                        <div className="text-[10px] text-slate-500">需关注</div>
                      </div>
                      <div className="bg-surface-800/50 rounded-lg p-3 text-center">
                        <div className="text-lg font-bold tabular-nums text-red-400">{content.summary.failed}</div>
                        <div className="text-[10px] text-slate-500">未通过</div>
                      </div>
                    </div>
                  )}
                  {content.summary && content.summary.weighted_score !== undefined && (
                    <div className="bg-surface-800/50 rounded-lg p-4 text-center">
                      <div className="text-2xl font-bold tabular-nums" style={{color: content.summary.weighted_score >= 90 ? '#4ade80' : content.summary.weighted_score >= 75 ? '#a3e635' : content.summary.weighted_score >= 60 ? '#fbbf24' : '#f87171'}}>
                        {content.summary.weighted_score}分 ({content.summary.grade})
                      </div>
                      <div className="text-[10px] text-slate-500 mt-1">加权合规评分</div>
                    </div>
                  )}

                  {/* Compliance categories */}
                  {content.categories && Array.isArray(content.categories) && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">分类汇总</h4>
                      <div className="grid grid-cols-3 gap-3">
                        {content.categories.map((c: any, i: number) => (
                          <div key={i} className="bg-surface-800/50 rounded-lg p-3">
                            <div className="font-medium text-sm text-white">{c.name}</div>
                            <div className="flex items-center gap-2 mt-1 text-[10px]">
                              <span className="text-green-400">{c.pass || c.passed || 0}通过</span>
                              {(c.warning || 0) > 0 && <span className="text-yellow-400">{c.warning || 0}关注</span>}
                              {(c.fail || c.failed || 0) > 0 && <span className="text-red-400">{c.fail || c.failed || 0}失败</span>}
                            </div>
                            <div className="text-xs font-bold mt-1" style={{color: c.score >= 80 ? '#4ade80' : c.score >= 50 ? '#fbbf24' : '#f87171'}}>{c.score}分</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Compliance checks */}
                  {content.checks && Array.isArray(content.checks) && (
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-2">合规检查项 ({content.checks.length})</h4>
                      <div className="max-h-64 overflow-y-auto space-y-1">
                        {content.checks.map((c: any, i: number) => (
                          <div key={i} className="bg-surface-800/50 rounded-lg px-3 py-2">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className={`w-2 h-2 rounded-full shrink-0 ${
                                  c.status === 'pass' ? 'bg-green-400' :
                                  c.status === 'warning' ? 'bg-yellow-400' :
                                  c.status === 'fail' ? 'bg-red-400' : 'bg-slate-500'
                                }`} />
                                <code className="text-slate-500 text-[10px]">{c.id}</code>
                                <span className="text-slate-300 text-xs">{c.name}</span>
                              </div>
                              <div className="flex items-center gap-2">
                                <span className={`text-[10px] font-semibold ${
                                  c.status === 'pass' ? 'text-green-400' :
                                  c.status === 'warning' ? 'text-yellow-400' :
                                  c.status === 'fail' ? 'text-red-400' : 'text-slate-500'
                                }`}>{c.status_label}</span>
                                {c.evidence_count > 0 && <span className="text-[9px] text-slate-500">证据: {c.evidence_count}条</span>}
                                <span className={`text-[9px] ${c.risk_level === 'high' ? 'text-red-400' : c.risk_level === 'medium' ? 'text-yellow-400' : 'text-slate-500'}`}>{c.risk_level}</span>
                              </div>
                            </div>
                            {c.evidence && Array.isArray(c.evidence) && c.evidence.length > 0 && (
                              <div className="mt-1.5 ml-6 space-y-0.5">
                                {c.evidence.slice(0, 3).map((e: any, ei: number) => (
                                  <div key={ei} className="text-[10px] text-slate-500 flex items-center gap-1">
                                    <span className={`shrink-0 ${e.severity === 'critical' ? 'text-red-400' : e.severity === 'high' ? 'text-orange-400' : 'text-slate-400'}`}>[{e.severity}]</span>
                                    <span className="truncate">{e.title}</span>
                                    {e.cwe && <span className="text-slate-600">({e.cwe})</span>}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Raw JSON toggle */}
                  <details className="group">
                    <summary className="cursor-pointer text-xs text-slate-500 hover:text-slate-300 py-2 select-none">查看原始 JSON 数据 ▾</summary>
                    <pre className="mt-2 bg-black/40 rounded-lg p-4 text-[10px] text-slate-400 overflow-x-auto max-h-80 overflow-y-auto">
                      {JSON.stringify(content, null, 2)}
                    </pre>
                  </details>
                </div>
              )
            })()}

            <div className="flex justify-end mt-4 pt-4 border-t border-slate-700/50 gap-2">
              <button onClick={() => downloadFile(selectedReport!, '', false, true)} className="px-3 py-1.5 text-xs bg-cyan-600/25 text-cyan-300 font-semibold hover:bg-cyan-600/40 rounded-lg transition-colors ring-1 ring-cyan-500/40">HTML</button>
              <button onClick={() => downloadFile(selectedReport!, 'json')} className="px-3 py-1.5 text-xs bg-surface-800 text-slate-300 hover:text-white rounded-lg transition-colors">JSON</button>
              <button onClick={() => downloadFile(selectedReport!, 'markdown')} className="px-3 py-1.5 text-xs bg-purple-600/20 text-purple-400 hover:bg-purple-600/30 rounded-lg transition-colors">Markdown</button>
              <button onClick={() => downloadFile(selectedReport!, 'csv')} className="px-3 py-1.5 text-xs bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 rounded-lg transition-colors">CSV</button>
              <button onClick={() => downloadFile(selectedReport!, '', true)} className="px-3 py-1.5 text-xs bg-red-600/20 text-red-400 hover:bg-red-600/30 rounded-lg transition-colors">PDF</button>
              <button onClick={() => { setSelectedReport(null); setReportDetail(null) }} className="px-3 py-1.5 text-xs bg-surface-800 hover:bg-surface-700 text-white rounded-lg transition-colors">关闭</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
