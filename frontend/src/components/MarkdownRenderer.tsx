import { AlertTriangle, Shield, Zap, CheckCircle2, Info, ChevronRight } from 'lucide-react'

interface MarkdownRendererProps {
  content: string
}

export default function MarkdownRenderer({ content }: MarkdownRendererProps) {
  if (!content) return null

  const blocks = content.split('\n')
  const elements: JSX.Element[] = []
  let i = 0

  while (i < blocks.length) {
    const line = blocks[i]

    // H2
    if (line.startsWith('## ')) {
      elements.push(
        <h2 key={i} className="text-sm font-bold text-white mt-6 mb-3 pb-2 border-b border-white/[0.06] flex items-center gap-2">
          <span className="w-1 h-4 rounded-full bg-primary-500" />
          {line.slice(3).replace(/\*\*(.+?)\*\*/g, '$1')}
        </h2>
      )
      i++
      continue
    }

    // H3
    if (line.startsWith('### ')) {
      const text = line.slice(4)
      let icon = <ChevronRight size={12} className="text-primary-400 shrink-0" />
      if (text.includes('严重') || text.includes('评估') || text.includes('风险')) icon = <AlertTriangle size={12} className="text-orange-400 shrink-0" />
      else if (text.includes('攻击') || text.includes('路径')) icon = <Zap size={12} className="text-red-400 shrink-0" />
      else if (text.includes('修复') || text.includes('方案') || text.includes('建议')) icon = <CheckCircle2 size={12} className="text-green-400 shrink-0" />
      else if (text.includes('验证')) icon = <Shield size={12} className="text-accent-400 shrink-0" />
      else if (text.includes('缓解') || text.includes('临时')) icon = <Info size={12} className="text-blue-400 shrink-0" />
      elements.push(
        <h3 key={i} className="text-xs font-semibold text-slate-200 mt-4 mb-2 flex items-center gap-1.5">
          {icon}
          {text.replace(/\*\*(.+?)\*\*/g, '$1')}
        </h3>
      )
      i++
      continue
    }

    // H4
    if (line.startsWith('#### ')) {
      elements.push(
        <h4 key={i} className="text-[11px] font-semibold text-primary-400 mt-3 mb-1.5">
          {line.slice(5).replace(/\*\*(.+?)\*\*/g, '$1')}
        </h4>
      )
      i++
      continue
    }

    // Code block
    if (line.trim().startsWith('```')) {
      const lang = line.trim().slice(3).trim()
      let code = ''
      i++
      while (i < blocks.length && !blocks[i].trim().startsWith('```')) {
        code += blocks[i] + '\n'
        i++
      }
      i++ // skip closing ```
      elements.push(
        <div key={`cb-${i}`} className="relative group rounded-lg bg-surface-950/80 border border-white/[0.06] overflow-hidden my-3">
          <div className="flex items-center justify-between px-3 py-1.5 border-b border-white/[0.04]">
            <span className="text-[10px] text-slate-500 font-mono">{lang || 'code'}</span>
          </div>
          <pre className="text-[11px] font-mono text-slate-300 p-3 overflow-x-auto leading-relaxed">{code.trimEnd()}</pre>
        </div>
      )
      continue
    }

    // Horizontal rule
    if (line.trim() === '---') {
      elements.push(<hr key={i} className="my-4 border-white/[0.06]" />)
      i++
      continue
    }

    // Bold/link/emphasis inline processing helper
    const processInline = (s: string) =>
      s.replace(/\*\*(.+?)\*\*/g, '<strong class="text-white font-semibold">$1</strong>')
       .replace(/\*(.+?)\*/g, '<em class="text-slate-400">$1</em>')
       .replace(/`([^`]+)`/g, '<code class="bg-surface-800 text-primary-300 px-1 py-0.5 rounded text-[10px] font-mono">$1</code>')

    // Skip empty lines
    if (line.trim() === '') {
      i++
      continue
    }

    // Bullet list
    if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
      const items: JSX.Element[] = []
      while (i < blocks.length && (blocks[i].trim().startsWith('- ') || blocks[i].trim().startsWith('* '))) {
        const itemText = processInline(blocks[i].trim().slice(2))
        items.push(
          <li key={`b-${i}`} className="flex items-start gap-2 text-xs text-slate-300 leading-relaxed">
            <span className="w-1 h-1 rounded-full bg-primary-500/70 mt-1.5 shrink-0" />
            <span dangerouslySetInnerHTML={{ __html: itemText }} />
          </li>
        )
        i++
      }
      elements.push(<ul key={`ul-${i}`} className="space-y-1.5 pl-3 my-2">{items}</ul>)
      continue
    }

    // Numbered list
    if (/^\d+\.\s/.test(line.trim())) {
      const items: JSX.Element[] = []
      let n = 1
      while (i < blocks.length && /^\d+\.\s/.test(blocks[i].trim())) {
        const itemText = processInline(blocks[i].trim().replace(/^\d+\.\s/, ''))
        items.push(
          <li key={`n-${i}`} className="flex items-start gap-2 text-xs text-slate-300 leading-relaxed">
            <span className="text-primary-400 font-mono text-[10px] mt-0.5 shrink-0">{n}.</span>
            <span dangerouslySetInnerHTML={{ __html: itemText }} />
          </li>
        )
        n++
        i++
      }
      elements.push(<ul key={`ol-${i}`} className="space-y-1.5 pl-3 my-2">{items}</ul>)
      continue
    }

    // Regular paragraph
    elements.push(
      <p key={i} className="text-xs text-slate-300 leading-relaxed my-1" dangerouslySetInnerHTML={{ __html: processInline(line) }} />
    )
    i++
  }

  return <div className="markdown-body">{elements}</div>
}
