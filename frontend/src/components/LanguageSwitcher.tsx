import { Languages } from 'lucide-react'
import { useI18n } from '../i18n'

export default function LanguageSwitcher() {
  const { lang, setLang, t } = useI18n()
  const next: 'zh' | 'en' = lang === 'zh' ? 'en' : 'zh'

  return (
    <button
      onClick={() => setLang(next)}
      className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-white/[0.06] bg-surface-800/50 text-slate-400 hover:text-slate-200 hover:border-white/10 transition-all text-sm"
      title={t('lang.title')}
    >
      <Languages size={15} />
      <span className="hidden sm:inline">{lang === 'zh' ? '中' : 'EN'}</span>
    </button>
  )
}
