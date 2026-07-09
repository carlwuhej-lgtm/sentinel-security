import { useState, useRef, useEffect } from 'react'
import { Palette } from 'lucide-react'
import { THEMES, applyTheme, getTheme } from '../theme'
import { useI18n } from '../i18n'

export default function ThemeSwitcher() {
  const [open, setOpen] = useState(false)
  const [current, setCurrent] = useState(getTheme())
  const ref = useRef<HTMLDivElement>(null)
  const { t, lang } = useI18n()

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  const pick = (id: string) => {
    applyTheme(id)
    setCurrent(id)
    setOpen(false)
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-white/[0.06] bg-surface-800/50 text-slate-400 hover:text-slate-200 hover:border-white/10 transition-all text-sm"
        title={t('theme.title')}
      >
        <Palette size={15} />
        <span className="hidden sm:inline">{t('theme.title')}</span>
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-44 rounded-xl border border-white/10 bg-surface-850 shadow-2xl p-2 z-50 animate-fade-in">
          <div className="px-2 py-1 text-[11px] uppercase tracking-wider text-slate-500">
            {t('theme.choose')}
          </div>
          {THEMES.map((th) => (
            <button
              key={th.id}
              onClick={() => pick(th.id)}
              className={`w-full flex items-center gap-3 px-2 py-2 rounded-lg text-sm transition-colors ${
                current === th.id
                  ? 'bg-primary-500/10 text-primary-300'
                  : 'text-slate-300 hover:bg-surface-800'
              }`}
            >
              <span
                className="w-4 h-4 rounded-full ring-1 ring-white/10"
                style={{ background: th.swatch }}
              />
              <span>{lang === 'en' ? th.nameEn : th.name}</span>
              {current === th.id && (
                <span className="ml-auto w-1.5 h-1.5 rounded-full bg-primary-400" />
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
