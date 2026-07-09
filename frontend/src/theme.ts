// 主题系统：几套预设配色，运行时切换 <html data-theme> 即可全站换色。
// 颜色变量定义在 index.css 的 :root 与各 [data-theme] 中，
// Tailwind 的 primary / accent / surface 均引用这些变量。

export interface ThemeDef {
  id: string
  name: string // 中文名
  nameEn: string
  swatch: string // 顶栏色板展示用的主色
}

export const THEMES: ThemeDef[] = [
  { id: 'blue',    name: '深蓝',   nameEn: 'Blue',    swatch: '#3b82f6' },
  { id: 'emerald', name: '翡翠绿', nameEn: 'Emerald', swatch: '#10b981' },
  { id: 'violet',  name: '紫罗兰', nameEn: 'Violet',  swatch: '#8b5cf6' },
  { id: 'amber',   name: '琥珀',   nameEn: 'Amber',   swatch: '#f59e11' },
  { id: 'rose',    name: '玫瑰红', nameEn: 'Rose',    swatch: '#f43f5e' },
]

export const THEME_KEY = 'sentinel_theme'

export function getTheme(): string {
  const v = localStorage.getItem(THEME_KEY)
  return THEMES.some((t) => t.id === v) ? (v as string) : 'blue'
}

export function applyTheme(id: string): void {
  const theme = THEMES.some((t) => t.id === id) ? id : 'blue'
  document.documentElement.setAttribute('data-theme', theme)
  localStorage.setItem(THEME_KEY, theme)
}

// 模块加载即应用（在首屏渲染前生效，避免闪烁）
applyTheme(getTheme())
