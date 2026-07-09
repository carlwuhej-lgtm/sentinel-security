import api from './api/client'

const KEY = 'sentinel_logo_url'

export function getLogoUrl(): string {
  return localStorage.getItem(KEY) || ''
}

export function setLogoUrl(u: string): void {
  if (u) localStorage.setItem(KEY, u)
  else localStorage.removeItem(KEY)
}

/** 拉取当前平台 Logo URL（管理员可能在后台改过），写入 localStorage 缓存。 */
export async function fetchLogoUrl(): Promise<string> {
  try {
    const res = await api.get('/settings/logo')
    const u = res.data?.logo_url || ''
    setLogoUrl(u)
    return u
  } catch {
    return ''
  }
}
