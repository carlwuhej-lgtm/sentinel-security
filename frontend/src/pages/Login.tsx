import { useState, FormEvent, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import { Shield, ScanSearch, BrainCircuit, BellRing, ArrowRight } from 'lucide-react'
import { useI18n } from '../i18n'
import { getLogoUrl, fetchLogoUrl } from '../branding'

const featureKeys = [
  { key: 'multiTool', icon: <ScanSearch size={14} /> },
  { key: 'ai', icon: <BrainCircuit size={14} /> },
  { key: 'alert', icon: <BellRing size={14} /> },
  { key: 'lifecycle', icon: <Shield size={14} /> },
]

export default function Login() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [logoUrl, setLogoUrl] = useState(getLogoUrl())
  const [regOpen, setRegOpen] = useState(true)

  useEffect(() => { fetchLogoUrl().then(setLogoUrl) }, [])
  useEffect(() => {
    api.get('/auth/register/status')
      .then(res => setRegOpen(Boolean(res.data?.open)))
      .catch(() => setRegOpen(true))
  }, [])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault(); setError(''); setLoading(true)
    try {
      const res = await api.post('/auth/login', { email, password })
      localStorage.setItem('sentinel_token', res.data.token)
      localStorage.setItem('sentinel_user', JSON.stringify(res.data.user))
      // 强制改密标记改用 sessionStorage（按标签页隔离，关闭即清），
      // 不再用 localStorage，避免旧标记跨会话残留导致反复弹窗。
      localStorage.removeItem('sentinel_force_pwd')  // 清理旧版遗留的粘性标记
      if (res.data.must_change_pwd) {
        sessionStorage.setItem('sentinel_force_pwd', '1')
      }
      navigate('/')
    } catch (err: any) {
      setError(err.response?.data?.error || '登录失败，请检查邮箱和密码')
    } finally { setLoading(false) }
  }

  return (
    <div className="min-h-screen flex flex-col lg:flex-row bg-surface-950 bg-grid">
      {/* Left: Brand */}
      <div className="flex-1 flex items-center justify-center p-8 lg:p-16 xl:p-20 relative overflow-hidden">
        <div className="max-w-md w-full relative z-10">
          {/* Logo */}
          {logoUrl ? (
            <img
              src={logoUrl}
              alt="logo"
              className="w-14 h-14 rounded-2xl object-cover ring-1 ring-primary-400/20 mb-8"
            />
          ) : (
            <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center shadow-[0_0_24px_rgba(59,130,246,0.25)] ring-1 ring-primary-400/20 mb-8">
              <Shield size={28} strokeWidth={2.5} className="text-white" />
            </div>
          )}

          <h1 className="text-4xl lg:text-5xl font-black text-white tracking-tight mb-2">
            Sentinel
          </h1>
          <p className="text-slate-400 text-lg mb-2">{t('login.subtitle')}</p>
          <p className="text-slate-600 text-sm mb-10 max-w-xs leading-relaxed">
            {t('login.desc')}
          </p>

          {/* Features */}
          <ul className="space-y-3">
            {featureKeys.map((f) => (
              <li key={f.key} className="flex items-center gap-3 text-sm text-slate-300">
                <span className="w-6 h-6 rounded-lg bg-primary-500/10 border border-primary-500/15 flex items-center justify-center text-primary-400 shrink-0">
                  {f.icon}
                </span>
                {t(`login.features.${f.key}`)}
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Right: Form */}
      <div className="flex-1 flex items-center justify-center p-8 lg:p-16 xl:p-20 bg-surface-900/40 backdrop-blur-sm">
        <div className="w-full max-w-sm animate-slide-up">
          <div className="glass-card p-8 border-white/[0.05]">
            <h2 className="text-xl font-bold text-white mb-1">{t('login.title')}</h2>
            <p className="text-slate-500 text-xs mb-8">
              {t('login.defaultHint')}
            </p>

            <form onSubmit={handleSubmit} className="space-y-5">
              <div className="input-group">
                <label className="input-label" htmlFor="email">{t('login.email')}</label>
                <input
                  id="email" type="email" className="input"
                  placeholder="admin@sentinel.io"
                  value={email} onChange={(e) => setEmail(e.target.value)}
                  required autoComplete="email"
                />
              </div>

              <div className="input-group">
                <label className="input-label" htmlFor="password">{t('login.password')}</label>
                <input
                  id="password" type="password" className="input"
                  placeholder="••••••••"
                  value={password} onChange={(e) => setPassword(e.target.value)}
                  required autoComplete="current-password"
                />
              </div>

              {error && (
                <div className="rounded-lg bg-red-500/10 border border-red-500/15 px-3 py-2.5 text-red-400 text-xs flex items-center gap-2">
                  <Shield size={12} />{error}
                </div>
              )}

              <button type="submit" disabled={loading} className="btn-primary w-full py-2.5 group">
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="spinner" />{t('login.submitting')}
                  </span>
                ) : (
                  <span className="flex items-center justify-center gap-2">
                    {t('login.submit')} <ArrowRight size={16} className="group-hover:translate-x-1 transition-transform" />
                  </span>
                )}
              </button>
            </form>

            {regOpen === false ? (
              <p className="text-center text-xs text-slate-500 mt-4">
                注册已关闭，请联系管理员申请账号
              </p>
            ) : (
              <p className="text-center text-xs text-slate-500 mt-4">
                {t('login.noAccount')}
                <Link to="/register" className="text-primary-400 hover:text-primary-300 transition-colors ml-1">{t('login.register')}</Link>
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
