import { useState, FormEvent, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import { Shield, ArrowLeft, Mail, Lock, User, AlertCircle, UserX } from 'lucide-react'

export default function Register() {
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [regOpen, setRegOpen] = useState<boolean | null>(null)

  useEffect(() => {
    api.get('/auth/register/status')
      .then(res => setRegOpen(Boolean(res.data?.open)))
      .catch(() => setRegOpen(null))
  }, [])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault(); setError('')

    if (password !== confirmPassword) {
      setError('两次输入的密码不一致')
      return
    }
    if (password.length < 6) {
      setError('密码至少 6 位')
      return
    }

    setLoading(true)
    try {
      const res = await api.post('/auth/register', { name, email, password })
      localStorage.setItem('sentinel_token', res.data.token)
      localStorage.setItem('sentinel_user', JSON.stringify(res.data.user))
      navigate('/')
    } catch (err: any) {
      const status = err.response?.status
      const data = err.response?.data || {}
      if (status === 403) {
        setError(data.message || data.error || '注册已关闭，请联系管理员申请账号')
      } else {
        setError(data.error || data.message || '注册失败，请稍后重试')
      }
    } finally { setLoading(false) }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-surface-950 bg-grid p-4">
      <div className="w-full max-w-md">
        {/* Back link */}
        <Link to="/login" className="inline-flex items-center gap-1.5 text-slate-500 hover:text-slate-300 text-sm mb-8 transition-colors">
          <ArrowLeft size={14} />
          返回登录
        </Link>

        <div className="glass-card p-8 border-white/[0.05]">
          {/* 公开注册已关闭：仅展示提示，不渲染表单 */}
          {regOpen === false ? (
            <div className="text-center py-6">
              <div className="w-12 h-12 rounded-2xl bg-slate-500/10 flex items-center justify-center mx-auto mb-4">
                <UserX size={24} className="text-slate-400" />
              </div>
              <h1 className="text-xl font-bold text-white mb-2">注册已关闭</h1>
              <p className="text-slate-400 text-sm leading-relaxed">
                当前平台未开放公开注册。<br />如需账号，请联系管理员申请。
              </p>
            </div>
          ) : (
            <>
          {/* Header */}
          <div className="flex items-center gap-3 mb-1">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center shadow-[0_0_16px_rgba(59,130,246,0.2)]">
              <Shield size={20} strokeWidth={2.5} className="text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">创建账号</h1>
              <p className="text-slate-500 text-xs">加入 Sentinel 安全平台</p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 mt-8">
            {/* Name */}
            <div className="input-group">
              <label className="input-label" htmlFor="reg-name">姓名</label>
              <div className="relative">
                <User size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  id="reg-name" type="text" className="input pl-9"
                  placeholder="你的姓名"
                  value={name} onChange={(e) => setName(e.target.value)}
                  required
                />
              </div>
            </div>

            {/* Email */}
            <div className="input-group">
              <label className="input-label" htmlFor="reg-email">邮箱地址</label>
              <div className="relative">
                <Mail size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  id="reg-email" type="email" className="input pl-9"
                  placeholder="your@email.com"
                  value={email} onChange={(e) => setEmail(e.target.value)}
                  required autoComplete="email"
                />
              </div>
            </div>

            {/* Password */}
            <div className="input-group">
              <label className="input-label" htmlFor="reg-password">密码</label>
              <div className="relative">
                <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  id="reg-password" type="password" className="input pl-9"
                  placeholder="至少 6 位"
                  value={password} onChange={(e) => setPassword(e.target.value)}
                  required autoComplete="new-password"
                />
              </div>
            </div>

            {/* Confirm Password */}
            <div className="input-group">
              <label className="input-label" htmlFor="reg-confirm">确认密码</label>
              <div className="relative">
                <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  id="reg-confirm" type="password" className="input pl-9"
                  placeholder="再次输入密码"
                  value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)}
                  required autoComplete="new-password"
                />
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="rounded-lg bg-red-500/10 border border-red-500/15 px-3 py-2.5 text-red-400 text-xs flex items-center gap-2">
                <AlertCircle size={14} />{error}
              </div>
            )}

            {/* Submit */}
            <button type="submit" disabled={loading} className="btn-primary w-full py-2.5">
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="spinner" />注册中...
                </span>
              ) : '注册'}
            </button>

            <p className="text-center text-xs text-slate-500 pt-1">
              已有账号？
              <Link to="/login" className="text-primary-400 hover:text-primary-300 ml-1">去登录</Link>
            </p>
          </form>
          </>
          )}
        </div>
      </div>
    </div>
  )
}
