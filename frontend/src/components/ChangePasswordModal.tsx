import { useState, FormEvent } from 'react'
import { X, Lock, AlertCircle, CheckCircle2 } from 'lucide-react'
import api from '../api/client'

interface Props {
  onClose: () => void
  forced?: boolean
  onSuccess?: () => void
}

export default function ChangePasswordModal({ onClose, forced = false, onSuccess }: Props) {
  const [oldPassword, setOldPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')

    if (!oldPassword || !newPassword || !confirmPassword) {
      setError('请填写所有字段')
      return
    }
    if (newPassword.length < 6) {
      setError('新密码至少 6 位')
      return
    }
    if (newPassword !== confirmPassword) {
      setError('两次输入的新密码不一致')
      return
    }

    setLoading(true)
    try {
      const res = await api.post('/auth/change-password', {
        old_password: oldPassword,
        new_password: newPassword,
      })
      setSuccess('密码修改成功')
      // 后端改密后会吊销旧 token 并签发新 token，存回 localStorage 保持登录态
      const newToken = res.data?.token
      if (newToken) localStorage.setItem('sentinel_token', newToken)
      if (forced) {
        setTimeout(() => { onSuccess?.() }, 1500)
      } else {
        setTimeout(onClose, 1500)
      }
    } catch (err: any) {
      const msg = err.response?.data?.error || '修改失败，请稍后重试'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={forced ? undefined : onClose} />

      {/* Modal */}
      <div className="relative w-full max-w-sm glass-card border-white/[0.08] p-6 animate-slide-up">
        {/* Header */}
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-primary-500/10 border border-primary-500/15 flex items-center justify-center">
              <Lock size={14} className="text-primary-400" />
            </div>
            <h2 className="text-base font-semibold text-white">修改密码</h2>
          </div>
          {!forced && (
            <button onClick={onClose} className="text-slate-500 hover:text-slate-300 p-1 rounded-lg hover:bg-surface-800/60 transition-all">
              <X size={16} />
            </button>
          )}
        </div>

        {/* 强制改密提示 */}
        {forced && !success && (
          <div className="rounded-lg bg-amber-500/10 border border-amber-500/15 px-3 py-2 text-amber-400 text-xs mb-4">
            为账户安全，首次登录必须修改默认密码后才能继续使用。
          </div>
        )}

        {/* Success */}
        {success && (
          <div className="rounded-lg bg-green-500/10 border border-green-500/15 px-3 py-2.5 text-green-400 text-xs flex items-center gap-2 mb-4">
            <CheckCircle2 size={14} />{success}
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="rounded-lg bg-red-500/10 border border-red-500/15 px-3 py-2.5 text-red-400 text-xs flex items-center gap-2 mb-4">
            <AlertCircle size={14} />{error}
          </div>
        )}

        {!success && (
          <form onSubmit={handleSubmit} className="space-y-3.5">
            <div className="input-group">
              <label className="input-label" htmlFor="cp-old">当前密码</label>
              <input
                id="cp-old" type="password" className="input"
                placeholder="输入当前密码"
                value={oldPassword} onChange={(e) => setOldPassword(e.target.value)}
                required autoComplete="current-password"
              />
            </div>

            <div className="input-group">
              <label className="input-label" htmlFor="cp-new">新密码</label>
              <input
                id="cp-new" type="password" className="input"
                placeholder="至少 6 位"
                value={newPassword} onChange={(e) => setNewPassword(e.target.value)}
                required autoComplete="new-password"
              />
            </div>

            <div className="input-group">
              <label className="input-label" htmlFor="cp-confirm">确认新密码</label>
              <input
                id="cp-confirm" type="password" className="input"
                placeholder="再次输入新密码"
                value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)}
                required autoComplete="new-password"
              />
            </div>

            <div className="flex gap-2.5 pt-1">
              {!forced && (
                <button type="button" onClick={onClose} className="btn-ghost flex-1 py-2 text-sm">
                  取消
                </button>
              )}
              <button type="submit" disabled={loading} className={`btn-primary py-2 text-sm ${forced ? 'w-full' : 'flex-1'}`}>
                {loading ? '提交中...' : '确认修改'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
