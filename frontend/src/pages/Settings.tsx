import { useState, useEffect, ChangeEvent } from 'react'
import api from '../api/client'
import { useI18n } from '../i18n'
import { getLogoUrl, setLogoUrl, fetchLogoUrl } from '../branding'

interface EmailConfig {
  enabled: boolean
  host: string
  port: number
  username: string
  password: string
  from_addr: string
  recipients: string
  levels: {
    critical: boolean
    high: boolean
    medium: boolean
    low: boolean
  }
}

interface AlertRules {
  alert_on: {
    critical: boolean
    high: boolean
    medium: boolean
    low: boolean
  }
  daily_digest: boolean
  weekly_report: boolean
}

interface GatePolicy {
  token: string
  gate_mode: string
  gate_rules: {
    critical: string
    high: string
    medium: string
    low: string
  }
}

interface Toast {
  type: 'success' | 'error'
  message: string
}

export default function Settings() {
  const { t } = useI18n()
  const [activeTab, setActiveTab] = useState<'email' | 'alert' | 'gate' | 'backup' | 'channels' | 'appearance' | 'ai'>('email')
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [testResult, setTestResult] = useState('')
  const [logoUrl, setLogo] = useState(getLogoUrl())
  const [logoBusy, setLogoBusy] = useState(false)
  const [allowRegister, setAllowRegister] = useState(false)
  const [regBusy, setRegBusy] = useState(false)
  const isAdmin = JSON.parse(localStorage.getItem('sentinel_user') || '{}')?.role === 'admin'

  // nosemgrep: empty form field default values, not actual passwords
  const [emailConfig, setEmailConfig] = useState<EmailConfig>({
    enabled: false,
    host: '',
    port: 587,
    username: '',
    password: '',
    from_addr: '',
    recipients: '',
    levels: { critical: false, high: false, medium: false, low: false },
  })

  const [alertRules, setAlertRules] = useState<AlertRules>({
    alert_on: { critical: false, high: false, medium: false, low: false },
    daily_digest: false,
    weekly_report: false,
  })

  const [toast, setToast] = useState<Toast | null>(null)

  const [gatePolicy, setGatePolicy] = useState<GatePolicy>({
    token: '',
    gate_mode: 'block',
    gate_rules: { critical: 'block', high: 'warn', medium: 'pass', low: 'pass' },
  })

  const [backups, setBackups] = useState<{ filename: string; size: number; created_at: string }[]>([])
  const [backupBusy, setBackupBusy] = useState(false)

  const [channels, setChannels] = useState<{ id: number; channel_type: string; name: string; webhook_url: string; enabled: number }[]>([])
  const [channelForm, setChannelForm] = useState({ name: '飞书', webhook_url: '', secret: '', enabled: true })
  const [channelBusy, setChannelBusy] = useState(false)

  // ─── AI 模型供应商管理 ──────────────────────────────────────────
  interface AiProvider {
    id: number
    name: string
    provider_type: string
    api_base: string
    model: string
    api_key: string
    is_active: boolean
    created_at: string
    updated_at: string
  }
  const [providers, setProviders] = useState<AiProvider[]>([])
  const [providerBusy, setProviderBusy] = useState(false)
  const [providerTestingId, setProviderTestingId] = useState<number | null>(null)
  const [providerTestResult, setProviderTestResult] = useState<{ id: number; reachable: boolean; reply_ok: boolean; detail: string } | null>(null)
  const [showProviderForm, setShowProviderForm] = useState(false)
  const [editingProviderId, setEditingProviderId] = useState<number | null>(null)
  const emptyProviderForm = { name: '', provider_type: 'openai', api_base: '', model: '', api_key: '' }
  const [providerForm, setProviderForm] = useState(emptyProviderForm)

  useEffect(() => {
    if (activeTab === 'email') {
      loadEmailConfig()
    } else if (activeTab === 'alert') {
      loadAlertRules()
    } else if (activeTab === 'gate') {
      loadGatePolicy()
    } else if (activeTab === 'backup') {
      loadBackups()
    } else if (activeTab === 'channels') {
      loadChannels()
    } else if (activeTab === 'appearance') {
      fetchLogoUrl().then(setLogo)
      api.get('/settings/registration').then(r => setAllowRegister(!!r.data.allow_public_register)).catch(() => {})
    } else if (activeTab === 'ai') {
      loadProviders()
    }
  }, [activeTab])

  // ─── AI 模型供应商 ──────────────────────────────────────────────
  const loadProviders = async () => {
    try {
      const res = await api.get('/ai/providers')
      setProviders(res.data || [])
    } catch {
      showToast('error', '加载 AI 供应商失败')
    }
  }

  const saveProvider = async () => {
    if (!providerForm.name.trim() || !providerForm.api_base.trim() || !providerForm.model.trim()) {
      showToast('error', '名称、API 地址、模型名称均为必填')
      return
    }
    setProviderBusy(true)
    try {
      if (editingProviderId) {
        await api.put(`/ai/providers/${editingProviderId}`, providerForm)
        showToast('success', '供应商已更新')
      } else {
        await api.post('/ai/providers', providerForm)
        showToast('success', '供应商已添加')
      }
      setShowProviderForm(false)
      setEditingProviderId(null)
      setProviderForm(emptyProviderForm)
      loadProviders()
    } catch (e: any) {
      showToast('error', e.response?.data?.error || '保存失败')
    } finally {
      setProviderBusy(false)
    }
  }

  const editProvider = (p: AiProvider) => {
    setEditingProviderId(p.id)
    setProviderForm({ name: p.name, provider_type: p.provider_type, api_base: p.api_base, model: p.model, api_key: '' })
    setShowProviderForm(true)
  }

  const activateProvider = async (id: number) => {
    try {
      await api.post(`/ai/providers/${id}/activate`)
      showToast('success', '已切换为激活模型（无需重启）')
      loadProviders()
    } catch (e: any) {
      showToast('error', e.response?.data?.error || '切换失败')
    }
  }

  const deleteProvider = async (id: number) => {
    if (!window.confirm('确定删除该 AI 供应商？')) return
    try {
      await api.delete(`/ai/providers/${id}`)
      showToast('success', '已删除')
      setProviderTestResult(null)
      loadProviders()
    } catch (e: any) {
      showToast('error', e.response?.data?.error || '删除失败')
    }
  }

  const testProvider = async (id: number) => {
    setProviderTestingId(id)
    setProviderTestResult(null)
    try {
      const res = await api.post(`/ai/providers/${id}/test`)
      setProviderTestResult({ id, ...res.data })
    } catch (e: any) {
      setProviderTestResult({ id, reachable: false, reply_ok: false, detail: e.response?.data?.error || '测试失败' })
    } finally {
      setProviderTestingId(null)
    }
  }

  const showToast = (type: 'success' | 'error', message: string) => {
    setToast({ type, message })
    setTimeout(() => setToast(null), 4000)
  }

  const loadEmailConfig = async () => {
    setLoading(true)
    try {
      const res = await api.get('/settings/email-config')
      const data = res.data
      // nosemgrep: password field intentionally reset to empty when loading config
      setEmailConfig({
        enabled: data.enabled ?? false,
        host: data.host ?? '',
        port: data.port ?? 587,
        username: data.username ?? '',
        password: '',
        from_addr: data.from_addr ?? '',
        recipients: Array.isArray(data.recipients) ? data.recipients.join('\n') : (data.recipients ?? ''),
        levels: data.levels ?? { critical: false, high: false, medium: false, low: false },
      })
    } catch {
      showToast('error', '加载邮件配置失败')
    } finally {
      setLoading(false)
    }
  }

  const loadAlertRules = async () => {
    setLoading(true)
    try {
      const res = await api.get('/settings/alert-rules')
      const data = res.data
      setAlertRules({
        alert_on: data.alert_on ?? { critical: false, high: false, medium: false, low: false },
        daily_digest: data.daily_digest ?? false,
        weekly_report: data.weekly_report ?? false,
      })
    } catch {
      showToast('error', '加载告警规则失败')
    } finally {
      setLoading(false)
    }
  }

  const saveEmailConfig = async () => {
    setSaving(true)
    try {
      const payload = {
        ...emailConfig,
        recipients: emailConfig.recipients
          .split(/[\n,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        password: emailConfig.password || undefined,
      }
      await api.put('/settings/email-config', payload)
      showToast('success', '邮件配置已保存')
    } catch {
      showToast('error', '保存邮件配置失败')
    } finally {
      setSaving(false)
    }
  }

  const sendTestEmail = async () => {
    setSaving(true)
    setTestResult('')
    try {
      const res = await api.post('/settings/email-config/test')
      setTestResult(res.data?.message ?? '测试邮件发送成功')
      showToast('success', '测试邮件已发送，请检查收件箱')
    } catch {
      setTestResult('测试邮件发送失败')
      showToast('error', '测试邮件发送失败')
    } finally {
      setSaving(false)
    }
  }

  const saveAlertRules = async () => {
    setSaving(true)
    try {
      await api.put('/settings/alert-rules', alertRules)
      showToast('success', '告警规则已保存')
    } catch {
      showToast('error', '保存告警规则失败')
    } finally {
      setSaving(false)
    }
  }

  const loadGatePolicy = async () => {
    setLoading(true)
    try {
      const res = await api.get('/webhooks/config')
      const data = res.data
      setGatePolicy({
        token: data.token ?? '',
        gate_mode: data.gate_mode ?? 'block',
        gate_rules: {
          critical: data.gate_rules?.critical ?? 'block',
          high: data.gate_rules?.high ?? 'warn',
          medium: data.gate_rules?.medium ?? 'pass',
          low: data.gate_rules?.low ?? 'pass',
        },
      })
    } catch {
      showToast('error', '加载门禁策略失败')
    } finally {
      setLoading(false)
    }
  }

  const saveGatePolicy = async () => {
    setSaving(true)
    try {
      await api.put('/webhooks/config', {
        gate_mode: gatePolicy.gate_mode,
        gate_rules: gatePolicy.gate_rules,
      })
      showToast('success', '门禁策略已保存')
    } catch {
      showToast('error', '保存门禁策略失败')
    } finally {
      setSaving(false)
    }
  }

  const regenerateToken = async () => {
    setSaving(true)
    try {
      const res = await api.post('/webhooks/regenerate-token')
      setGatePolicy(prev => ({ ...prev, token: res.data.token }))
      showToast('success', 'Token 已重新生成')
    } catch {
      showToast('error', 'Token 重新生成失败')
    } finally {
      setSaving(false)
    }
  }

  // ─── 数据备份 / 恢复 ────────────────────────────────────────────────
  const loadBackups = async () => {
    try {
      const res = await api.get('/settings/backups')
      setBackups(res.data.backups || [])
    } catch {
      showToast('error', '加载备份列表失败')
    }
  }

  const createBackup = async () => {
    setBackupBusy(true)
    try {
      await api.post('/settings/backup')
      showToast('success', '备份已生成')
      loadBackups()
    } catch {
      showToast('error', '备份生成失败')
    } finally {
      setBackupBusy(false)
    }
  }

  const downloadBackup = (filename: string) => {
    window.open(`/api/settings/backup/${encodeURIComponent(filename)}/download`, '_blank')
  }

  const restoreBackup = async (filename: string) => {
    if (!window.confirm(`确定从快照 ${filename} 恢复？恢复前会自动备份当前状态。`)) return
    setBackupBusy(true)
    try {
      await api.post('/settings/restore', { filename })
      showToast('success', '恢复成功（已自动备份恢复前状态）')
      loadBackups()
    } catch {
      showToast('error', '恢复失败')
    } finally {
      setBackupBusy(false)
    }
  }

  const loadChannels = async () => {
    try {
      const res = await api.get('/alerts/channels')
      setChannels(res.data || [])
    } catch (e: any) {
      showToast('error', e.response?.data?.error || '加载渠道失败')
    }
  }

  const addChannel = async () => {
    if (!channelForm.webhook_url.trim()) {
      showToast('error', '请填写飞书 Webhook 地址')
      return
    }
    setChannelBusy(true)
    try {
      await api.post('/alerts/channels', {
        channel_type: 'feishu',
        name: channelForm.name || '飞书',
        webhook_url: channelForm.webhook_url.trim(),
        secret: channelForm.secret || '',
        enabled: channelForm.enabled ? 1 : 0,
      })
      setChannelForm({ name: '飞书', webhook_url: '', secret: '', enabled: true })
      showToast('success', '飞书渠道已添加')
      loadChannels()
    } catch (e: any) {
      showToast('error', e.response?.data?.error || '添加失败')
    } finally {
      setChannelBusy(false)
    }
  }

  const deleteChannel = async (id: number) => {
    if (!confirm('确定删除该通知渠道？')) return
    try {
      await api.delete(`/alerts/channels/${id}`)
      showToast('success', '已删除')
      loadChannels()
    } catch (e: any) {
      showToast('error', e.response?.data?.error || '删除失败')
    }
  }

  const toggleChannel = async (ch: any) => {
    try {
      await api.put(`/alerts/channels/${ch.id}`, { enabled: ch.enabled ? 0 : 1 })
      loadChannels()
    } catch (e: any) {
      showToast('error', e.response?.data?.error || '更新失败')
    }
  }

  const restoreFromFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    if (!window.confirm('确定用上传的数据库文件恢复？恢复前会自动备份当前状态。')) return
    setBackupBusy(true)
    try {
      const fd = new FormData()
      fd.append('file', file)
      await api.post('/settings/restore', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      showToast('success', '恢复成功（已自动备份恢复前状态）')
      loadBackups()
    } catch {
      showToast('error', '恢复失败')
    } finally {
      setBackupBusy(false)
      e.target.value = ''
    }
  }

  // ─── 外观：Logo 上传 / 移除 ──────────────────────────────────────
  const uploadLogoFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setLogoBusy(true)
    try {
      const fd = new FormData()
      fd.append('file', file)
      const res = await api.post('/settings/logo', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      const url = res.data?.logo_url || ''
      setLogo(url)
      setLogoUrl(url)
      showToast('success', 'Logo 已更新')
    } catch (err: any) {
      showToast('error', err.response?.data?.error || '上传失败')
    } finally {
      setLogoBusy(false)
      e.target.value = ''
    }
  }

  const removeLogoFile = async () => {
    if (!window.confirm('确定移除 Logo，恢复默认盾牌图标？')) return
    setLogoBusy(true)
    try {
      await api.delete('/settings/logo')
      setLogo('')
      setLogoUrl('')
      showToast('success', 'Logo 已移除')
    } catch {
      showToast('error', '移除失败')
    } finally {
      setLogoBusy(false)
    }
  }

  const updateGateRule = (level: keyof GatePolicy['gate_rules'], value: string) => {
    setGatePolicy(prev => ({
      ...prev,
      gate_rules: { ...prev.gate_rules, [level]: value },
    }))
  }

  const updateEmailConfig = <K extends keyof EmailConfig>(key: K, value: EmailConfig[K]) => {
    setEmailConfig((prev) => ({ ...prev, [key]: value }))
  }

  const updateEmailLevel = (level: keyof EmailConfig['levels'], value: boolean) => {
    setEmailConfig((prev) => ({
      ...prev,
      levels: { ...prev.levels, [level]: value },
    }))
  }

  const updateAlertOn = (level: keyof AlertRules['alert_on'], value: boolean) => {
    setAlertRules((prev) => ({
      ...prev,
      alert_on: { ...prev.alert_on, [level]: value },
    }))
  }

  const updateAlertRules = <K extends keyof AlertRules>(key: K, value: AlertRules[K]) => {
    setAlertRules((prev) => ({ ...prev, [key]: value }))
  }

  const Toggle = ({
    checked,
    onChange,
    disabled,
  }: {
    checked: boolean
    onChange: (v: boolean) => void
    disabled?: boolean
  }) => (
    <div
      className={`toggle ${checked ? 'toggle-active' : ''}`}
      onClick={() => !disabled && onChange(!checked)}
      style={{
        display: 'inline-flex',
        width: 44,
        height: 24,
        borderRadius: 12,
        padding: 2,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        background: checked ? '#3b82f6' : '#334155',
        transition: 'background 0.2s',
        alignItems: 'center',
        flexShrink: 0,
      }}
    >
      <div
        style={{
          width: 20,
          height: 20,
          borderRadius: '50%',
          background: '#fff',
          transform: checked ? 'translateX(20px)' : 'translateX(0)',
          transition: 'transform 0.2s',
        }}
      />
    </div>
  )

  if (loading && activeTab === 'email' && !emailConfig.host) {
    return <div className="text-slate-500 text-sm">加载中...</div>
  }

  const aiInputStyle = {
    flex: 1,
    minWidth: 240,
    padding: '8px 12px',
    borderRadius: 6,
    border: '1px solid #334155',
    background: '#0f172a',
    color: '#e2e8f0',
    fontSize: 13,
    outline: 'none',
    boxSizing: 'border-box' as const,
  }

  const aiBtn = (bg: string, border: string, color: string = '#e2e8f0') => ({
    padding: '4px 12px',
    background: bg,
    color,
    border: `1px solid ${border}`,
    borderRadius: 4,
    cursor: 'pointer',
    fontSize: 12,
  })

  return (
    <div className="max-w-7xl mx-auto">
      <div className="page-header">
        <div>
          <h1 className="page-title">{t('settings.title')}</h1>
          <p className="page-subtitle">{t('settings.subtitle')}</p>
        </div>
      </div>

      {/* Toast Notification */}
      {toast && (
        <div
          style={{
            position: 'fixed',
            top: 16,
            right: 16,
            zIndex: 9999,
            padding: '12px 20px',
            borderRadius: 8,
            fontSize: 14,
            fontWeight: 500,
            color: '#fff',
            background: toast.type === 'success' ? '#16a34a' : '#dc2626',
            boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
            animation: 'fadeIn 0.2s',
          }}
        >
          {toast.message}
        </div>
      )}

      {/* Tab Navigation */}
      <div className="tabs" style={{ display: 'flex', gap: 0, marginBottom: 24, borderBottom: '1px solid #1e293b' }}>
        <button
          className={activeTab === 'email' ? 'tab tab-active' : 'tab'}
          onClick={() => setActiveTab('email')}
          style={{
            padding: '10px 24px',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: activeTab === 'email' ? 600 : 400,
            color: activeTab === 'email' ? '#3b82f6' : '#94a3b8',
            borderBottom: activeTab === 'email' ? '2px solid #3b82f6' : '2px solid transparent',
            transition: 'color 0.2s, border-color 0.2s',
          }}
        >
          {t('settings.tab.email')}
        </button>
        <button
          className={activeTab === 'alert' ? 'tab tab-active' : 'tab'}
          onClick={() => setActiveTab('alert')}
          style={{
            padding: '10px 24px',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: activeTab === 'alert' ? 600 : 400,
            color: activeTab === 'alert' ? '#3b82f6' : '#94a3b8',
            borderBottom: activeTab === 'alert' ? '2px solid #3b82f6' : '2px solid transparent',
            transition: 'color 0.2s, border-color 0.2s',
          }}
        >
          {t('settings.tab.alert')}
        </button>
        <button
          className={activeTab === 'gate' ? 'tab tab-active' : 'tab'}
          onClick={() => setActiveTab('gate')}
          style={{
            padding: '10px 24px',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: activeTab === 'gate' ? 600 : 400,
            color: activeTab === 'gate' ? '#3b82f6' : '#94a3b8',
            borderBottom: activeTab === 'gate' ? '2px solid #3b82f6' : '2px solid transparent',
            transition: 'color 0.2s, border-color 0.2s',
          }}
        >
          {t('settings.tab.gate')}
        </button>
        <button
          className={activeTab === 'backup' ? 'tab tab-active' : 'tab'}
          onClick={() => setActiveTab('backup')}
          style={{
            padding: '10px 24px',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: activeTab === 'backup' ? 600 : 400,
            color: activeTab === 'backup' ? '#3b82f6' : '#94a3b8',
            borderBottom: activeTab === 'backup' ? '2px solid #3b82f6' : '2px solid transparent',
            transition: 'color 0.2s, border-color 0.2s',
          }}
        >
          {t('settings.tab.backup')}
        </button>
        <button
          className={activeTab === 'channels' ? 'tab tab-active' : 'tab'}
          onClick={() => setActiveTab('channels')}
          style={{
            padding: '10px 24px',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: activeTab === 'channels' ? 600 : 400,
            color: activeTab === 'channels' ? '#3b82f6' : '#94a3b8',
            borderBottom: activeTab === 'channels' ? '2px solid #3b82f6' : '2px solid transparent',
            transition: 'color 0.2s, border-color 0.2s',
          }}
        >
          通知渠道
        </button>
        <button
          className={activeTab === 'appearance' ? 'tab tab-active' : 'tab'}
          onClick={() => setActiveTab('appearance')}
          style={{
            padding: '10px 24px',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: activeTab === 'appearance' ? 600 : 400,
            color: activeTab === 'appearance' ? '#3b82f6' : '#94a3b8',
            borderBottom: activeTab === 'appearance' ? '2px solid #3b82f6' : '2px solid transparent',
            transition: 'color 0.2s, border-color 0.2s',
          }}
        >
          {t('settings.tab.appearance')}
        </button>
        <button
          className={activeTab === 'ai' ? 'tab tab-active' : 'tab'}
          onClick={() => setActiveTab('ai')}
          style={{
            padding: '10px 24px',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: activeTab === 'ai' ? 600 : 400,
            color: activeTab === 'ai' ? '#3b82f6' : '#94a3b8',
            borderBottom: activeTab === 'ai' ? '2px solid #3b82f6' : '2px solid transparent',
            transition: 'color 0.2s, border-color 0.2s',
          }}
        >
          AI 模型
        </button>
      </div>

      {/* ===== Tab 1: 邮件通知 ===== */}
      {activeTab === 'email' && (
        <div>
          {/* SMTP Server Configuration */}
          <div className="card" style={{ padding: 24, marginBottom: 20 }}>
            <h3 className="text-white font-semibold text-sm mb-1">SMTP 服务器配置</h3>
            <p className="text-slate-500 text-xs mb-4">配置用于发送安全告警的邮件服务器</p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* 启用邮件通知 */}
              <div className="input-group" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <label className="input-label" style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 500, display: 'block', marginBottom: 4 }}>
                    启用邮件通知
                  </label>
                  <div className="input-hint" style={{ color: '#64748b', fontSize: 12 }}>开启后系统将通过邮件发送安全告警</div>
                </div>
                <Toggle checked={emailConfig.enabled} onChange={(v) => updateEmailConfig('enabled', v)} />
              </div>

              {/* SMTP 服务器 */}
              <div className="input-group">
                <label className="input-label" style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 500, display: 'block', marginBottom: 4 }}>
                  SMTP 服务器
                </label>
                <input
                  className="input"
                  type="text"
                  value={emailConfig.host}
                  onChange={(e) => updateEmailConfig('host', e.target.value)}
                  placeholder="smtp.example.com"
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: 6,
                    border: '1px solid #334155',
                    background: '#0f172a',
                    color: '#e2e8f0',
                    fontSize: 13,
                    outline: 'none',
                    boxSizing: 'border-box',
                  }}
                />
              </div>

              {/* 端口 */}
              <div className="input-group">
                <label className="input-label" style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 500, display: 'block', marginBottom: 4 }}>
                  端口
                </label>
                <input
                  className="input"
                  type="number"
                  value={emailConfig.port}
                  onChange={(e) => updateEmailConfig('port', Number(e.target.value))}
                  placeholder="587"
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: 6,
                    border: '1px solid #334155',
                    background: '#0f172a',
                    color: '#e2e8f0',
                    fontSize: 13,
                    outline: 'none',
                    boxSizing: 'border-box',
                  }}
                />
                <div className="input-hint" style={{ color: '#64748b', fontSize: 12, marginTop: 4 }}>默认端口: 587 (TLS)</div>
              </div>

              {/* 用户名 */}
              <div className="input-group">
                <label className="input-label" style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 500, display: 'block', marginBottom: 4 }}>
                  用户名
                </label>
                <input
                  className="input"
                  type="text"
                  value={emailConfig.username}
                  onChange={(e) => updateEmailConfig('username', e.target.value)}
                  placeholder="user@example.com"
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: 6,
                    border: '1px solid #334155',
                    background: '#0f172a',
                    color: '#e2e8f0',
                    fontSize: 13,
                    outline: 'none',
                    boxSizing: 'border-box',
                  }}
                />
              </div>

              {/* 密码 */}
              <div className="input-group">
                <label className="input-label" style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 500, display: 'block', marginBottom: 4 }}>
                  密码
                </label>
                <input
                  className="input"
                  type="password"
                  value={emailConfig.password}
                  onChange={(e) => updateEmailConfig('password', e.target.value)}
                  placeholder="留空则不修改"
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: 6,
                    border: '1px solid #334155',
                    background: '#0f172a',
                    color: '#e2e8f0',
                    fontSize: 13,
                    outline: 'none',
                    boxSizing: 'border-box',
                  }}
                />
              </div>

              {/* 发件人地址 */}
              <div className="input-group">
                <label className="input-label" style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 500, display: 'block', marginBottom: 4 }}>
                  发件人地址
                </label>
                <input
                  className="input"
                  type="text"
                  value={emailConfig.from_addr}
                  onChange={(e) => updateEmailConfig('from_addr', e.target.value)}
                  placeholder="sentinel@example.com"
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: 6,
                    border: '1px solid #334155',
                    background: '#0f172a',
                    color: '#e2e8f0',
                    fontSize: 13,
                    outline: 'none',
                    boxSizing: 'border-box',
                  }}
                />
              </div>

              {/* 收件人列表 */}
              <div className="input-group">
                <label className="input-label" style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 500, display: 'block', marginBottom: 4 }}>
                  收件人列表
                </label>
                <textarea
                  className="input"
                  value={emailConfig.recipients}
                  onChange={(e) => updateEmailConfig('recipients', e.target.value)}
                  placeholder={'admin@example.com\nsecurity@example.com'}
                  rows={4}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: 6,
                    border: '1px solid #334155',
                    background: '#0f172a',
                    color: '#e2e8f0',
                    fontSize: 13,
                    outline: 'none',
                    resize: 'vertical',
                    fontFamily: 'inherit',
                    boxSizing: 'border-box',
                  }}
                />
                <div className="input-hint" style={{ color: '#64748b', fontSize: 12, marginTop: 4 }}>每行一个邮箱地址，或使用逗号分隔</div>
              </div>
            </div>
          </div>

          {/* Alert Levels */}
          <div className="card" style={{ padding: 24, marginBottom: 20 }}>
            <h3 className="text-white font-semibold text-sm mb-1">告警级别</h3>
            <p className="text-slate-500 text-xs mb-4">选择需要发送邮件通知的漏洞严重级别</p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {([
                { key: 'critical', label: '严重 (Critical)', desc: '可能导致系统完全被控制的严重漏洞' },
                { key: 'high', label: '高危 (High)', desc: '可直接利用的高风险漏洞' },
                { key: 'medium', label: '中危 (Medium)', desc: '需要特定条件才能利用的中等风险漏洞' },
                { key: 'low', label: '低危 (Low)', desc: '影响较小的低风险漏洞' },
              ] as const).map(({ key, label, desc }) => (
                <div key={key} className="input-group" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div>
                    <span style={{ color: '#e2e8f0', fontSize: 13 }}>{label}</span>
                    <div className="input-hint" style={{ color: '#64748b', fontSize: 12 }}>{desc}</div>
                  </div>
                  <Toggle
                    checked={emailConfig.levels[key]}
                    onChange={(v) => updateEmailLevel(key, v)}
                  />
                </div>
              ))}
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <button
              className="btn-primary"
              onClick={saveEmailConfig}
              disabled={saving}
              style={{
                padding: '8px 16px',
                borderRadius: 6,
                background: '#3b82f6',
                color: '#fff',
                border: 'none',
                fontSize: 13,
                fontWeight: 500,
                cursor: saving ? 'not-allowed' : 'pointer',
                opacity: saving ? 0.7 : 1,
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              {saving && (
                <span style={{ display: 'inline-block', width: 14, height: 14, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.6s linear infinite' }} />
              )}
              保存配置
            </button>
            <button
              className="btn-secondary"
              onClick={sendTestEmail}
              disabled={saving || !emailConfig.enabled}
              style={{
                padding: '8px 16px',
                borderRadius: 6,
                background: '#1e293b',
                color: '#94a3b8',
                border: '1px solid #334155',
                fontSize: 13,
                fontWeight: 500,
                cursor: saving || !emailConfig.enabled ? 'not-allowed' : 'pointer',
                opacity: saving || !emailConfig.enabled ? 0.5 : 1,
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              发送测试邮件
            </button>
          </div>

          {testResult && (
            <div
              style={{
                marginTop: 16,
                padding: '10px 16px',
                borderRadius: 6,
                fontSize: 13,
                color: testResult.includes('成功') ? '#86efac' : '#fca5a5',
                background: testResult.includes('成功') ? 'rgba(22,163,74,0.1)' : 'rgba(220,38,38,0.1)',
                border: `1px solid ${testResult.includes('成功') ? 'rgba(22,163,74,0.3)' : 'rgba(220,38,38,0.3)'}`,
              }}
            >
              {testResult}
            </div>
          )}
        </div>
      )}

      {/* ===== Tab 2: 告警规则 ===== */}
      {activeTab === 'alert' && (
        <div>
          {/* 漏洞发现通知 */}
          <div className="card" style={{ padding: 24, marginBottom: 20 }}>
            <h3 className="text-white font-semibold text-sm mb-1">漏洞发现通知</h3>
            <p className="text-slate-500 text-xs mb-4">
              当扫描发现新漏洞时，根据严重级别发送实时告警通知
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {([
                { key: 'critical', label: '严重漏洞', desc: '发现 Critical 级别漏洞时立即通知' },
                { key: 'high', label: '高危漏洞', desc: '发现 High 级别漏洞时立即通知' },
                { key: 'medium', label: '中危漏洞', desc: '发现 Medium 级别漏洞时立即通知' },
                { key: 'low', label: '低危漏洞', desc: '发现 Low 级别漏洞时立即通知' },
              ] as const).map(({ key, label, desc }) => (
                <div key={key} className="input-group" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div>
                    <span style={{ color: '#e2e8f0', fontSize: 13 }}>{label}</span>
                    <div className="input-hint" style={{ color: '#64748b', fontSize: 12 }}>{desc}</div>
                  </div>
                  <Toggle
                    checked={alertRules.alert_on[key]}
                    onChange={(v) => updateAlertOn(key, v)}
                  />
                </div>
              ))}
            </div>
          </div>

          {/* 每日安全摘要 */}
          <div className="card" style={{ padding: 24, marginBottom: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <h3 className="text-white font-semibold text-sm mb-1">每日安全摘要</h3>
                <p className="text-slate-500 text-xs">
                  每天定时发送安全摘要报告，汇总当日漏洞扫描情况
                </p>
              </div>
              <Toggle
                checked={alertRules.daily_digest}
                onChange={(v) => updateAlertRules('daily_digest', v)}
              />
            </div>
          </div>

          {/* 每周安全报告 */}
          <div className="card" style={{ padding: 24, marginBottom: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <h3 className="text-white font-semibold text-sm mb-1">每周安全报告</h3>
                <p className="text-slate-500 text-xs">
                  每周发送安全态势报告，包含趋势分析和统计汇总
                </p>
              </div>
              <Toggle
                checked={alertRules.weekly_report}
                onChange={(v) => updateAlertRules('weekly_report', v)}
              />
            </div>
          </div>

          {/* Save Button */}
          <button
            className="btn-primary"
            onClick={saveAlertRules}
            disabled={saving}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              background: '#3b82f6',
              color: '#fff',
              border: 'none',
              fontSize: 13,
              fontWeight: 500,
              cursor: saving ? 'not-allowed' : 'pointer',
              opacity: saving ? 0.7 : 1,
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            {saving && (
              <span style={{ display: 'inline-block', width: 14, height: 14, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.6s linear infinite' }} />
            )}
            保存告警规则
          </button>
        </div>
      )}

      {/* ===== Tab 3: 门禁策略 ===== */}
      {activeTab === 'gate' && (
        <div>
          {/* Gate Mode */}
          <div className="card" style={{ padding: 24, marginBottom: 20 }}>
            <h3 className="text-white font-semibold text-sm mb-1">安全门禁模式</h3>
            <p className="text-slate-500 text-xs mb-4">
              设置 CI/CD 管道中安全门禁的整体行为模式
            </p>

            <div style={{ display: 'flex', gap: 12 }}>
              {([
                { key: 'block', label: '阻断模式', desc: '门禁不通过时阻断 CI/CD 流水线，禁止部署' },
                { key: 'warn', label: '告警模式', desc: '门禁不通过时仅发出告警，不阻断部署' },
              ] as const).map(({ key, label, desc }) => (
                <div
                  key={key}
                  onClick={() => setGatePolicy(prev => ({ ...prev, gate_mode: key }))}
                  style={{
                    flex: 1,
                    padding: '16px',
                    borderRadius: 8,
                    border: gatePolicy.gate_mode === key ? '2px solid #3b82f6' : '2px solid #334155',
                    background: gatePolicy.gate_mode === key ? 'rgba(59,130,246,0.08)' : '#0f172a',
                    cursor: 'pointer',
                    transition: 'border-color 0.2s, background 0.2s',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <div style={{
                      width: 16, height: 16, borderRadius: '50%',
                      border: gatePolicy.gate_mode === key ? '4px solid #3b82f6' : '2px solid #475569',
                      transition: 'border 0.2s',
                    }} />
                    <span style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{label}</span>
                  </div>
                  <div className="input-hint" style={{ color: '#64748b', fontSize: 12, paddingLeft: 24 }}>{desc}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Per-Severity Rules */}
          <div className="card" style={{ padding: 24, marginBottom: 20 }}>
            <h3 className="text-white font-semibold text-sm mb-1">漏洞级别处置规则</h3>
            <p className="text-slate-500 text-xs mb-4">
              针对不同严重级别的漏洞，设定扫描完成后对 CI/CD 流水线的处置动作
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {([
                { key: 'critical', color: '#dc2626', bg: 'rgba(220,38,38,0.08)', label: 'Critical（严重）', desc: '可能导致系统完全被控制' },
                { key: 'high', color: '#f97316', bg: 'rgba(249,115,22,0.08)', label: 'High（高危）', desc: '可直接利用的高风险漏洞' },
                { key: 'medium', color: '#eab308', bg: 'rgba(234,179,8,0.08)', label: 'Medium（中危）', desc: '需特定条件才能利用' },
                { key: 'low', color: '#22c55e', bg: 'rgba(34,197,94,0.08)', label: 'Low（低危）', desc: '影响较小的低风险漏洞' },
              ] as const).map(({ key, color, bg, label, desc }) => (
                <div
                  key={key}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '12px 16px', borderRadius: 6,
                    background: bg, border: `1px solid ${color}20`,
                  }}
                >
                  <div>
                    <span style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 500 }}>{label}</span>
                    <div className="input-hint" style={{ color: '#64748b', fontSize: 12 }}>{desc}</div>
                  </div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    {(['pass', 'warn', 'block'] as const).map(action => {
                      const isActive = gatePolicy.gate_rules[key] === action
                      const actionColors: Record<string, { bg: string; text: string; border: string }> = {
                        pass: { bg: isActive ? 'rgba(34,197,94,0.15)' : 'transparent', text: isActive ? '#22c55e' : '#475569', border: isActive ? '#22c55e' : '#334155' },
                        warn: { bg: isActive ? 'rgba(249,115,22,0.15)' : 'transparent', text: isActive ? '#f97316' : '#475569', border: isActive ? '#f97316' : '#334155' },
                        block: { bg: isActive ? 'rgba(220,38,38,0.15)' : 'transparent', text: isActive ? '#dc2626' : '#475569', border: isActive ? '#dc2626' : '#334155' },
                      }
                      const actionLabels: Record<string, string> = { pass: '放行', warn: '告警', block: '阻断' }
                      const c = actionColors[action]
                      return (
                        <button
                          key={action}
                          onClick={() => updateGateRule(key as keyof GatePolicy['gate_rules'], action)}
                          style={{
                            padding: '4px 12px', borderRadius: 4,
                            fontSize: 12, fontWeight: isActive ? 600 : 400,
                            border: `1px solid ${c.border}`,
                            background: c.bg, color: c.text,
                            cursor: 'pointer',
                            transition: 'all 0.15s',
                          }}
                        >
                          {actionLabels[action]}
                        </button>
                      )
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Rule Preview */}
          <div className="card" style={{ padding: 24, marginBottom: 20 }}>
            <h3 className="text-white font-semibold text-sm mb-1">门禁规则预览</h3>
            <p className="text-slate-500 text-xs mb-4">当前配置下的门禁行为</p>

            <div style={{
              padding: 16, borderRadius: 6,
              background: '#0f172a', border: '1px solid #334155',
              fontSize: 13, fontFamily: 'monospace', lineHeight: 1.8,
            }}>
              <div style={{ color: '#64748b', marginBottom: 4 }}># 扫描完成后，按以下规则判断：</div>
              {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
                const rule = gatePolicy.gate_rules[sev]
                const actionText = rule === 'block' ? '阻断流水线' : rule === 'warn' ? '发送告警' : '放行通过'
                const color = rule === 'block' ? '#dc2626' : rule === 'warn' ? '#f97316' : '#22c55e'
                const sevColors: Record<string, string> = { critical: '#dc2626', high: '#f97316', medium: '#eab308', low: '#22c55e' }
                return (
                  <div key={sev}>
                    <span style={{ color: sevColors[sev] }}>  {sev.toUpperCase().padEnd(10)}</span>
                    <span style={{ color: '#94a3b8' }}>→ </span>
                    <span style={{ color }}>{actionText}</span>
                  </div>
                )
              })}
              <div style={{ color: '#64748b', marginTop: 8 }}># 门禁模式: {gatePolicy.gate_mode === 'block' ? '阻断模式（不通过则禁止部署）' : '告警模式（仅告警不阻断）'}</div>
            </div>
          </div>

          {/* Webhook Token */}
          <div className="card" style={{ padding: 24, marginBottom: 20 }}>
            <h3 className="text-white font-semibold text-sm mb-1">Webhook Token</h3>
            <p className="text-slate-500 text-xs mb-4">
              CI/CD 管道调用 Webhook 时的认证凭据。留空表示不校验 Token（开发模式）。
            </p>

            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input
                className="input"
                type="text"
                value={gatePolicy.token}
                onChange={(e) => setGatePolicy(prev => ({ ...prev, token: e.target.value }))}
                placeholder="留空则不校验 Token"
                readOnly
                style={{
                  flex: 1,
                  padding: '8px 12px', borderRadius: 6,
                  border: '1px solid #334155', background: '#0f172a',
                  color: '#e2e8f0', fontSize: 13, fontFamily: 'monospace',
                  outline: 'none', boxSizing: 'border-box',
                }}
              />
              <button
                onClick={regenerateToken}
                disabled={saving}
                style={{
                  padding: '8px 14px', borderRadius: 6,
                  background: '#1e293b', color: '#f97316',
                  border: '1px solid #f97316/30',
                  fontSize: 13, fontWeight: 500,
                  cursor: saving ? 'not-allowed' : 'pointer',
                  opacity: saving ? 0.5 : 1, whiteSpace: 'nowrap',
                }}
              >
                重新生成
              </button>
            </div>
            <div className="input-hint" style={{ color: '#64748b', fontSize: 12, marginTop: 6 }}>
              用法: curl -X POST .../api/webhooks/scan?token={gatePolicy.token || '<YOUR_TOKEN>'}
            </div>
          </div>

          {/* Save Button */}
          <button
            className="btn-primary"
            onClick={saveGatePolicy}
            disabled={saving}
            style={{
              padding: '8px 16px',
              borderRadius: 6,
              background: '#3b82f6',
              color: '#fff',
              border: 'none',
              fontSize: 13,
              fontWeight: 500,
              cursor: saving ? 'not-allowed' : 'pointer',
              opacity: saving ? 0.7 : 1,
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            {saving && (
              <span style={{ display: 'inline-block', width: 14, height: 14, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.6s linear infinite' }} />
            )}
            保存门禁策略
          </button>
        </div>
      )}

      {/* ===== Tab 4: 数据备份 ===== */}
      {activeTab === 'backup' && (
        <div>
          <div className="card" style={{ padding: 24, marginBottom: 20 }}>
            <h3 className="text-white font-semibold text-sm mb-1">数据库备份与恢复</h3>
            <p className="text-slate-500 text-xs mb-4">生成当前数据库快照，或从快照 / 上传文件恢复（恢复前自动备份当前状态，可随时回滚）</p>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <button
                onClick={createBackup}
                disabled={backupBusy}
                style={{ padding: '8px 18px', background: '#3b82f6', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', fontSize: 14 }}
              >
                {backupBusy ? '处理中...' : '生成备份快照'}
              </button>
              <label
                style={{ padding: '8px 18px', background: '#334155', color: '#e2e8f0', border: '1px solid #475569', borderRadius: 6, cursor: 'pointer', fontSize: 14 }}
              >
                上传文件恢复
                <input type="file" accept=".db" onChange={restoreFromFile} style={{ display: 'none' }} />
              </label>
            </div>
          </div>

          <div className="card" style={{ padding: 24 }}>
            <h3 className="text-white font-semibold text-sm mb-3">备份列表</h3>
            {backups.length === 0 ? (
              <p className="text-slate-500 text-sm">暂无备份，点击上方按钮生成。</p>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ color: '#94a3b8', textAlign: 'left', borderBottom: '1px solid #1e293b' }}>
                    <th style={{ padding: '8px 10px' }}>文件名</th>
                    <th style={{ padding: '8px 10px' }}>大小</th>
                    <th style={{ padding: '8px 10px' }}>创建时间</th>
                    <th style={{ padding: '8px 10px' }}>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {backups.map((b) => (
                    <tr key={b.filename} style={{ borderBottom: '1px solid #1e293b' }}>
                      <td style={{ padding: '8px 10px', color: '#e2e8f0' }}>{b.filename}</td>
                      <td style={{ padding: '8px 10px', color: '#94a3b8' }}>{(b.size / 1024).toFixed(1)} KB</td>
                      <td style={{ padding: '8px 10px', color: '#94a3b8' }}>{b.created_at}</td>
                      <td style={{ padding: '8px 10px', display: 'flex', gap: 8 }}>
                        <button
                          onClick={() => restoreBackup(b.filename)}
                          disabled={backupBusy}
                          style={{ padding: '4px 12px', background: '#334155', color: '#e2e8f0', border: '1px solid #475569', borderRadius: 4, cursor: 'pointer', fontSize: 12 }}
                        >
                          恢复
                        </button>
                        <button
                          onClick={() => downloadBackup(b.filename)}
                          style={{ padding: '4px 12px', background: 'transparent', color: '#60a5fa', border: '1px solid #1d4ed8', borderRadius: 4, cursor: 'pointer', fontSize: 12 }}
                        >
                          下载
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ===== Tab 5: 通知渠道 ===== */}
      {activeTab === 'channels' && (
        <div>
          <div className="card" style={{ padding: 24, marginBottom: 20 }}>
            <h3 className="text-white font-semibold text-sm mb-1">通知渠道（飞书）</h3>
            <p className="text-slate-500 text-xs mb-4">配置飞书机器人 Webhook 后，新建 / 解决工单会自动推送卡片到飞书群。Secret 可选（飞书自定义机器人签名校验）。</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12, maxWidth: 620 }}>
              <input
                placeholder="渠道名称（默认：飞书）"
                value={channelForm.name}
                onChange={(e) => setChannelForm({ ...channelForm, name: e.target.value })}
                style={{ padding: '8px 10px', background: '#0f172a', border: '1px solid #334155', borderRadius: 6, color: '#e2e8f0', fontSize: 14 }}
              />
              <input
                placeholder="飞书 Webhook 地址（https://open.feishu.cn/open-apis/bot/v2/hook/...）"
                value={channelForm.webhook_url}
                onChange={(e) => setChannelForm({ ...channelForm, webhook_url: e.target.value })}
                style={{ padding: '8px 10px', background: '#0f172a', border: '1px solid #334155', borderRadius: 6, color: '#e2e8f0', fontSize: 14 }}
              />
              <input
                placeholder="Secret（可选，机器人安全设置中的签名校验密钥）"
                value={channelForm.secret}
                onChange={(e) => setChannelForm({ ...channelForm, secret: e.target.value })}
                style={{ padding: '8px 10px', background: '#0f172a', border: '1px solid #334155', borderRadius: 6, color: '#e2e8f0', fontSize: 14 }}
              />
              <label style={{ color: '#cbd5e1', fontSize: 13, display: 'flex', alignItems: 'center', gap: 8 }}>
                <input
                  type="checkbox"
                  checked={channelForm.enabled}
                  onChange={(e) => setChannelForm({ ...channelForm, enabled: e.target.checked })}
                />
                启用推送
              </label>
              <button
                onClick={addChannel}
                disabled={channelBusy}
                style={{ padding: '8px 18px', background: '#3b82f6', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', fontSize: 14, alignSelf: 'flex-start' }}
              >
                {channelBusy ? '处理中...' : '添加飞书渠道'}
              </button>
            </div>
          </div>

          <div className="card" style={{ padding: 24 }}>
            <h3 className="text-white font-semibold text-sm mb-3">已配置渠道</h3>
            {channels.length === 0 ? (
              <p className="text-slate-500 text-sm">暂无渠道，先添加飞书 Webhook。</p>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ color: '#94a3b8', textAlign: 'left', borderBottom: '1px solid #1e293b' }}>
                    <th style={{ padding: '8px 10px' }}>名称</th>
                    <th style={{ padding: '8px 10px' }}>类型</th>
                    <th style={{ padding: '8px 10px' }}>Webhook</th>
                    <th style={{ padding: '8px 10px' }}>状态</th>
                    <th style={{ padding: '8px 10px' }}>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {channels.map((c) => (
                    <tr key={c.id} style={{ borderBottom: '1px solid #1e293b' }}>
                      <td style={{ padding: '8px 10px', color: '#e2e8f0' }}>{c.name}</td>
                      <td style={{ padding: '8px 10px', color: '#94a3b8' }}>{c.channel_type}</td>
                      <td style={{ padding: '8px 10px', color: '#94a3b8', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.webhook_url}</td>
                      <td style={{ padding: '8px 10px', color: c.enabled ? '#22c55e' : '#94a3b8' }}>{c.enabled ? '已启用' : '已停用'}</td>
                      <td style={{ padding: '8px 10px', display: 'flex', gap: 8 }}>
                        <button
                          onClick={() => toggleChannel(c)}
                          style={{ padding: '4px 12px', background: '#334155', color: '#e2e8f0', border: '1px solid #475569', borderRadius: 4, cursor: 'pointer', fontSize: 12 }}
                        >
                          {c.enabled ? '停用' : '启用'}
                        </button>
                        <button
                          onClick={() => deleteChannel(c.id)}
                          style={{ padding: '4px 12px', background: 'transparent', color: '#f87171', border: '1px solid #7f1d1d', borderRadius: 4, cursor: 'pointer', fontSize: 12 }}
                        >
                          删除
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ===== Tab 6: 外观（Logo） ===== */}
      {activeTab === 'appearance' && (
        <>
        <div className="card" style={{ padding: 24 }}>
          <h3 className="text-white font-semibold text-sm mb-1">{t('appearance.logo')}</h3>
          <p className="text-slate-500 text-xs mb-4">{t('appearance.logoDesc')}</p>
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-2xl bg-surface-800 border border-white/10 flex items-center justify-center overflow-hidden">
              {logoUrl ? (
                <img src={logoUrl} alt="logo" className="w-full h-full object-cover" />
              ) : (
                <span className="text-slate-500 text-xs">默认</span>
              )}
            </div>
            <div className="flex flex-col gap-2">
              {isAdmin ? (
                <>
                  <label
                    style={{ padding: '8px 18px', background: '#3b82f6', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', fontSize: 14 }}
                  >
                    {logoBusy ? t('common.loading') : t('appearance.upload')}
                    <input type="file" accept="image/png,image/jpeg,image/svg+xml,image/gif,image/webp" onChange={uploadLogoFile} style={{ display: 'none' }} />
                  </label>
                  {logoUrl && (
                    <button
                      onClick={removeLogoFile}
                      disabled={logoBusy}
                      style={{ padding: '8px 18px', background: 'transparent', color: '#f87171', border: '1px solid #7f1d1d', borderRadius: 6, cursor: 'pointer', fontSize: 14, alignSelf: 'flex-start' }}
                    >
                      {t('appearance.remove')}
                    </button>
                  )}
                </>
              ) : (
                <p className="text-slate-500 text-sm">仅管理员可修改 Logo</p>
              )}
            </div>
          </div>
          <p className="text-slate-600 text-xs mt-6">{t('appearance.themeHint')}</p>
        </div>

        {isAdmin && (
          <div className="card" style={{ padding: 24, marginTop: 20 }}>
            <h3 className="text-white font-semibold text-sm mb-1">注册策略</h3>
            <p className="text-slate-500 text-xs mb-4">开放后，任何人可自助注册账号。出于安全考虑，默认关闭。</p>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={allowRegister}
                disabled={regBusy}
                onChange={async (e) => {
                  const next = e.target.checked
                  setAllowRegister(next)
                  setRegBusy(true)
                  try {
                    await api.put('/settings/registration', { allow_public_register: next })
                    showToast('success', next ? '已开放公开注册' : '已关闭公开注册')
                  } catch {
                    setAllowRegister(!next)
                    showToast('error', '更新失败')
                  } finally { setRegBusy(false) }
                }}
              />
              <span className="text-sm text-slate-300">{allowRegister ? '公开注册：开启' : '公开注册：关闭'}</span>
            </label>
          </div>
        )}
        </>
      )}

      {/* ===== Tab 7: AI 模型管理 ===== */}
      {activeTab === 'ai' && (
        <div>
          <div className="card" style={{ padding: 24, marginBottom: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
              <h3 className="text-white font-semibold text-sm">AI 模型供应商</h3>
              {isAdmin && (
                <button
                  onClick={() => { setEditingProviderId(null); setProviderForm(emptyProviderForm); setShowProviderForm(s => !s) }}
                  style={{ padding: '6px 14px', background: showProviderForm ? '#334155' : '#3b82f6', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', fontSize: 13 }}
                >
                  {showProviderForm ? '收起' : '+ 新增供应商'}
                </button>
              )}
            </div>
            <p className="text-slate-500 text-xs mb-4">配置本地 Ollama 或第三方 OpenAI 兼容模型（DeepSeek / 通义 / GPT / 智谱等）。切换激活项即时生效，无需重启。</p>

            {showProviderForm && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 8, padding: 16, borderRadius: 8, background: '#0f172a', border: '1px solid #334155' }}>
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  <input
                    placeholder="名称（如：Ollama 本地 / DeepSeek）"
                    value={providerForm.name}
                    onChange={(e) => setProviderForm({ ...providerForm, name: e.target.value })}
                    style={aiInputStyle}
                  />
                  <select
                    value={providerForm.provider_type}
                    onChange={(e) => setProviderForm({ ...providerForm, provider_type: e.target.value })}
                    style={aiInputStyle}
                  >
                    <option value="ollama">Ollama（本地，免 Key）</option>
                    <option value="openai">OpenAI 兼容（DeepSeek/通义/GPT/智谱…）</option>
                    <option value="azure">Azure OpenAI</option>
                  </select>
                </div>
                <input
                  placeholder="API 地址（如 http://10.80.3.180:11434/v1 或 https://api.deepseek.com/v1）"
                  value={providerForm.api_base}
                  onChange={(e) => setProviderForm({ ...providerForm, api_base: e.target.value })}
                  style={aiInputStyle}
                />
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  <input
                    placeholder="模型名称（如 qwen3:0.6b / deepseek-chat / gpt-4o）"
                    value={providerForm.model}
                    onChange={(e) => setProviderForm({ ...providerForm, model: e.target.value })}
                    style={aiInputStyle}
                  />
                  <input
                    type="password"
                    placeholder={editingProviderId ? '留空则不修改' : 'API Key（Ollama 留空）'}
                    value={providerForm.api_key}
                    onChange={(e) => setProviderForm({ ...providerForm, api_key: e.target.value })}
                    style={aiInputStyle}
                  />
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    onClick={saveProvider}
                    disabled={providerBusy}
                    style={{ padding: '7px 16px', background: '#3b82f6', color: '#fff', border: 'none', borderRadius: 6, cursor: providerBusy ? 'not-allowed' : 'pointer', fontSize: 13, opacity: providerBusy ? 0.7 : 1 }}
                  >
                    {providerBusy ? '保存中...' : (editingProviderId ? '保存修改' : '添加')}
                  </button>
                  <button
                    onClick={() => { setShowProviderForm(false); setEditingProviderId(null); setProviderForm(emptyProviderForm) }}
                    style={{ padding: '7px 16px', background: 'transparent', color: '#94a3b8', border: '1px solid #475569', borderRadius: 6, cursor: 'pointer', fontSize: 13 }}
                  >
                    取消
                  </button>
                </div>
              </div>
            )}

            {providers.length === 0 ? (
              <p className="text-slate-500 text-sm mt-4">暂无供应商，点击右上角新增。</p>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13, marginTop: 8 }}>
                <thead>
                  <tr style={{ color: '#94a3b8', textAlign: 'left', borderBottom: '1px solid #1e293b' }}>
                    <th style={{ padding: '8px 10px' }}>名称</th>
                    <th style={{ padding: '8px 10px' }}>类型</th>
                    <th style={{ padding: '8px 10px' }}>模型</th>
                    <th style={{ padding: '8px 10px' }}>API 地址</th>
                    <th style={{ padding: '8px 10px' }}>状态</th>
                    <th style={{ padding: '8px 10px' }}>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {providers.map((p) => (
                    <tr key={p.id} style={{ borderBottom: '1px solid #1e293b' }}>
                      <td style={{ padding: '8px 10px', color: '#e2e8f0' }}>{p.name}</td>
                      <td style={{ padding: '8px 10px', color: '#94a3b8' }}>{p.provider_type}</td>
                      <td style={{ padding: '8px 10px', color: '#e2e8f0' }}>{p.model}</td>
                      <td style={{ padding: '8px 10px', color: '#94a3b8', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.api_base}</td>
                      <td style={{ padding: '8px 10px' }}>
                        {p.is_active
                          ? <span style={{ color: '#22c55e', fontSize: 12 }}>● 使用中</span>
                          : <span style={{ color: '#64748b', fontSize: 12 }}>未激活</span>}
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {!p.is_active && (
                            <button onClick={() => activateProvider(p.id)} style={aiBtn('#3b82f6', '#1d4ed8')}>激活</button>
                          )}
                          <button onClick={() => testProvider(p.id)} disabled={providerTestingId === p.id} style={aiBtn('#334155', '#475569')}>
                            {providerTestingId === p.id ? '测试中...' : '测试'}
                          </button>
                          {isAdmin && (
                            <>
                              <button onClick={() => editProvider(p)} style={aiBtn('transparent', '#475569', '#60a5fa')}>编辑</button>
                              <button onClick={() => deleteProvider(p.id)} style={aiBtn('transparent', '#7f1d1d', '#f87171')}>删除</button>
                            </>
                          )}
                        </div>
                        {providerTestResult && providerTestResult.id === p.id && (
                          <div style={{
                            marginTop: 6, padding: '6px 10px', borderRadius: 6, fontSize: 12,
                            color: providerTestResult.reachable ? '#86efac' : '#fca5a5',
                            background: providerTestResult.reachable ? 'rgba(22,163,74,0.1)' : 'rgba(220,38,38,0.1)',
                            border: `1px solid ${providerTestResult.reachable ? 'rgba(22,163,74,0.3)' : 'rgba(220,38,38,0.3)'}`,
                          }}>
                            {providerTestResult.reachable ? (providerTestResult.reply_ok ? '✓ 连接正常，模型可调用' : '⚠ 连接可达但调用失败') : '✗ 连接失败'}
                            {providerTestResult.detail ? ` — ${providerTestResult.detail}` : ''}
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="card" style={{ padding: 24 }}>
            <h3 className="text-white font-semibold text-sm mb-1">使用说明</h3>
            <ul style={{ color: '#94a3b8', fontSize: 13, lineHeight: 1.9, paddingLeft: 20, margin: 0 }}>
              <li>本地 <b style={{ color: '#e2e8f0' }}>Ollama</b> 已默认配置并激活，无需 Key，断网也可用。</li>
              <li>第三方模型填 <b style={{ color: '#e2e8f0' }}>OpenAI 兼容</b> 地址即可（DeepSeek / 通义千问 / GPT / 智谱 GLM / Kimi 等），API Key 加密存储。</li>
              <li>「激活」切换即时生效，漏洞分析、AI 问答、预生成修复建议均自动改用新模型，<b style={{ color: '#e2e8f0' }}>无需重启后端</b>。</li>
              <li>换用更大的模型（如 gpt-4o / deepseek-chat / qwen-max）可显著提升漏洞分析与修复建议质量。</li>
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}
