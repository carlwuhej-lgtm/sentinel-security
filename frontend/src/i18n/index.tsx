import { createContext, useContext, useState, ReactNode, useCallback } from 'react'

export type Lang = 'zh' | 'en'
const LANG_KEY = 'sentinel_lang'

type Dict = Record<string, string>

// 核心界面双语词典（其余页面后续分批补全）
const zh: Dict = {
  // 导航
  'nav.today': '今日概览',
  'nav.vulnerabilities': '漏洞管理',
  'nav.scans': '扫描中心',
  'nav.tickets': '工单中心',
  'nav.alerts': '告警中心',
  'nav.investigation': '事件调查',
  'nav.ai': 'AI 分析',
  'nav.knowledge': '知识库',
  'nav.projects': '项目管理',
  'nav.tools': '工具集成',
  'nav.assets': '资产管理',
  'nav.rules': '规则管理',
  'nav.reports': '报告中心',
  'nav.audit': '审计日志',
  'nav.users': '用户管理',
  'nav.settings': '系统设置',

  // 导航分组
  'group.overview': '概览',
  'group.workflow': '安全工作流',
  'group.analysis': '深入分析',
  'group.config': '配置（前置项）',
  'group.compliance': '报告与合规',
  'group.system': '系统',

  // 通用
  'common.search': '搜索',
  'common.logout': '退出登录',
  'common.relogin': '重新登录',
  'common.changePassword': '修改密码',
  'common.save': '保存',
  'common.cancel': '取消',
  'common.loading': '加载中…',
  'common.confirm': '确定',

  // 主题 / 语言
  'theme.title': '主题',
  'theme.choose': '选择主题',
  'lang.title': '语言',

  // 登录
  'login.brandSubtitle': '一人安全助手',
  'login.subtitle': '应用安全智能管理平台',
  'login.desc': '覆盖 SAST · SCA · DAST 的全栈安全扫描与漏洞生命周期管理',
  'login.features.multiTool': '多工具集成扫描',
  'login.features.ai': 'AI 智能漏洞分析',
  'login.features.alert': '实时告警通知',
  'login.features.lifecycle': '漏洞全生命周期管理',
  'login.title': '登录',
  'login.defaultHint': '默认账号 admin@sentinel.io / admin123',
  'login.email': '邮箱地址',
  'login.password': '密码',
  'login.submit': '登录',
  'login.submitting': '登录中…',
  'login.noAccount': '还没有账号？',
  'login.register': '立即注册',

  // 设置
  'settings.title': '系统设置',
  'settings.subtitle': '平台配置、安全策略与系统维护',
  'settings.tab.email': '邮件通知',
  'settings.tab.alert': '告警规则',
  'settings.tab.gate': '门禁策略',
  'settings.tab.backup': '数据备份',
  'settings.tab.channels': '通知渠道',
  'settings.tab.appearance': '外观',

  // 今日概览
  'today.startScan': '开始扫描',
  'today.newProject': '新建项目',
  'today.summary': '摘要',
  'today.range.today': '今日',
  'today.range.7d': '近 7 天',
  'today.range.30d': '本月',
  'today.range.all': '全部',
  'today.welcome': '欢迎使用 Sentinel',
  'today.guideDesc': '还没有项目。先接入一个代码仓库，然后发起第一次扫描，开始发现安全问题。',
  'today.createFirst': '创建第一个项目',
  'today.stat.openVulns': '未修复漏洞',
  'today.stat.pendingAlerts': '待处理告警',
  'today.stat.openTickets': '进行中工单',
  'today.stat.slaBreached': 'SLA已超时',
  'today.stat.fixRate': '修复率',
  'today.stat.new': '新增',
  'today.refresh': '刷新',
  'today.allClear.title': '一切尽在掌控',
  'today.allClear.desc': '没有需要立即处理的紧急事项',
  'today.allClear.fixed1': '本期修复了',
  'today.allClear.fixed2': '个漏洞',
  'today.allClear.rate': '修复率',
  'today.sec.urgent': '需要立即修复',
  'today.sec.slaBreached': 'SLA 已超时',
  'today.sec.alerts': '待处理告警',
  'today.sec.slaExpiring': 'SLA 即将到期（24h）',

  // 外观 Tab
  'appearance.logo': '平台 Logo',
  'appearance.logoDesc': '上传自定义 Logo（PNG / JPG / SVG 等），全站侧边栏与登录页生效。仅管理员可修改。',
  'appearance.upload': '上传 Logo',
  'appearance.remove': '移除 Logo',
  'appearance.preview': '预览',
  'appearance.themeHint': '主题配色为每用户本地偏好，点击右上角调色板按钮即可切换。',
}

const en: Dict = {
  'nav.today': 'Today',
  'nav.vulnerabilities': 'Vulnerabilities',
  'nav.scans': 'Scans',
  'nav.tickets': 'Tickets',
  'nav.alerts': 'Alerts',
  'nav.investigation': 'Investigation',
  'nav.ai': 'AI Analysis',
  'nav.knowledge': 'Knowledge Base',
  'nav.projects': 'Projects',
  'nav.tools': 'Tool Integrations',
  'nav.assets': 'Assets',
  'nav.rules': 'Rules',
  'nav.reports': 'Reports',
  'nav.audit': 'Audit Log',
  'nav.users': 'User Management',
  'nav.settings': 'Settings',

  'group.overview': 'Overview',
  'group.workflow': 'Security Workflow',
  'group.analysis': 'Deep Analysis',
  'group.config': 'Configuration',
  'group.compliance': 'Reports & Compliance',
  'group.system': 'System',

  'common.search': 'Search',
  'common.logout': 'Sign out',
  'common.relogin': 'Re-login',
  'common.changePassword': 'Change Password',
  'common.save': 'Save',
  'common.cancel': 'Cancel',
  'common.loading': 'Loading…',
  'common.confirm': 'OK',

  'theme.title': 'Theme',
  'theme.choose': 'Choose Theme',
  'lang.title': 'Language',

  'login.brandSubtitle': 'Your Security Copilot',
  'login.subtitle': 'Application Security Platform',
  'login.desc': 'Full-stack security scanning (SAST · SCA · DAST) & vulnerability lifecycle management',
  'login.features.multiTool': 'Multi-tool integrated scanning',
  'login.features.ai': 'AI-powered vulnerability analysis',
  'login.features.alert': 'Real-time alerting',
  'login.features.lifecycle': 'Full vulnerability lifecycle management',
  'login.title': 'Sign In',
  'login.defaultHint': 'Default: admin@sentinel.io / admin123',
  'login.email': 'Email',
  'login.password': 'Password',
  'login.submit': 'Sign In',
  'login.submitting': 'Signing in…',
  'login.noAccount': 'No account yet?',
  'login.register': 'Register now',

  'settings.title': 'System Settings',
  'settings.subtitle': 'Platform configuration, security policy & maintenance',
  'settings.tab.email': 'Email',
  'settings.tab.alert': 'Alert Rules',
  'settings.tab.gate': 'Gate Policy',
  'settings.tab.backup': 'Backup',
  'settings.tab.channels': 'Channels',
  'settings.tab.appearance': 'Appearance',

  'today.startScan': 'Start Scan',
  'today.newProject': 'New Project',
  'today.summary': 'Summary',
  'today.range.today': 'Today',
  'today.range.7d': 'Last 7 days',
  'today.range.30d': 'This month',
  'today.range.all': 'All',
  'today.welcome': 'Welcome to Sentinel',
  'today.guideDesc': 'No projects yet. Connect a code repository, then run your first scan to start finding security issues.',
  'today.createFirst': 'Create first project',
  'today.stat.openVulns': 'Open vulnerabilities',
  'today.stat.pendingAlerts': 'Pending alerts',
  'today.stat.openTickets': 'Open tickets',
  'today.stat.slaBreached': 'SLA breached',
  'today.stat.fixRate': 'Fix rate',
  'today.stat.new': 'new',
  'today.refresh': 'Refresh',
  'today.allClear.title': 'All under control',
  'today.allClear.desc': 'No urgent items need immediate attention',
  'today.allClear.fixed1': 'Fixed',
  'today.allClear.fixed2': 'vulns this period',
  'today.allClear.rate': 'Fix rate',
  'today.sec.urgent': 'Needs immediate fix',
  'today.sec.slaBreached': 'SLA breached',
  'today.sec.alerts': 'Pending alerts',
  'today.sec.slaExpiring': 'SLA expiring (24h)',

  'appearance.logo': 'Platform Logo',
  'appearance.logoDesc': 'Upload a custom logo (PNG / JPG / SVG …). It appears in the sidebar and login page. Admin only.',
  'appearance.upload': 'Upload Logo',
  'appearance.remove': 'Remove Logo',
  'appearance.preview': 'Preview',
  'appearance.themeHint': 'Theme is a per-user local preference — click the palette button at the top-right to switch.',
}

const DICTS: Record<Lang, Dict> = { zh, en }

interface I18nCtx {
  lang: Lang
  setLang: (l: Lang) => void
  t: (key: string) => string
}

const Ctx = createContext<I18nCtx | null>(null)

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    const v = localStorage.getItem(LANG_KEY)
    return v === 'en' ? 'en' : 'zh'
  })

  const setLang = (l: Lang) => {
    localStorage.setItem(LANG_KEY, l)
    document.documentElement.lang = l === 'en' ? 'en' : 'zh-CN'
    setLangState(l)
  }

  const t = useCallback(
    (key: string) => DICTS[lang][key] ?? DICTS.zh[key] ?? key,
    [lang]
  )

  return <Ctx.Provider value={{ lang, setLang, t }}>{children}</Ctx.Provider>
}

export function useI18n(): I18nCtx {
  const c = useContext(Ctx)
  if (!c) throw new Error('useI18n must be used within I18nProvider')
  return c
}
