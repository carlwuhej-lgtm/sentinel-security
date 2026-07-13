import logging
logger = logging.getLogger(__name__)
"""
哨兵安全平台 — 邮件通知服务

核心能力：
1. 漏洞分配通知：漏洞被指派时，自动生成 AI 修复建议 → 邮件发送给修复人
2. 扫描告警通知：扫描完成后发现 Critical/High 漏洞 → 邮件发送给管理员
3. 手动发送修复通知：前端按钮触发，将修复方案通过邮件发送给指定用户

集成点：
- AI 修复建议：优先使用真实 AI API，未配置时回退到 CWE 知识库
- SMTP 配置：从 email_config 表读取，支持 STARTTLS 和 SSL
- 知识库联动：邮件底部自动匹配相关安全知识库文章
"""

import json
import sqlite3
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from services.crypto_service import decrypt


# ═══════════════════════════════════════════════════════
# CWE 知识库 — AI 未配置时的内置修复方案
# ═══════════════════════════════════════════════════════

CWE_FIX_KNOWLEDGE = {
    "89": {
        "name": "SQL 注入 (SQL Injection)",
        "root_cause": "应用程序将用户输入直接拼接进 SQL 语句，未使用参数化查询。",
        "fix_approaches": [
            {
                "title": "方案一：使用参数化查询（推荐）",
                "language": "python",
                "before": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                "after": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            },
            {
                "title": "方案二：使用 ORM 框架",
                "language": "python",
                "before": 'cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")',
                "after": 'User.query.filter_by(name=name).all()',
            },
        ],
        "verification": "1. 使用 SQLMap 验证注入点已消除\n2. 代码审查确认所有 SQL 使用参数化\n3. 部署 WAF 作为纵深防御",
    },
    "79": {
        "name": "XSS 跨站脚本攻击",
        "root_cause": "应用程序未对用户输入进行 HTML 输出编码，直接将原始数据渲染到页面中。",
        "fix_approaches": [
            {
                "title": "方案一：输出编码（HTML 转义）",
                "language": "python",
                "before": "return f'<div>Hello, {username}!</div>'",
                "after": "from markupsafe import escape\nreturn f'<div>Hello, {escape(username)}!</div>'",
            },
            {
                "title": "方案二：设置 Content-Security-Policy",
                "language": "python",
                "before": "# 响应头中无 CSP",
                "after": "resp.headers['Content-Security-Policy'] = \"default-src 'self'\"",
            },
        ],
        "verification": "1. 在所有输入点注入 XSS payload 验证\n2. 检查 HTTP 响应头 CSP 策略\n3. 使用浏览器 DevTools 确认脚本未执行",
    },
    "798": {
        "name": "硬编码凭证 (Hardcoded Credentials)",
        "root_cause": "源代码中包含明文的密码、API Key 或数据库连接字符串。",
        "fix_approaches": [
            {
                "title": "方案一：迁移到环境变量",
                "language": "python",
                "before": "DB_PASSWORD = 'mysecretpassword123'",
                "after": "import os\nDB_PASSWORD = os.environ['DB_PASSWORD']",
            },
            {
                "title": "方案二：使用密钥管理服务 (KMS/Vault)",
                "language": "python",
                "before": "API_KEY = 'sk-abc123def456'",
                "after": "import hvac\nclient = hvac.Client()\nAPI_KEY = client.secrets.kv.v2.read_secret('api_key')['data']['value']",
            },
        ],
        "verification": "1. grep/secrets 扫描确认无残留硬编码\n2. 验证环境变量或 Vault 配置正确\n3. 立即撤销已泄露的凭证并轮换新密钥",
    },
    "327": {
        "name": "弱密码哈希算法 (Weak Cryptographic Hash)",
        "root_cause": "使用了 SHA256/MD5 等单次哈希存储密码，无法抵御彩虹表和暴力破解。",
        "fix_approaches": [
            {
                "title": "方案一：迁移到 PBKDF2（推荐）",
                "language": "python",
                "before": "import hashlib\npw_hash = hashlib.sha256(password.encode()).hexdigest()",
                "after": "import hashlib, os\nsalt = os.urandom(32)\npw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 260000).hex()",
            },
            {
                "title": "方案二：使用 bcrypt",
                "language": "python",
                "before": "pw_hash = hashlib.sha256(password).hexdigest()",
                "after": "import bcrypt\npw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()",
            },
        ],
        "verification": "1. 新注册用户使用新算法\n2. 旧用户登录时自动升级哈希（rehash）\n3. 代码审查确认无遗留 SHA256 调用",
    },
    "dep-cve": {
        "name": "依赖库 CVE 漏洞",
        "root_cause": "项目使用了包含已知安全漏洞的第三方依赖版本。",
        "fix_approaches": [
            {
                "title": "方案一：升级依赖版本（推荐）",
                "language": "bash",
                "before": "# 使用了漏洞版本\n# pip install requests==2.25.0",
                "after": "# 升级到已修复版本\n# pip install --upgrade requests",
            },
            {
                "title": "方案二：评估影响后临时缓解",
                "language": "python",
                "before": "from vuln_lib import dangerous_func\nresult = dangerous_func(user_input)",
                "after": "from vuln_lib import dangerous_func\nfrom security import sanitize\nresult = dangerous_func(sanitize(user_input))",
            },
        ],
        "verification": "1. 运行 pip audit / npm audit 确认漏洞消除\n2. 回归测试确保升级无破坏性变更\n3. 启用 Dependabot 自动更新监控",
    },
}

DEFAULT_CWE = "89"


def _match_cwe(vuln: dict) -> str:
    """根据漏洞信息匹配 CWE 知识库条目。"""
    cwe_id = str(vuln.get("cwe_id", "") or "")
    title = (vuln.get("title", "") or "").lower()
    desc = (vuln.get("description", "") or "").lower()
    combined = title + " " + desc

    if cwe_id in CWE_FIX_KNOWLEDGE:
        return cwe_id

    for key, info in CWE_FIX_KNOWLEDGE.items():
        if info["name"].lower() in combined:
            return key

    if "sql" in combined and ("inject" in combined or "注入" in combined):
        return "89"
    if "xss" in combined or "跨站" in combined or "cross-site" in combined:
        return "79"
    if "password" in combined or "secret" in combined or "credential" in combined or "密码" in combined or "密钥" in combined or "硬编码" in combined or "hardcod" in combined:
        return "798"
    if "hash" in combined or "sha256" in combined or "md5" in combined or "弱密码" in combined or "弱哈希" in combined:
        return "327"
    if "cve" in combined or "depend" in combined or "依赖" in combined or "supply chain" in combined:
        return "dep-cve"

    return DEFAULT_CWE


def _render_ai_fix_html(ai_text: str, sev_color: str) -> str:
    """把预生成的 AI 修复建议纯文本渲染成邮件 HTML 块。

    - ```代码块``` → <pre><code>
    - 其余按段落输出，保留换行
    """
    import html as _html
    import re as _re

    parts = _re.split(r'```[a-zA-Z0-9]*\n?', ai_text)
    # 奇数索引为代码块内容（以 ``` 分割后，1、3、5... 是代码）
    blocks = []
    for idx, seg in enumerate(parts):
        seg = seg.strip("\n")
        if not seg.strip():
            continue
        if idx % 2 == 1:
            blocks.append(
                f'<pre style="background:#1e293b; color:#86efac; padding:12px; border-radius:6px; '
                f'overflow-x:auto; font-size:13px; line-height:1.6;"><code>{_html.escape(seg)}</code></pre>'
            )
        else:
            safe = _html.escape(seg).replace("\n", "<br>")
            blocks.append(
                f'<p style="margin:8px 0; color:#475569; font-size:14px; line-height:1.8;">{safe}</p>'
            )
    body = "\n".join(blocks)
    return (
        f'<div style="margin:20px 0; padding:16px; background:#f8fafc; '
        f'border-left:4px solid {sev_color}; border-radius:4px;">\n{body}\n</div>'
    )


def _render_kb_links_html(kb_articles: list, base_url: str = "http://localhost:5000") -> str:
    """将知识库文章列表渲染为邮件 HTML 块。"""
    if not kb_articles:
        return ""
    items = ""
    for a in kb_articles:
        url = f"{base_url}/knowledge-base/{a['id']}"
        cat = a.get("category_label", a.get("category", ""))
        items += (
            f'<tr>'
            f'<td style="padding:6px 10px; border-bottom:1px solid #e2e8f0;">📖</td>'
            f'<td style="padding:6px 10px; border-bottom:1px solid #e2e8f0;">'
            f'<a href="{url}" style="color:#3b82f6; text-decoration:none; font-weight:500;">{a["title"]}</a></td>'
            f'<td style="padding:6px 10px; border-bottom:1px solid #e2e8f0; font-size:12px; color:#64748b;">{cat}</td>'
            f'</tr>'
        )
    return f"""
    <div style="margin:20px 0; padding:16px; background:#eff6ff; border-radius:6px;">
        <h4 style="margin:0 0 10px 0; color:#1e3a5f;">📚 相关知识库文章</h4>
        <table style="width:100%; border-collapse:collapse; font-size:14px;">
            {items}
        </table>
    </div>
    """


def _fetch_related_kb(db_path: str, cwe_id: str = "", severity: str = "", 
                       keywords: str = "") -> list:
    """从知识库查找与 CWE/关键词匹配的文章。"""
    if not db_path:
        return []
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        conn.row_factory = sqlite3.Row
        q = "SELECT id, title, category, summary FROM knowledge_articles WHERE is_published=1"
        params = []

        if cwe_id:
            q += " AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)"
            cwe_like = f"%{cwe_id}%"
            params.extend([cwe_like, cwe_like, cwe_like])

        if keywords:
            for kw in keywords.split(",")[:3]:
                kw = kw.strip()
                if not kw:
                    continue
                q += " AND (title LIKE ? OR content LIKE ?)"
                kw_like = f"%{kw}%"
                params.extend([kw_like, kw_like])

        q += " ORDER BY view_count DESC LIMIT 4"
        rows = conn.execute(q, params).fetchall()
        conn.close()

        # 如果 CWE 匹配没结果，尝试按 severity 分类关键词搜索
        if not rows and severity:
            sev_keywords = {
                "CRITICAL": "严重漏洞 紧急修复",
                "HIGH": "高危漏洞 安全加固",
                "MEDIUM": "中危漏洞 安全配置",
            }.get(severity.upper(), "")
            if sev_keywords:
                conn2 = sqlite3.connect(db_path, timeout=5)
                conn2.row_factory = sqlite3.Row
                kw_likes = []
                kw_params = []
                for kw in sev_keywords.split():
                    kw_likes.append("(title LIKE ? OR content LIKE ?)")
                    kw_params.extend([f"%{kw}%", f"%{kw}%"])
                backup_q = f"SELECT id, title, category, summary FROM knowledge_articles WHERE is_published=1 AND ({' OR '.join(kw_likes)}) ORDER BY view_count DESC LIMIT 3"
                rows = conn2.execute(backup_q, kw_params).fetchall()
                conn2.close()

        CATEGORY_LABELS = {
            "web_security": "Web 安全", "supply_chain": "供应链安全",
            "data_security": "数据安全", "ops_process": "运维与流程",
            "tool_guide": "工具指南", "incident_case": "事件案例",
            "compliance": "合规与标准", "general": "综合",
        }
        return [
            {"id": r["id"], "title": r["title"], "category": r["category"],
             "category_label": CATEGORY_LABELS.get(r["category"], r["category"]),
             "summary": r["summary"]}
            for r in rows
        ]
    except Exception:
        return []


def generate_fix_for_email(vuln: dict, db_path: str = "") -> dict:
    """
    为邮件生成修复建议。优先使用扫描阶段预生成的 AI 建议（vuln['ai_analysis']），
    没有时回退 CWE 知识库模板。
    返回 {"subject_tag": str, "html_body": str}
    """
    cwe_key = _match_cwe(vuln)
    info = CWE_FIX_KNOWLEDGE.get(cwe_key, CWE_FIX_KNOWLEDGE[DEFAULT_CWE])

    severity = (vuln.get("severity", "medium") or "medium").upper()
    sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}
    sev_color = sev_colors.get(severity, "#6b7280")
    sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    sev_icon = sev_icons.get(severity, "⚪")

    # 优先使用预生成的真 AI 建议；否则回退知识库模板
    ai_text = (vuln.get("ai_analysis") or "").strip()
    if ai_text:
        fix_title = "🤖 AI 修复建议"
        approaches_html = _render_ai_fix_html(ai_text, sev_color)
    else:
        fix_title = "🔧 修复建议（知识库）"
        approaches_html = ""
        for i, approach in enumerate(info["fix_approaches"], 1):
            approaches_html += f"""
            <div style="margin:20px 0; padding:16px; background:#f8fafc; border-left:4px solid {sev_color}; border-radius:4px;">
                <h4 style="margin:0 0 12px 0; color:#1e293b;">{approach['title']}</h4>
                <p style="margin:8px 0 4px 0; color:#64748b; font-size:13px;">🔧 修复前：</p>
                <pre style="background:#1e293b; color:#e2e8f0; padding:12px; border-radius:6px; overflow-x:auto; font-size:13px; line-height:1.6;"><code>{approach['before']}</code></pre>
                <p style="margin:8px 0 4px 0; color:#64748b; font-size:13px;">✅ 修复后：</p>
                <pre style="background:#1e293b; color:#86efac; padding:12px; border-radius:6px; overflow-x:auto; font-size:13px; line-height:1.6;"><code>{approach['after']}</code></pre>
            </div>
            """

    # 关联知识库文章
    kb_articles = _fetch_related_kb(
        db_path,
        cwe_id=vuln.get("cwe_id", ""),
        severity=severity,
        keywords=vuln.get("title", ""),
    )
    kb_links_html = _render_kb_links_html(kb_articles)

    html_body = f"""
    <html>
    <head><meta charset="utf-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width:680px; margin:0 auto; padding:0; background:#f1f5f9;">
        <!-- Header -->
        <div style="background:linear-gradient(135deg, #1e293b, #0f172a); padding:32px 24px; text-align:center;">
            <h1 style="margin:0; color:#fff; font-size:24px;">🛡️ Sentinel Security</h1>
            <p style="margin:8px 0 0 0; color:#94a3b8; font-size:14px;">漏洞修复通知 · 安全左移，修复为先</p>
        </div>

        <div style="padding:24px;">

            <!-- Vulnerability Info Card -->
            <div style="background:#fff; border-radius:8px; padding:24px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.1);">
                <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
                    <span style="font-size:28px;">{sev_icon}</span>
                    <div>
                        <h2 style="margin:0; color:#1e293b; font-size:20px;">{vuln.get('title', '未知漏洞')}</h2>
                        <span style="display:inline-block; margin-top:4px; padding:2px 10px; background:{sev_color}; color:#fff; border-radius:12px; font-size:12px; font-weight:600;">{severity}</span>
                    </div>
                </div>

                <table style="width:100%; border-collapse:collapse; font-size:14px;">
                    <tr>
                        <td style="padding:8px 0; color:#64748b; width:90px;">CWE 编号</td>
                        <td style="padding:8px 0; color:#1e293b; font-weight:500;">{vuln.get('cwe_id', 'N/A')} — {info['name']}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0; color:#64748b;">文件路径</td>
                        <td style="padding:8px 0; color:#1e293b;"><code>{vuln.get('file_path', 'N/A')}</code>:L{vuln.get('line', 0)}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0; color:#64748b;">项目</td>
                        <td style="padding:8px 0; color:#1e293b;">{vuln.get('project_name', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0; color:#64748b;">扫描工具</td>
                        <td style="padding:8px 0; color:#1e293b;">{vuln.get('source_tool', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0; color:#64748b;">CVSS 评分</td>
                        <td style="padding:8px 0; color:#1e293b; font-weight:500;">{vuln.get('cvss_score', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0; color:#64748b;">SLA 截止</td>
                        <td style="padding:8px 0; color:#1e293b;">{vuln.get('sla_due_date', 'N/A')}</td>
                    </tr>
                </table>

                <div style="margin-top:16px; padding:12px; background:#fef3c7; border-radius:6px; font-size:14px; color:#92400e;">
                    <strong>⚠ 根因分析：</strong>{info['root_cause']}
                </div>
            </div>

            <!-- Fix Suggestions -->
            <div style="background:#fff; border-radius:8px; padding:24px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.1);">
                <h3 style="margin:0 0 16px 0; color:#1e293b;">{fix_title}</h3>
                {approaches_html}
            </div>

            <!-- Verification Steps -->
            <div style="background:#fff; border-radius:8px; padding:24px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.1);">
                <h3 style="margin:0 0 12px 0; color:#1e293b;">✅ 验证步骤</h3>
                <p style="color:#475569; font-size:14px; line-height:1.8; white-space:pre-line;">{info['verification']}</p>
            </div>

            {kb_links_html}

            <!-- Footer -->
            <div style="text-align:center; padding:16px; color:#94a3b8; font-size:12px;">
                <p>此邮件由 Sentinel Security Platform 自动生成</p>
                <p>请登录 <a href="http://localhost:5000" style="color:#3b82f6;">哨兵安全平台</a> 查看详情并更新修复状态</p>
                <p style="margin-top:8px;">Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>
    </body>
    </html>
    """

    subject_tag = f"[{severity}] {sev_icon} {vuln.get('title', '漏洞修复通知')[:30]}"

    return {
        "subject_tag": subject_tag,
        "html_body": html_body,
    }


# ═══════════════════════════════════════════════════════
# Notification Service
# ═══════════════════════════════════════════════════════

class NotificationService:
    """邮件通知服务 — 读取 SMTP 配置 + 发送通知邮件"""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _get_smtp_config(self) -> dict | None:
        """从 email_config 表读取 SMTP 配置。"""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM email_config WHERE id=1 AND enabled=1").fetchone()
        conn.close()
        if not row:
            return None
        return {
            "host": row["host"] or "",
            "port": int(row["port"] or 587),
            "username": row["username"] or "",
            "password": decrypt(row["password"] or ""),  # H-03: 解密存储的密码
            "from_addr": row["from_addr"] or "",
            "alert_on": json.loads(row["alert_on"] or '["critical","high"]'),
        }

    def _send(self, smtp: dict, to_emails: list, subject: str, html_body: str) -> tuple:
        """通过 SMTP 发送 HTML 邮件。返回 (success: bool, message: str)"""
        if not to_emails:
            return False, "收件人列表为空"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = smtp["from_addr"]
        msg["To"] = ", ".join(to_emails)
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        try:
            if smtp["port"] == 465:
                server = smtplib.SMTP_SSL(smtp["host"], smtp["port"], timeout=15)
            else:
                server = smtplib.SMTP(smtp["host"], smtp["port"], timeout=15)
                server.ehlo()
                server.starttls()
                server.ehlo()

            if smtp["username"] and smtp["password"]:
                server.login(smtp["username"], smtp["password"])

            server.sendmail(smtp["from_addr"], to_emails, msg.as_string())
            server.quit()
            return True, "发送成功"
        except Exception as e:
            return False, str(e)

    # ─── 核心方法：发送漏洞修复通知 ───

    def send_fix_notification(self, vuln: dict, assignee_email: str, assignee_name: str = "") -> tuple:
        """
        发送漏洞修复通知邮件。

        参数:
            vuln: 漏洞详情 dict，需包含 title, severity, cwe_id, file_path, line, 
                  source_tool, cvss_score, sla_due_date, project_name, description
            assignee_email: 被指派人的邮箱
            assignee_name: 被指派人姓名（可选）

        返回:
            (success: bool, message: str)
        """
        if not assignee_email:
            return False, "被指派人没有邮箱地址"

        smtp = self._get_smtp_config()
        if not smtp:
            return False, "邮件服务未配置或未启用。请先在「系统设置」中配置 SMTP。"

        # 生成修复建议（优先预生成的 AI 建议，回退知识库）
        fix_data = generate_fix_for_email(vuln, self.db_path)

        subject = f"{fix_data['subject_tag']} — 修复通知"

        # 措辞随建议来源变化：有真 AI 建议才说"AI 生成"
        _has_ai = bool((vuln.get("ai_analysis") or "").strip())
        _lead = "以下是 AI 生成的修复建议：" if _has_ai else "以下是修复建议："
        greeting = f"<p style='color:#475569; font-size:15px;'>Hi {assignee_name or '同学'}，</p>\n<p style='color:#475569; font-size:14px;'>你被指派修复以下安全漏洞，请在 SLA 截止时间前完成修复。{_lead}</p>"
        html_body = fix_data["html_body"].replace(
            '<div style="padding:24px;">',
            f'<div style="padding:24px;">\n{greeting}'
        )

        return self._send(smtp, [assignee_email], subject, html_body)

    # ─── 扫描告警通知 ───

    def send_scan_alert(self, project_name: str, tool_name: str, vulns: list, scan_result: dict):
        """
        扫描完成后发现 Critical/High 漏洞时发送告警邮件。

        参数:
            project_name: 项目名称
            tool_name: 扫描工具名称
            vulns: 漏洞列表
            scan_result: 扫描结果 dict (含 duration_ms, summary)
        """
        smtp = self._get_smtp_config()
        if not smtp:
            logger.warning("[Notification] SMTP not configured, skipping scan alert")
            return

        # 只告警 Critical 和 High
        alert_sevs = smtp.get("alert_on", ["critical", "high"])
        alert_vulns = [v for v in vulns if v.get("severity", "").lower() in alert_sevs]
        if not alert_vulns:
            return

        # 收件人从 email_config.recipients 取
        conn = self._get_conn()
        row = conn.execute("SELECT recipients FROM email_config WHERE id=1").fetchone()
        conn.close()

        recipients_str = row["recipients"] if row else ""
        to_emails = [e.strip() for e in recipients_str.split(",") if e.strip()]
        if not to_emails:
            logger.warning("[Notification] No recipients configured, skipping alert")
            return

        # Build HTML
        vuln_rows = ""
        # 收集所有 CWE/标题用于知识库匹配
        all_cwe_ids = set()
        all_titles = []
        for v in alert_vulns:
            sev = v.get("severity", "N/A").upper()
            vuln_rows += f"""
            <tr>
                <td style="padding:8px 12px; border-bottom:1px solid #e2e8f0;">{"🔴" if sev == "CRITICAL" else "🟠"}</td>
                <td style="padding:8px 12px; border-bottom:1px solid #e2e8f0; font-weight:600; color:#dc2626;">{sev}</td>
                <td style="padding:8px 12px; border-bottom:1px solid #e2e8f0;">{v.get('title', 'N/A')[:60]}</td>
                <td style="padding:8px 12px; border-bottom:1px solid #e2e8f0; font-family:monospace; font-size:12px;">{v.get('file_path', '')}:{v.get('line', '')}</td>
            </tr>
            """
            if v.get("cwe_id"):
                all_cwe_ids.add(v["cwe_id"])
            if v.get("title"):
                all_titles.append(v["title"])

        # 匹配知识库文章
        kb_articles = _fetch_related_kb(
            self.db_path,
            cwe_id=",".join(list(all_cwe_ids)[:3]) if all_cwe_ids else "",
            keywords=",".join(all_titles[:2]) if all_titles else "",
        )
        kb_links_html = _render_kb_links_html(kb_articles)

        html_body = f"""
        <html>
        <head><meta charset="utf-8"></head>
        <body style="font-family:-apple-system,BlinkMacSystemFont,sans-serif; max-width:680px; margin:0 auto; background:#f1f5f9;">
            <div style="background:linear-gradient(135deg,#dc2626,#991b1b); padding:24px; text-align:center;">
                <h1 style="margin:0; color:#fff; font-size:22px;">🚨 安全扫描告警</h1>
                <p style="margin:6px 0 0 0; color:#fca5a5; font-size:14px;">{project_name} · {tool_name}</p>
            </div>
            <div style="padding:20px;">
                <p style="color:#475569;">扫描完成，发现 <strong style="color:#dc2626;">{len(alert_vulns)}</strong> 个高危/严重漏洞：</p>
                <table style="width:100%; border-collapse:collapse; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,0.1);">
                    <tr style="background:#f8fafc;">
                        <th style="padding:10px 12px; text-align:left; font-size:13px; color:#64748b;"></th>
                        <th style="padding:10px 12px; text-align:left; font-size:13px; color:#64748b;">级别</th>
                        <th style="padding:10px 12px; text-align:left; font-size:13px; color:#64748b;">漏洞</th>
                        <th style="padding:10px 12px; text-align:left; font-size:13px; color:#64748b;">位置</th>
                    </tr>
                    {vuln_rows}
                </table>
                <p style="margin-top:16px; text-align:center; color:#94a3b8; font-size:12px;">
                    扫描耗时: {scan_result.get('duration_ms', 'N/A')}ms<br>
                    请登录 <a href="http://localhost:5000" style="color:#3b82f6;">哨兵安全平台</a> 处理漏洞
                </p>
                {kb_links_html}
            </div>
        </body>
        </html>
        """

        try:
            self._send(smtp, to_emails, f"[Sentinel 扫描告警] {project_name} 发现 {len(alert_vulns)} 个高危漏洞", html_body)
        except Exception as e:
            logger.error(f"[Notification] Alert send failed: {e}")


# ═══════════════════════════════════════════════════════
# IM 通知 — 钉钉 / 企业微信 / 飞书 / Webhook
# ═══════════════════════════════════════════════════════

import hashlib
import hmac
import base64
import urllib.parse
import time as _time

# 渠道发送历史（内存缓存，用于告警收敛）
_NOTIFY_CACHE: dict = {}  # key: (channel_id, alert_type) -> timestamp


def _should_send(channel_id: int, alert_type: str, dedup_seconds: int = 300) -> bool:
    """告警收敛：同一渠道+类型 N 秒内不重复发。"""
    key = (channel_id, alert_type)
    now = _time.time()
    if key in _NOTIFY_CACHE and now - _NOTIFY_CACHE[key] < dedup_seconds:
        return False
    _NOTIFY_CACHE[key] = now
    return True


def _sign_dingtalk(secret: str, timestamp: int) -> str:
    """钉钉机器人加签。"""
    if not secret:
        return ""
    string_to_sign = f"{timestamp}\n{secret}"
    hmac_code = hmac.new(secret.encode(), string_to_sign.encode(), hashlib.sha256).digest()
    return urllib.parse.quote_plus(base64.b64encode(hmac_code))


def _send_dingtalk(webhook_url: str, secret: str, title: str, content: str) -> tuple:
    """发送钉钉 Markdown 消息。"""
    try:
        import requests as req
        url = webhook_url
        if secret:
            ts = int(_time.time() * 1000)
            sign = _sign_dingtalk(secret, ts)
            url = f"{webhook_url}&timestamp={ts}&sign={sign}" if "?" in webhook_url else f"{webhook_url}?timestamp={ts}&sign={sign}"

        msg = {
            "msgtype": "markdown",
            "markdown": {
                "title": title[:50],
                "text": content,
            }
        }
        r = req.post(url, json=msg, timeout=10)
        return r.status_code == 200, r.text[:200]
    except Exception as e:
        return False, str(e)


def _send_wecom(webhook_url: str, title: str, content: str) -> tuple:
    """发送企业微信 Markdown 消息。"""
    try:
        import requests as req
        msg = {
            "msgtype": "markdown",
            "markdown": {
                "content": f"## {title}\n{content}"
            }
        }
        r = req.post(webhook_url, json=msg, timeout=10)
        return r.status_code == 200, r.text[:200]
    except Exception as e:
        return False, str(e)


def _send_feishu(webhook_url: str, title: str, content: str, secret: str = "") -> tuple:
    """发送飞书交互卡片消息。secret 可选：提供则按飞书自定义机器人签名校验。"""
    try:
        import requests as req
        msg = {
            "msg_type": "interactive",
            "card": {
                "header": {
                    "title": {"tag": "plain_text", "content": title[:50]},
                    "template": "red" if "严重" in title else "orange" if "高危" in title else "blue",
                },
                "elements": [
                    {"tag": "markdown", "content": content},
                ]
            }
        }
        # 飞书自定义机器人签名校验（可选）
        if secret:
            timestamp = str(int(_time.time()))
            string_to_sign = f"{timestamp}\n{secret}"
            hmac_code = hmac.new(secret.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256).digest()
            sign = base64.b64encode(hmac_code).decode("utf-8")
            msg["timestamp"] = timestamp
            msg["sign"] = sign
        r = req.post(webhook_url, json=msg, timeout=10)
        return r.status_code == 200, r.text[:200]
    except Exception as e:
        return False, str(e)


def send_im_alert(db_path: str, alert_id: int, project_name: str, tool_name: str,
                  total: int, critical: int, high: int) -> None:
    """
    向所有启用的 IM 渠道发送告警通知。
    从 notification_channels 表读取渠道配置。
    """
    import json as _json

    # 构建消息内容
    sev_emoji = "🔴" if critical > 0 else "🟠"
    content = (
        f"### {sev_emoji} 安全扫描告警\n\n"
        f"**项目**: {project_name}\n"
        f"**扫描工具**: {tool_name}\n"
        f"**漏洞总数**: {total}\n"
        f"- 严重: **{critical}** 个\n"
        f"- 高危: **{high}** 个\n\n"
        f"> 请登录 [哨兵安全平台](http://localhost:5000) 查看详情\n"
        f"> 告警时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    title = f"{sev_emoji} [{project_name}] 发现 {critical + high} 个高危漏洞"

    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        channels = conn.execute(
            "SELECT * FROM notification_channels WHERE enabled=1 ORDER BY channel_type"
        ).fetchall()
        conn.close()

        for ch in channels:
            cid = ch["id"]
            ctype = ch["channel_type"]
            if not _should_send(cid, "scan_alert"):
                logger.info(f"[IM] Channel {ctype}#{cid}: suppressed (dedup)")
                continue

            webhook_url = ch["webhook_url"]
            secret = ch["secret"] or ""

            try:
                if ctype == "dingtalk":
                    success, msg = _send_dingtalk(webhook_url, secret, title, content)
                elif ctype == "wecom":
                    success, msg = _send_wecom(webhook_url, title, content)
                elif ctype == "feishu":
                    success, msg = _send_feishu(webhook_url, title, content, secret)
                else:
                    continue

                status = "OK" if success else f"FAIL: {msg[:80]}"
                logger.info(f"[IM] {ctype}#{cid}: {status}")
            except Exception as e:
                logger.error(f"[IM] {ctype}#{cid} error: {e}")
    except Exception as e:
        logger.error(f"[IM] send_im_alert failed: {e}")
