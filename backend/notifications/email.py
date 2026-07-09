"""
邮件告警通知系统
扫描发现 Critical/High 漏洞时自动发送邮件给安全团队。

配置：backend/config.py 中的 SMTP 和告警规则
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from typing import Optional


class EmailNotifier:
    """SMTP 邮件通知器"""

    def __init__(self, smtp_config: dict):
        """
        Args:
            smtp_config: {
                "host": "smtp.example.com",
                "port": 587,
                "username": "sentinel@company.com",
                "password": "xxx",
                "use_tls": True,
                "from_addr": "sentinel@company.com",
                "from_name": "哨兵安全平台",
                "recipients": ["sec-team@company.com", "admin@company.com"],
                "enabled": True,
                "alert_on": ["critical", "high"],  # 哪些级别触发告警
                "daily_digest": True,  # 是否发送日报
            }
        """
        self.config = smtp_config

    @property
    def enabled(self) -> bool:
        return self.config.get("enabled", False)

    def send_scan_alert(self, project_name: str, tool_name: str,
                        vulnerabilities: list, scan_result: dict) -> bool:
        """
        扫描完成后发送告警邮件。
        仅在发现满足告警级别的漏洞时才发送。
        """
        if not self.enabled:
            return False

        alert_levels = self.config.get("alert_on", ["critical", "high"])
        alertable = [v for v in vulnerabilities
                     if v.get("severity", "low") in alert_levels]

        if not alertable:
            return False  # 无非告警级别漏洞，不发送

        subject = f"[哨兵] 发现 {len(alertable)} 个高危漏洞 — {project_name} ({tool_name})"
        body = self._build_alert_body(project_name, tool_name, alertable, scan_result)
        return self._send(subject, body)

    def send_reminder(self, project_name: str, days_open: int, unresolved_count: int) -> bool:
        """发送漏洞逾期未修复提醒"""
        if not self.enabled:
            return False
        subject = f"[哨兵] 提醒：{project_name} 有 {unresolved_count} 个漏洞逾期 {days_open} 天未修复"
        body = f"""
        <h3>漏洞逾期提醒</h3>
        <p>项目 <b>{project_name}</b> 中有 <b style='color:red'>{unresolved_count}</b> 个漏洞
        已发现超过 <b>{days_open}</b> 天但仍未修复。</p>
        <p>请登录 <a href='{self.config.get('base_url', '#')}'>哨兵应用安全平台</a> 处理。</p>
        <p style='color:#666;font-size:12px'>此邮件由哨兵安全平台自动发送</p>
        """
        return self._send(subject, body)

    def send_daily_digest(self, stats: dict) -> bool:
        """发送每日安全摘要"""
        if not self.enabled or not self.config.get("daily_digest"):
            return False

        subject = f"[哨兵] 每日安全摘要 — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        body = f"""
        <h3>今日安全摘要</h3>
        <table style='border-collapse:collapse;width:100%'>
            <tr><td style='padding:8px;border:1px solid #ddd'>新发现漏洞</td>
                <td style='padding:8px;border:1px solid #ddd;color:red'>{stats.get('new_vulns', 0)}</td></tr>
            <tr><td style='padding:8px;border:1px solid #ddd'>已修复</td>
                <td style='padding:8px;border:1px solid #ddd;color:green'>{stats.get('fixed', 0)}</td></tr>
            <tr><td style='padding:8px;border:1px solid #ddd'>活跃项目</td>
                <td style='padding:8px;border:1px solid #ddd'>{stats.get('active_projects', 0)}</td></tr>
            <tr><td style='padding:8px;border:1px solid #ddd'>扫描次数</td>
                <td style='padding:8px;border:1px solid #ddd'>{stats.get('scans_today', 0)}</td></tr>
        </table>
        <p style='color:#666;font-size:12px;margin-top:16px'>此邮件由哨兵安全平台自动发送</p>
        """
        return self._send(subject, body)

    def _build_alert_body(self, project_name, tool_name, alertable, scan_result) -> str:
        rows = ""
        for v in alertable:
            sev_color = {"critical": "#dc2626", "high": "#ea580c",
                         "medium": "#ca8a04", "low": "#6b7280"}
            color = sev_color.get(v.get("severity", "low"), "#6b7280")
            rows += f"""
            <tr>
                <td style='padding:6px 10px;border:1px solid #ddd'><span style='color:{color};font-weight:bold'>
                    {v['severity'].upper()}</span></td>
                <td style='padding:6px 10px;border:1px solid #ddd'>{v.get('cve_id', 'N/A')}</td>
                <td style='padding:6px 10px;border:1px solid #ddd'>{v.get('title', 'Unknown')}</td>
                <td style='padding:6px 10px;border:1px solid #ddd'>{v.get('file_path', 'N/A')}:{v.get('line', '-')}</td>
            </tr>"""

        return f"""
        <h3>⚠️ 安全告警</h3>
        <p>项目 <b>{project_name}</b> 的 <b>{tool_name}</b> 扫描完成，
           发现 <b style='color:red'>{len(alertable)}</b> 个高危漏洞：</p>
        <table style='border-collapse:collapse;width:100%;font-size:14px'>
            <tr style='background:#f3f4f6'>
                <th style='padding:8px;border:1px solid #ddd'>级别</th>
                <th style='padding:8px;border:1px solid #ddd'>编号</th>
                <th style='padding:8px;border:1px solid #ddd'>标题</th>
                <th style='padding:8px;border:1px solid #ddd'>位置</th>
            </tr>
            {rows}
        </table>
        <p style='margin-top:16px'>扫描耗时：{scan_result.get('duration_ms', 0) // 1000}s，总计 {scan_result.get('summary', {}).get('total', 0)} 个漏洞</p>
        <p>请立即登录 <a href='{self.config.get('base_url', '#')}'>哨兵应用安全平台</a> 查看详情并分配修复。</p>
        <p style='color:#666;font-size:12px;margin-top:24px'>此邮件由哨兵安全平台自动发送，请勿回复。</p>
        """

    def _send(self, subject: str, html_body: str) -> bool:
        """底层 SMTP 发送"""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f'{self.config.get("from_name", "哨兵")} <{self.config["from_addr"]}>'
            msg["To"] = ", ".join(self.config.get("recipients", []))

            msg.attach(MIMEText(html_body, "html", "utf-8"))

            context = None
            if self.config.get("use_tls"):
                context = ssl.create_default_context()

            with smtplib.SMTP(self.config["host"], self.config["port"]) as server:
                if self.config.get("use_tls"):
                    server.starttls(context=context)
                server.login(self.config["username"], self.config["password"])
                server.send_message(msg)

            print(f"[EmailNotifier] Sent: {subject}")
            return True

        except Exception as e:
            print(f"[EmailNotifier] Failed to send email: {e}")
            return False
