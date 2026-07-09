# ─── Email Notification Routes ───
"""邮件发送 API：
- GET  /api/email/config       — 获取邮件配置
- PUT  /api/email/config       — 更新邮件配置
- POST /api/email/test        — 测试邮件发送
- POST /api/email/notify-vuln — 漏洞分配/更新时自动通知
"""

import smtplib
import sqlite3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Blueprint, request, jsonify
from app import get_db
from routes.auth import login_required, admin_required

email_bp = Blueprint("email", __name__)


# ── 读取/更新邮件配置 ────────────────────────────────────────────────

@email_bp.route("/config", methods=["GET"])
@login_required
def get_email_config():
    db = get_db()
    row = db.execute("SELECT * FROM email_config WHERE id=1").fetchone()
    if not row:
        return jsonify({"enabled": False})
    d = dict(row)
    d.pop("password", None)  # 不返回密码
    d["enabled"] = bool(d.get("enabled", 0))
    return jsonify(d)


@email_bp.route("/config", methods=["PUT"])
@admin_required
def update_email_config():
    data = request.get_json(silent=True) or {}
    db = get_db()
    fields = ["enabled", "host", "port", "username", "password", "from_addr", "recipients"]
    sets = []
    params = []
    for f in fields:
        if f in data:
            sets.append(f"{f}=?")
            params.append(data[f])
    if not sets:
        return jsonify({"error": "没有可更新的字段"}), 400
    db.execute(
        f"UPDATE email_config SET {','.join(sets)} WHERE id=1",
        params
    )
    db.commit()
    return jsonify({"ok": True, "message": "邮件配置已更新"})


# ── 发送邮件（内部工具函数）─────────────────────────────────────────

def _get_smtp_config():
    """从数据库读取 SMTP 配置，返回 dict。"""
    db = get_db()
    row = db.execute("SELECT * FROM email_config WHERE id=1").fetchone()
    if not row:
        return None
    return dict(row)


def send_email(to_addrs, subject, html_body, text_body="", smtp_cfg=None):
    """发送邮件，返回 (成功?, 消息)。

    smtp_cfg: 可选，覆盖数据库配置的 SMTP 设置（测试用）
    """
    cfg = smtp_cfg or _get_smtp_config()
    if not cfg:
        return False, "邮件配置不存在"
    if not cfg.get("enabled"):
        return False, "邮件功能未启用"

    host = cfg.get("host", "")
    port = int(cfg.get("port", 587))
    username = cfg.get("username", "")
    password = cfg.get("password", "")
    from_addr = cfg.get("from_addr", username)
    use_tls = True

    if not host or not username:
        return False, "邮件服务器配置不完整"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs) if isinstance(to_addrs, list) else to_addrs
    msg.attach(MIMEText(text_body or html_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        server = smtplib.SMTP(host, port, timeout=15)
        server.ehlo()
        if use_tls:
            server.starttls()
        if password:
            server.login(username, password)
        server.sendmail(from_addr, to_addrs, msg.as_string())
        server.quit()
        return True, f"邮件已发送至 {to_addrs}"
    except Exception as e:
        return False, f"邮件发送失败: {str(e)}"


# ── API：测试邮件 ────────────────────────────────────────────────────

@email_bp.route("/test", methods=["POST"])
@admin_required
def test_email():
    data = request.get_json(silent=True) or {}
    to = data.get("to", "")
    if not to:
        return jsonify({"error": "请填写接收邮箱"}), 400

    # 测试时允许用请求体里的配置
    smtp_cfg = None
    if data.get("host"):
        smtp_cfg = {
            "enabled": True,
            "host": data.get("host"),
            "port": int(data.get("port", 587)),
            "username": data.get("username", ""),
            "password": data.get("password", ""),
            "from_addr": data.get("from_addr", data.get("username", "")),
        }

    html = """<div style="font-family:sans-serif;max-width:600px">
        <h2 style="color:#6366f1">🛡️ 哨兵安全平台 — 邮件配置测试</h2>
        <p>这是一封测试邮件，确认您的邮件配置正常工作。</p>
        <p style="color:#64748b;font-size:12px">若收到此邮件，说明配置正确。</p>
    </div>"""
    ok, msg = send_email([to], "【哨兵安全平台】邮件配置测试", html, "哨兵安全平台邮件配置测试", smtp_cfg)
    return jsonify({"ok": ok, "message": msg})


# ── API：发送漏洞通知邮件 ──────────────────────────────────────────

@email_bp.route("/notify-vuln", methods=["POST"])
@login_required
def notify_vuln():
    """漏洞分配/更新时，给处理人发送邮件通知。"""
    data = request.get_json(silent=True) or {}
    vuln_id = data.get("vuln_id")
    assignee_email = data.get("assignee_email", "")
    assignee_name = data.get("assignee_name", "")
    if not vuln_id:
        return jsonify({"error": "缺少 vuln_id"}), 400

    db = get_db()
    # 获取漏洞详情
    vuln = db.execute(
        """SELECT v.*, p.name as project_name, p.target_url
           FROM vulnerabilities v
           LEFT JOIN scan_tasks s ON v.scan_id = s.id
           LEFT JOIN projects p ON s.project_id = p.id
           WHERE v.id=?""",
        (vuln_id,)
    ).fetchone()
    if not vuln:
        return jsonify({"error": "漏洞不存在"}), 404

    vuln = dict(vuln)
    to_addrs = []
    if assignee_email:
        to_addrs.append(assignee_email)
    # 如果没有指定邮箱，尝试从 recipients 配置里取
    if not to_addrs:
        cfg = _get_smtp_config()
        if cfg and cfg.get("recipients"):
            to_addrs = [r.strip() for r in cfg["recipients"].split(",") if r.strip()]
    if not to_addrs:
        return jsonify({"ok": False, "message": "没有指定接收人邮箱"})

    # 构建邮件内容
    severity_label = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}.get(
        vuln["severity"], vuln["severity"]
    )
    status_label = {"open": "待处理", "in_progress": "修复中", "resolved": "已修复", "closed": "已关闭",
                    "false_positive": "误报"}.get(vuln["status"], vuln["status"])

    vuln_code = vuln.get("cve_id") or f"SNT-VLN-{int(vuln_id):06d}"

    html_body = f"""<div style="font-family:sans-serif;max-width:680px;padding:20px;color:#1e293b">
        <div style="background:linear-gradient(135deg,#6366f1,#8b5cf6);padding:24px 28px;border-radius:12px 12px 0 0;color:white">
            <h1 style="margin:0;font-size:20px">🛡️ 哨兵安全平台 — 漏洞处理通知</h1>
        </div>
        <div style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;padding:24px 28px;border-radius:0 0 12px 12px">
            <p>您好，{assignee_name or '同事'}：</p>
            <p>有新的安全漏洞需要您处理，详情如下：</p>

            <table style="width:100%;border-collapse:collapse;margin:16px 0;font-size:14px">
                <tr><td style="padding:8px 12px;background:#f1f5f9;width:120px;border:1px solid #e2e8f0">漏洞编号</td>
                    <td style="padding:8px 12px;border:1px solid #e2e8f0"><b>{vuln_code}</b></td></tr>
                <tr><td style="padding:8px 12px;background:#f1f5f9;border:1px solid #e2e8f0">漏洞标题</td>
                    <td style="padding:8px 12px;border:1px solid #e2e8f0">{vuln.get('title', '')}</td></tr>
                <tr><td style="padding:8px 12px;background:#f1f5f9;border:1px solid #e2e8f0">严重程度</td>
                    <td style="padding:8px 12px;border:1px solid #e2e8f0">
                        <span style="display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;
                              background:{'#fecaca' if vuln['severity']=='critical' else '#fed7aa' if vuln['severity']=='high' else '#fef9c3' if vuln['severity']=='medium' else '#dbeafe'};
                              color:{'#991b1b' if vuln['severity']=='critical' else '#92400e' if vuln['severity']=='high' else '#713f12' if vuln['severity']=='medium' else '#1e40af'}">
                            {severity_label}
                        </span>
                    </td></tr>
                <tr><td style="padding:8px 12px;background:#f1f5f9;border:1px solid #e2e8f0">当前状态</td>
                    <td style="padding:8px 12px;border:1px solid #e2e8f0">{status_label}</td></tr>
                <tr><td style="padding:8px 12px;background:#f1f5f9;border:1px solid #e2e8f0">所属项目</td>
                    <td style="padding:8px 12px;border:1px solid #e2e8f0">{vuln.get('project_name', '-')}</td></tr>
                <tr><td style="padding:8px 12px;background:#f1f5f9;border:1px solid #e2e8f0">文件路径</td>
                    <td style="padding:8px 12px;border:1px solid #e2e8f0;font-family:monospace;font-size:12px">{vuln.get('file_path', '-')}</td></tr>
                <tr><td style="padding:8px 12px;background:#f1f5f9;border:1px solid #e2e8f0">CWE 编号</td>
                    <td style="padding:8px 12px;border:1px solid #e2e8f0">{vuln.get('cwe_id', '-')}</td></tr>
                <tr><td style="padding:8px 12px;background:#f1f5f9;border:1px solid #e2e8f0">CVSS 评分</td>
                    <td style="padding:8px 12px;border:1px solid #e2e8f0">{vuln.get('cvss_score', '-')}</td></tr>
            </table>

            <div style="background:#f1f5f9;padding:16px 20px;border-radius:8px;margin:16px 0">
                <h3 style="margin:0 0 8px 0;font-size:14px;color:#475569">📋 漏洞描述</h3>
                <p style="margin:0;font-size:13px;color:#64748b;line-height:1.6">{vuln.get('description', '暂无描述')}</p>
            </div>"""

    # 添加 AI 分析结果
    if vuln.get("ai_analysis"):
        ai = vuln["ai_analysis"]
        if isinstance(ai, str):
            try:
                import json
                ai = json.loads(ai)
            except Exception:
                pass
        html_body += f"""<div style="background:#eff6ff;padding:16px 20px;border-radius:8px;margin:16px 0;border:1px solid #bfdbfe">
            <h3 style="margin:0 0 8px 0;font-size:14px;color:#1e40af">🤖 AI 修复建议</h3>
            <div style="font-size:13px;color:#1e3a5f;line-height:1.6;white-space:pre-wrap">{str(ai)}</div>
        </div>"""

    # 添加修复建议
    if vuln.get("fix_suggestion"):
        html_body += f"""<div style="background:#f0fdf4;padding:16px 20px;border-radius:8px;margin:16px 0;border:1px solid #bbf7d0">
            <h3 style="margin:0 0 8px 0;font-size:14px;color:#166534">🔧 推荐修复方案</h3>
            <pre style="margin:0;font-size:12px;color:#14532d;white-space:pre-wrap;font-family:monospace">{vuln.get('fix_suggestion', '')}</pre>
        </div>"""

    html_body += """<div style="margin-top:24px;padding-top:16px;border-top:1px solid #e2e8f0;font-size:12px;color:#94a3b8">
            <p>请尽快登录 <b>哨兵安全平台</b> 处理此漏洞。</p>
            <p>此邮件为自动发送，请勿直接回复。</p>
        </div></div>"""

    text_body = f"""漏洞处理通知
编号：{vuln_code}
标题：{vuln.get('title', '')}
严重程度：{severity_label}
状态：{status_label}
项目：{vuln.get('project_name', '-')}
请登录哨兵安全平台查看详情。"""

    ok, msg = send_email(to_addrs, f"【哨兵安全】【{severity_label}】{vuln.get('title', '')[:40]}", html_body, text_body)
    return jsonify({"ok": ok, "message": msg})
