import logging
logger = logging.getLogger(__name__)
# ─── Audit Logging (Phase 2 Enhanced) ───
"""
集中式审计日志系统 v2
- 所有操作（认证/CRUD/扫描/配置变更）统一记录
- 支持风险等级、操作结果、请求上下文、耗时等增强字段
- 支持查询 API（分页/筛选/导出）
"""

import time
from flask import request, g


def audit_log(
    user_id: int | None,
    user_email: str,
    action: str,
    target_type: str,
    target_id: int = 0,
    detail: str = "",
    ip_address: str = "",
    result: str = "success",
    risk_level: str = "low",
    duration_ms: int = 0,
    request_path: str = "",
    request_method: str = "",
    user_agent: str = "",
):
    """
    写入审计日志（增强版 v2）。

    Args:
        user_id: 操作人 ID（未登录时为 None）
        user_email: 操作人邮箱
        action: 操作类型，格式 "resource.action"
        target_type: 被操作的资源类型
        target_id: 资源 ID
        detail: 操作详情描述
        ip_address: 客户端 IP
        result: 操作结果 — success / failure / warning / blocked
        risk_level: 风险等级 — low / medium / high / critical
        duration_ms: 操作耗时（毫秒）
        request_path: API 路径
        request_method: HTTP 方法
        user_agent: 浏览器 UA
    """
    try:
        from app import get_db
        db = get_db()
        db.execute("""
            INSERT INTO audit_logs (
                user_id, user_email, action, target_type, target_id,
                detail, ip_address, result, risk_level,
                duration_ms, request_path, request_method, user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            (user_email or "")[:200],
            action[:100],
            target_type[:50],
            target_id or 0,
            (detail or "")[:2000],
            ip_address or (request.remote_addr or "")[:45],
            result[:20],
            risk_level[:20],
            duration_ms or 0,
            request_path or (request.path or "")[:255],
            request_method or (request.method or "")[:10],
            user_agent or (request.headers.get("User-Agent", "") or "")[:500],
        ))
        db.commit()
        db.close()
    except Exception as e:
        # 审计日志写入失败不应阻断主流程
        logger.error(f"[AUDIT ERROR] {e}")


def _get_request_context() -> dict:
    """获取当前请求的完整上下文信息（带 user_email 解析）。"""
    user_id = getattr(request, "current_user_id", None)
    user_email = ""
    if user_id:
        try:
            from app import get_db
            db = get_db()
            row = db.execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone()
            if row:
                user_email = row["email"] or ""
            db.close()
        except Exception:
            pass
    return {
        "user_id": user_id,
        "user_email": user_email,
        "ip": request.remote_addr or "",
        "path": request.path or "",
        "method": request.method or "",
        "ua": request.headers.get("User-Agent", "") or "",
    }


# ═══════════════════════════════════════════════════════
#  认证/安全事件
# ═══════════════════════════════════════════════════════

def audit_login_success(user_id: int, email: str):
    """记录登录成功。"""
    ctx = _get_request_context()
    audit_log(user_id, email, "user.login", "user", user_id,
              f"用户登录成功", ip_address=ctx["ip"],
              result="success", risk_level="low",
              user_agent=ctx["ua"])


def audit_login_failure(ip: str, email: str = ""):
    """记录登录失败。"""
    ctx = _get_request_context()
    audit_log(None, email or "", "user.login_failed", "user", 0,
              f"登录失败: {email}", ip_address=ip,
              result="failure", risk_level="medium",
              user_agent=ctx["ua"])


def audit_account_locked(ip: str, email: str):
    """记录账户锁定。"""
    ctx = _get_request_context()
    audit_log(None, email, "security.account_locked", "ip", 0,
              f"账户锁定: {email} (连续失败登录)", ip_address=ip,
              result="blocked", risk_level="high",
              user_agent=ctx["ua"])


def audit_login_blocked(ip: str, reason: str = ""):
    """记录登录被拦截。"""
    ctx = _get_request_context()
    audit_log(None, "", "security.login_blocked", "ip", 0,
              f"登录被拦截: {reason}" if reason else "登录被拦截", ip_address=ip,
              result="blocked", risk_level="high",
              user_agent=ctx["ua"])


# ═══════════════════════════════════════════════════════
#  用户管理
# ═══════════════════════════════════════════════════════

def audit_user_register(user_id: int, email: str):
    """记录用户注册。"""
    ctx = _get_request_context()
    audit_log(user_id, email, "user.register", "user", user_id,
              f"新用户注册: {email}", ip_address=ctx["ip"],
              result="success", risk_level="low",
              user_agent=ctx["ua"])


def audit_user_create(operator_id: int, target_user_id: int, target_email: str, role: str):
    """记录管理员创建用户（邀请/开号）。"""
    ctx = _get_request_context()
    audit_log(operator_id, ctx["user_email"], "user.create", "user", target_user_id,
              f"管理员创建用户: {target_email} (role={role})", ip_address=ctx["ip"],
              result="success", risk_level="medium",
              user_agent=ctx["ua"])


def audit_user_delete(operator_id: int, target_user_id: int, target_email: str):
    """记录用户删除。"""
    ctx = _get_request_context()
    audit_log(operator_id, ctx["user_email"], "user.delete", "user", target_user_id,
              f"删除用户: {target_email}", ip_address=ctx["ip"],
              result="success", risk_level="high",
              user_agent=ctx["ua"])


def audit_role_change(operator_id: int, target_user_id: int, target_email: str, new_role: str):
    """记录角色变更。"""
    ctx = _get_request_context()
    audit_log(operator_id, ctx["user_email"], "user.role_change", "user", target_user_id,
              f"用户 {target_email} 角色变更为 {new_role}", ip_address=ctx["ip"],
              result="success", risk_level="high",
              user_agent=ctx["ua"])


def audit_change_password(user_id: int, email: str):
    """记录密码修改。"""
    ctx = _get_request_context()
    audit_log(user_id, email, "user.change_password", "user", user_id,
              f"用户 {email} 修改了密码", ip_address=ctx["ip"],
              result="success", risk_level="medium",
              user_agent=ctx["ua"])


def audit_user_status_change(operator_id: int, target_user_id: int, target_email: str, new_status: str):
    """记录用户启用/禁用。"""
    ctx = _get_request_context()
    status_display = "启用" if new_status == "active" else "禁用"
    risk = "high" if new_status == "disabled" else "medium"
    audit_log(operator_id, ctx["user_email"], "user.status_change", "user", target_user_id,
              f"用户 {target_email} → {status_display}", ip_address=ctx["ip"],
              result="success", risk_level=risk,
              user_agent=ctx["ua"])


def audit_user_unlock(operator_id: int, target_user_id: int, target_email: str):
    """记录解锁用户账户。"""
    ctx = _get_request_context()
    audit_log(operator_id, ctx["user_email"], "user.unlock", "user", target_user_id,
              f"解锁用户账户: {target_email}", ip_address=ctx["ip"],
              result="success", risk_level="medium",
              user_agent=ctx["ua"])


# ═══════════════════════════════════════════════════════
#  项目管理
# ═══════════════════════════════════════════════════════

def audit_project_op(user_id: int, email: str, op: str, project_id: int, name: str, extra: str = ""):
    """记录项目 CRUD 操作。"""
    ctx = _get_request_context()
    detail = f"项目{op}: {name}"
    if extra:
        detail += f" ({extra})"
    risk = "high" if op in ("delete",) else "medium" if op in ("create",) else "low"
    audit_log(user_id, email or ctx["user_email"], f"project.{op}", "project", project_id,
              detail, ip_address=ctx["ip"],
              result="success", risk_level=risk,
              request_path=ctx["path"], request_method=ctx["method"],
              user_agent=ctx["ua"])


# ═══════════════════════════════════════════════════════
#  扫描管理
# ═══════════════════════════════════════════════════════

def audit_scan_op(user_id: int, scan_id: int, tool_type: str, project_name: str):
    """记录扫描操作。"""
    ctx = _get_request_context()
    audit_log(user_id, ctx["user_email"], "scan.triggered", "scan", scan_id,
              f"触发 {tool_type} 扫描 - 项目: {project_name}", ip_address=ctx["ip"],
              result="success", risk_level="medium",
              request_path=ctx["path"], request_method=ctx["method"],
              user_agent=ctx["ua"])


def audit_scan_delete(user_id: int, scan_id: int, tool_type: str):
    """记录删除扫描。"""
    ctx = _get_request_context()
    audit_log(user_id, ctx["user_email"], "scan.deleted", "scan", scan_id,
              f"删除扫描 #{scan_id} ({tool_type})", ip_address=ctx["ip"],
              result="success", risk_level="high",
              user_agent=ctx["ua"])


# ═══════════════════════════════════════════════════════
#  漏洞管理
# ═══════════════════════════════════════════════════════

def audit_vuln_status(user_id: int, vuln_id: int, title: str, old_status: str, new_status: str):
    """记录漏洞状态变更。"""
    ctx = _get_request_context()
    risk = "medium" if new_status in ("fixed", "ignored") else "low"
    audit_log(user_id, ctx["user_email"], "vuln.status_change", "vulnerability", vuln_id,
              f"[{title}] {old_status} → {new_status}", ip_address=ctx["ip"],
              result="success", risk_level=risk,
              user_agent=ctx["ua"])


def audit_vuln_assign(user_id: int, vuln_id: int, title: str, assignee_id: int):
    """记录漏洞指派。"""
    ctx = _get_request_context()
    audit_log(user_id, ctx["user_email"], "vuln.assigned", "vulnerability", vuln_id,
              f"[{title}] 指派给用户 #{assignee_id}", ip_address=ctx["ip"],
              result="success", risk_level="low",
              user_agent=ctx["ua"])


def audit_vuln_delete(user_id: int, vuln_id: int, title: str):
    """记录删除漏洞。"""
    ctx = _get_request_context()
    audit_log(user_id, ctx["user_email"], "vuln.deleted", "vulnerability", vuln_id,
              f"删除漏洞: [{title}]", ip_address=ctx["ip"],
              result="success", risk_level="high",
              user_agent=ctx["ua"])


def audit_vuln_batch_delete(user_id: int, count: int):
    """记录批量删除漏洞。"""
    ctx = _get_request_context()
    audit_log(user_id, ctx["user_email"], "vuln.batch_deleted", "vulnerability", 0,
              f"批量删除 {count} 个漏洞", ip_address=ctx["ip"],
              result="success", risk_level="critical",
              user_agent=ctx["ua"])


def audit_vuln_reverify(user_id: int, vuln_id: int, title: str, verdict: str):
    """记录漏洞复验。"""
    ctx = _get_request_context()
    result = "success"
    detail = f"复验漏洞 [{title}]: "
    if verdict == "still_open":
        detail += "仍然存在"
        result = "warning"
    elif verdict == "fixed":
        detail += "确认已修复"
    else:
        detail += verdict
    audit_log(user_id, ctx["user_email"], "vuln.reverified", "vulnerability", vuln_id,
              detail, ip_address=ctx["ip"],
              result=result, risk_level="medium",
              user_agent=ctx["ua"])


# ═══════════════════════════════════════════════════════
#  规则管理
# ═══════════════════════════════════════════════════════

def audit_rule_op(user_id: int, op: str, rule_id: int, rule_name: str, extra: str = ""):
    """记录规则操作。"""
    ctx = _get_request_context()
    detail = f"规则{op}: {rule_name}"
    if extra:
        detail += f" ({extra})"
    risk = "high" if op in ("delete",) else "medium" if op in ("create",) else "low"
    audit_log(user_id, ctx["user_email"], f"rule.{op}", "rule", rule_id,
              detail, ip_address=ctx["ip"],
              result="success", risk_level=risk,
              request_path=ctx["path"], request_method=ctx["method"],
              user_agent=ctx["ua"])


def audit_rule_toggle(user_id: int, rule_id: int, rule_name: str, new_state: bool):
    """记录规则启用/禁用。"""
    ctx = _get_request_context()
    state = "启用" if new_state else "禁用"
    audit_log(user_id, ctx["user_email"], "rule.toggle", "rule", rule_id,
              f"规则 {rule_name} → {state}", ip_address=ctx["ip"],
              result="success", risk_level="medium",
              user_agent=ctx["ua"])


# ═══════════════════════════════════════════════════════
#  资产管理
# ═══════════════════════════════════════════════════════

def audit_asset_op(user_id: int, op: str, asset_id: int, asset_name: str, extra: str = ""):
    """记录资产操作。"""
    ctx = _get_request_context()
    detail = f"资产{op}: {asset_name}"
    if extra:
        detail += f" ({extra})"
    risk = "high" if op in ("delete",) else "medium" if op in ("create",) else "low"
    audit_log(user_id, ctx["user_email"], f"asset.{op}", "asset", asset_id,
              detail, ip_address=ctx["ip"],
              result="success", risk_level=risk,
              request_path=ctx["path"], request_method=ctx["method"],
              user_agent=ctx["ua"])


def audit_asset_sync(user_id: int, created: int, updated: int):
    """记录资产同步。"""
    ctx = _get_request_context()
    audit_log(user_id, ctx["user_email"], "asset.synced", "asset", 0,
              f"从项目同步资产: 新建 {created}, 更新 {updated}", ip_address=ctx["ip"],
              result="success", risk_level="low",
              user_agent=ctx["ua"])


def audit_asset_recalc_risk(user_id: int, asset_id: int, asset_name: str, new_score: float, new_level: str):
    """记录资产风险重算。"""
    ctx = _get_request_context()
    audit_log(user_id, ctx["user_email"], "asset.recalc_risk", "asset", asset_id,
              f"重算资产风险 [{asset_name}]: score={new_score} level={new_level}",
              ip_address=ctx["ip"],
              result="success", risk_level="low",
              user_agent=ctx["ua"])


# ═══════════════════════════════════════════════════════
#  报告管理
# ═══════════════════════════════════════════════════════

def audit_report_gen(user_id: int, report_id: int, report_type: str, fmt: str, title: str = ""):
    """记录报告生成。"""
    ctx = _get_request_context()
    detail = f"生成报告: {report_type} ({fmt})"
    if title:
        detail += f" — {title}"
    audit_log(user_id, ctx["user_email"], "report.generated", "report", report_id,
              detail, ip_address=ctx["ip"],
              result="success", risk_level="low",
              request_path=ctx["path"], request_method=ctx["method"],
              user_agent=ctx["ua"])


def audit_report_delete(user_id: int, report_id: int):
    """记录删除报告。"""
    ctx = _get_request_context()
    audit_log(user_id, ctx["user_email"], "report.deleted", "report", report_id,
              f"删除报告 #{report_id}", ip_address=ctx["ip"],
              result="success", risk_level="high",
              user_agent=ctx["ua"])


def audit_report_download(user_id: int, report_id: int, fmt: str):
    """记录报告下载。"""
    ctx = _get_request_context()
    audit_log(user_id, ctx["user_email"], "report.downloaded", "report", report_id,
              f"下载报告 #{report_id} ({fmt})", ip_address=ctx["ip"],
              result="success", risk_level="low",
              user_agent=ctx["ua"])


def audit_report_export(user_id: int, count: int):
    """记录审计日志导出。"""
    ctx = _get_request_context()
    audit_log(user_id, ctx["user_email"], "audit.exported", "audit", 0,
              f"导出审计日志 ({count} 条)", ip_address=ctx["ip"],
              result="success", risk_level="medium",
              user_agent=ctx["ua"])


# ═══════════════════════════════════════════════════════
#  配置管理
# ═══════════════════════════════════════════════════════

def audit_setting_change(user_id: int, key: str, old_val: str, new_val: str):
    """记录配置变更。"""
    ctx = _get_request_context()
    risk = "high" if "password" in key.lower() or "secret" in key.lower() or "token" in key.lower() else "medium"
    # 敏感值脱敏
    if "password" in key.lower() or "secret" in key.lower() or "token" in key.lower() or "key" in key.lower():
        old_display = "***" if old_val else ""
        new_display = "***" if new_val else ""
    else:
        old_display = (old_val or "")[:80]
        new_display = (new_val or "")[:80]
    audit_log(user_id, ctx["user_email"], "setting.changed", "setting", 0,
              f"配置变更: {key} = '{old_display}' → '{new_display}'",
              ip_address=ctx["ip"],
              result="success", risk_level=risk,
              request_path=ctx["path"], request_method=ctx["method"],
              user_agent=ctx["ua"])


# ═══════════════════════════════════════════════════════
#  Webhook / 集成
# ═══════════════════════════════════════════════════════

def audit_webhook_scan(project: str, tool: str, gate_result: str):
    """记录 Webhook 触发的扫描（无用户上下文）。"""
    ctx = _get_request_context()
    audit_log(ctx["user_id"], "", "webhook.scan_triggered", "webhook", 0,
              f"CI/CD Webhook: 项目={project}, 工具={tool}, 门禁={gate_result}",
              ip_address=ctx["ip"],
              result="success", risk_level="medium",
              user_agent=ctx["ua"])


# ═══════════════════════════════════════════════════════
#  Token 管理
# ═══════════════════════════════════════════════════════

def audit_token_refresh(user_id: int, email: str):
    """记录 Token 刷新。"""
    ctx = _get_request_context()
    audit_log(user_id, email, "user.token_refresh", "user", user_id,
              f"刷新 JWT Token", ip_address=ctx["ip"],
              result="success", risk_level="low",
              user_agent=ctx["ua"])


def audit_token_revoke(user_id: int, email: str):
    """记录 Token 吊销。"""
    ctx = _get_request_context()
    audit_log(user_id, email, "user.token_revoke", "user", user_id,
              f"吊销 JWT Token", ip_address=ctx["ip"],
              result="success", risk_level="medium",
              user_agent=ctx["ua"])
