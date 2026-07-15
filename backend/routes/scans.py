import logging
logger = logging.getLogger(__name__)
# ─── 扫描编排 + 工具集成 + 告警通知 ───
"""
扫描路由：创建扫描 → 调用工具适配器 → 漏洞入库 → 邮件告警

工具集成使用 integrations/ 下的适配器框架，支持：
  - simulated 模式：生成真实扫描特征一致的模拟漏洞（默认）
  - real 模式：直接调用 Semgrep/Trivy/ZAP/Gitleaks 等 CLI
"""

import json
import random
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from app import get_db
from routes.auth import login_required, admin_required, require_permission, RES_SCAN, RES_VULN
from config import SCANNER_MODE, SMTP_CONFIG, DATABASE_PATH

# 工具集成框架
from integrations import REGISTRY as SCANNER_REGISTRY
from integrations import BaseScanner
from services.scanner_service import execute_scan_async
from routes.audit import (
    audit_log, audit_scan_op, audit_scan_delete,
    audit_vuln_status, audit_vuln_delete, audit_vuln_batch_delete,
    audit_vuln_reverify,
)

# 通知服务
from services.notification_service import NotificationService
_notifier = NotificationService(DATABASE_PATH)

scans_bp = Blueprint("scans", __name__)

# ─── 工具名称 → scanner key 映射 ───
_NAME_TO_KEY = {
    "Semgrep": "semgrep",
    "Trivy": "trivy",
    "OWASP ZAP": "zap",
    "Gitleaks": "gitleaks",
    "Dependency-Check": "dependency-check",
    "CodeQL": "codeql",
}


def _get_scanner(tool_name: str, tool_type: str, endpoint: str = "", api_key: str = "") -> BaseScanner:
    """根据工具名获取对应的扫描器实例。"""
    key = _NAME_TO_KEY.get(tool_name)
    if not key or key not in SCANNER_REGISTRY:
        # Fallback: 用 tool_type 找第一个匹配的
        for k, cls in SCANNER_REGISTRY.items():
            if cls.tool_type == tool_type:
                key = k
                break
    if not key:
        return None

    cls = SCANNER_REGISTRY[key]
    return cls(mode=SCANNER_MODE, api_endpoint=endpoint, api_key=api_key)


def _send_alert(project_name: str, tool_name: str, vulns: list, scan_result: dict):
    """扫描完成后，如果发现 Critical/High 漏洞，发送邮件告警。"""
    try:
        _notifier.send_scan_alert(project_name, tool_name, vulns, scan_result)
    except Exception as e:
        logger.error(f"[Alert] Failed to send alert: {e}")
        # 告警失败不影响扫描流程


def _send_assignment_notification(db, vuln, user_id: int, vuln_id: int):
    """
    漏洞被指派后，自动发送修复通知邮件给被指派人。
    包含 AI 修复建议（或 CWE 知识库降级方案）。
    发送失败不影响指派操作本身。
    """
    try:
        # 确保 vuln 是 dict（可能是 sqlite3.Row）
        if not isinstance(vuln, dict):
            vuln = dict(vuln)
        # 查询被指派人邮箱
        assignee = db.execute("SELECT id, name, email FROM users WHERE id=?", (user_id,)).fetchone()
        if not assignee or not assignee["email"]:
            logger.warning(f"[Notify] User #{user_id} has no email, skipping")
            return

        # 查询项目名
        scan = db.execute("SELECT project_id FROM scan_tasks WHERE id=?", (vuln["scan_id"],)).fetchone()
        project_name = "未知项目"
        if scan:
            proj = db.execute("SELECT name FROM projects WHERE id=?", (scan["project_id"],)).fetchone()
            if proj:
                project_name = proj["name"]

        # 构建漏洞数据用于邮件
        vuln_data = {
            "title": vuln["title"],
            "severity": vuln["severity"],
            "cwe_id": vuln.get("cwe_id", ""),
            "file_path": vuln.get("file_path", ""),
            "line": vuln.get("line", 0),
            "source_tool": vuln.get("source_tool", ""),
            "cvss_score": vuln.get("cvss_score", 0),
            "sla_due_date": vuln.get("sla_due_date", ""),
            "project_name": project_name,
            "description": vuln.get("description", ""),
        }

        success, msg = _notifier.send_fix_notification(
            vuln_data,
            assignee["email"],
            assignee["name"] or "",
        )
        if success:
            logger.info(f"[Notify] Fix notification sent to {assignee['email']} for vuln #{vuln_id}")
        else:
            logger.error(f"[Notify] Failed to send to {assignee['email']}: {msg}")

    except Exception as e:
        logger.error(f"[Notify] Notification failed (non-blocking): {e}")


# ═══════════════════════════════════ 路由 ═══════════════════════════════════

@scans_bp.route("", methods=["GET"])
@login_required
def list_scans():
    db = get_db()

    # ── 自动恢复：把卡死超过 10 分钟的 running 扫描标记为 failed ──
    try:
        cursor = db.execute("SELECT id FROM scan_tasks WHERE status='running'")
        stuck_ids = [r["id"] for r in cursor.fetchall()]
        for sid in stuck_ids:
            row = db.execute(
                "SELECT started_at FROM scan_tasks WHERE id=? AND status='running'", (sid,)
            ).fetchone()
            if row and row["started_at"]:
                # 检查是否超过 10 分钟
                need_recover = db.execute(
                    "SELECT 1 FROM scan_tasks WHERE id=? AND status='running' "
                    "AND datetime(started_at, '+10 minutes') < datetime('now','localtime')",
                    (sid,),
                ).fetchone()
                if need_recover:
                    db.execute(
                        "UPDATE scan_tasks SET status='failed', error='扫描超时（超过10分钟无响应，可能为后台进程异常退出）', "
                        "finished_at=datetime('now','localtime'), progress_message='自动恢复：线程卡死' WHERE id=?",
                        (sid,),
                    )
                    db.commit()
    except Exception:
        pass

    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    offset = (page - 1) * per_page

    project_id = request.args.get("project_id")
    if project_id:
        total = db.execute(
            "SELECT COUNT(*) FROM scan_tasks WHERE project_id=?", (int(project_id),)
        ).fetchone()[0]
        rows = db.execute(
            """SELECT s.*, p.name as project_name
               FROM scan_tasks s LEFT JOIN projects p ON s.project_id = p.id
               WHERE s.project_id=? ORDER BY s.created_at DESC
               LIMIT ? OFFSET ?""",
            (int(project_id), per_page, offset),
        ).fetchall()
    else:
        total = db.execute("SELECT COUNT(*) FROM scan_tasks").fetchone()[0]
        rows = db.execute(
            """SELECT s.*, p.name as project_name
               FROM scan_tasks s LEFT JOIN projects p ON s.project_id = p.id
               ORDER BY s.created_at DESC
               LIMIT ? OFFSET ?""",
            (per_page, offset),
        ).fetchall()

    return jsonify({
        "items": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    })


@scans_bp.route("/<int:sid>", methods=["GET"])
@login_required
def get_scan(sid: int):
    db = get_db()
    row = db.execute(
        """SELECT s.*, p.name as project_name
           FROM scan_tasks s LEFT JOIN projects p ON s.project_id = p.id
           WHERE s.id=?""", (sid,)
    ).fetchone()
    if not row:
        return jsonify({"error": "扫描任务不存在"}), 404

    vulns = db.execute(
        "SELECT * FROM vulnerabilities WHERE scan_id=? ORDER BY severity DESC", (sid,)
    ).fetchall()

    result = dict(row)
    result["vulnerabilities"] = [dict(v) for v in vulns]
    return jsonify(result)


@scans_bp.route("", methods=["POST"])
@login_required
@require_permission(RES_SCAN, "create")
def create_scan():
    """
    触发一次安全扫描。

    请求体：
      { project_id: int, tool_type: "SAST"|"SCA"|"DAST"|"SECRET" }
    """
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    tool_type = data.get("tool_type", "").strip()

    if not project_id or not tool_type:
        return jsonify({"error": "project_id 和 tool_type 为必填项"}), 400

    # 委托给扫描服务（异步执行，立即返回）
    from services.scanner_service import execute_scan_async
    success, result, error = execute_scan_async(
        project_id=project_id,
        tool_type=tool_type,
        trigger_type="manual",
        user_id=getattr(request, 'current_user_id', None),
    )

    if not success:
        if "不存在" in error:
            return jsonify({"error": error}), 404
        elif "不支持" in error or "没有启用" in error:
            return jsonify({"error": error}), 400
        else:
            return jsonify({"error": error}), 500

    # 审计日志
    db = get_db()
    project = db.execute("SELECT name FROM projects WHERE id=?", (project_id,)).fetchone()
    audit_scan_op(
        getattr(request, 'current_user_id', None), result.get("id"),
        tool_type, project["name"] if project else ""
    )

    return jsonify(result), 201


@scans_bp.route("/batch", methods=["POST"])
@login_required
@require_permission(RES_SCAN, "create")
def create_batch_scan():
    """
    批量触发扫描：对「多个项目 × 多种工具类型」并行发起扫描。

    请求体：
      {
        "project_ids": [1, 2, 3] | "all",   # 项目 ID 数组，或 "all" 表示全部项目
        "tool_types": ["SAST", "SCA"]        # 工具类型数组（SAST/SCA/DAST/SECRET）
      }
    返回：
      {
        "created": [ {project_id, tool_type, scan_id?, status?, error?}, ... ],
        "count": 成功提交的任务数,
        "total": 计划任务总数
      }
    """
    data = request.get_json(silent=True) or {}
    project_ids = data.get("project_ids")
    tool_types = data.get("tool_types") or []

    if not tool_types or not isinstance(tool_types, list):
        return jsonify({"error": "tool_types 不能为空且必须为数组"}), 400
    tool_types = [t.strip().upper() for t in tool_types if t and str(t).strip()]

    db = get_db()

    # ── 解析项目列表 ──
    if isinstance(project_ids, str) and project_ids.strip().lower() == "all":
        rows = db.execute("SELECT id FROM projects").fetchall()
        project_ids = [r["id"] for r in rows]
    if not project_ids or not isinstance(project_ids, list):
        return jsonify({"error": "project_ids 不能为空（可为项目 ID 数组或 'all'）"}), 400
    project_ids = [int(p) for p in project_ids if str(p).strip()]

    user_id = getattr(request, "current_user_id", None)
    created = []
    for pid in project_ids:
        for tt in tool_types:
            success, result, error = execute_scan_async(
                project_id=pid,
                tool_type=tt,
                trigger_type="manual",
                user_id=user_id,
            )
            if success:
                created.append({
                    "project_id": pid,
                    "tool_type": tt,
                    "scan_id": result.get("id"),
                    "status": result.get("status"),
                })
            else:
                created.append({"project_id": pid, "tool_type": tt, "error": error})

    # 审计日志（仅记录成功提交的任务）
    for c in created:
        if "scan_id" in c:
            proj = db.execute("SELECT name FROM projects WHERE id=?", (c["project_id"],)).fetchone()
            audit_scan_op(user_id, c["scan_id"], c["tool_type"], proj["name"] if proj else "")

    ok_count = sum(1 for c in created if "scan_id" in c)
    return jsonify({
        "created": created,
        "count": ok_count,
        "total": len(created),
    }), 201


@scans_bp.route("/<int:sid>", methods=["DELETE"])
@admin_required
def delete_scan(sid: int):
    db = get_db()
    row = db.execute("SELECT id, tool_type FROM scan_tasks WHERE id=?", (sid,)).fetchone()
    if not row:
        return jsonify({"error": "扫描任务不存在"}), 404
    db.execute("DELETE FROM scan_tasks WHERE id=?", (sid,))
    db.commit()
    audit_scan_delete(request.current_user_id, sid, row["tool_type"])
    return jsonify({"ok": True, "message": "扫描任务已删除"})


# ─── 漏洞管理 API ───

def _build_vuln_filters():
    """根据请求参数构建漏洞查询的 WHERE 子句与参数列表（供列表/导出/统计复用）。"""
    severity = request.args.get("severity")
    status = request.args.get("status")  # 支持逗号分隔多值如 open,in_progress
    sla = request.args.get("sla")        # "breached" → 仅超时未处理
    q = (request.args.get("q") or "").strip()
    conditions = []
    params = []
    if severity:
        conditions.append("v.severity=?")
        params.append(severity)
    if status:
        status_list = [s.strip() for s in status.split(",") if s.strip()]
        if len(status_list) == 1:
            conditions.append("v.status=?")
            params.append(status_list[0])
        elif len(status_list) > 1:
            placeholders = ",".join(["?"] * len(status_list))
            conditions.append(f"v.status IN ({placeholders})")
            params.extend(status_list)
    if sla == "breached":
        conditions.append("v.sla_breached=1 AND v.status='open'")
    if q:
        conditions.append("(LOWER(v.cve_id) LIKE ? OR LOWER(v.title) LIKE ? OR LOWER(v.file_path) LIKE ?)")
        like = f"%{q.lower()}%"
        params.extend([like, like, like])
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    return where, params


@scans_bp.route("/vulnerabilities", methods=["GET"])
@login_required
def list_vulnerabilities():
    """GET /api/vulnerabilities — 列出漏洞，支持筛选/搜索/分页。

    - 不传 page：返回全量数组（向后兼容 AI 分析页、命令面板等）
    - 传 page：返回 {items, total, page, per_page, total_pages}（后端真分页）
    """
    db = get_db()
    where, params = _build_vuln_filters()
    base_from = """FROM vulnerabilities v
            LEFT JOIN scan_tasks s ON v.scan_id = s.id
            LEFT JOIN projects p ON s.project_id = p.id"""
    select_cols = "SELECT v.*, s.tool_type, p.name as project_name"
    order = "ORDER BY CASE LOWER(v.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, v.created_at DESC"

    page_arg = request.args.get("page")
    if page_arg is None:
        # 向后兼容：无分页参数时返回全量数组
        rows = db.execute(f"{select_cols} {base_from} {where} {order}", params).fetchall()
        return jsonify([dict(r) for r in rows])

    # 后端真分页
    try:
        page = max(1, int(page_arg))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = int(request.args.get("per_page", 20))
    except (TypeError, ValueError):
        per_page = 20
    per_page = max(1, min(per_page, 200))

    total = db.execute(f"SELECT COUNT(*) {base_from} {where}", params).fetchone()[0]
    offset = (page - 1) * per_page
    rows = db.execute(
        f"{select_cols} {base_from} {where} {order} LIMIT ? OFFSET ?",
        params + [per_page, offset],
    ).fetchall()
    total_pages = max(1, (total + per_page - 1) // per_page)
    return jsonify({
        "items": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
    })


@scans_bp.route("/vulnerabilities/groups", methods=["GET"])
@login_required
def group_vulnerabilities():
    """GET /api/scans/vulnerabilities/groups — 按 (标题, 严重度, 来源工具) 聚合相同漏洞。

    将同一条规则在多文件/多行触发的重复记录折叠成一组，每组带数量、状态分布、
    受影响位置列表与代表性 ID，便于集中处置而非逐条查看。与 list 接口共用同一套筛选。
    """
    db = get_db()
    where, params = _build_vuln_filters()
    base_from = """FROM vulnerabilities v
            LEFT JOIN scan_tasks s ON v.scan_id = s.id
            LEFT JOIN projects p ON s.project_id = p.id"""
    sql = f"""
        SELECT
            v.title AS title,
            v.severity AS severity,
            v.source_tool AS source_tool,
            COUNT(*) AS cnt,
            SUM(CASE WHEN v.status='open' THEN 1 ELSE 0 END) AS open_count,
            SUM(CASE WHEN v.status='in_progress' THEN 1 ELSE 0 END) AS in_progress_count,
            SUM(CASE WHEN v.status='fixed' THEN 1 ELSE 0 END) AS fixed_count,
            SUM(CASE WHEN v.status='ignored' THEN 1 ELSE 0 END) AS ignored_count,
            SUM(CASE WHEN v.sla_breached=1 AND v.status='open' THEN 1 ELSE 0 END) AS breached_count,
            MIN(v.created_at) AS first_seen,
            MAX(v.created_at) AS last_seen,
            MIN(v.id) AS rep_id,
            GROUP_CONCAT(v.id) AS ids,
            GROUP_CONCAT(v.cve_id) AS cve_ids,
            GROUP_CONCAT(v.id || '::' || COALESCE(v.file_path,'') || ':' || COALESCE(v.line,0), '|||') AS locations
        {base_from}
        {where}
        GROUP BY v.title, v.severity, v.source_tool
        ORDER BY cnt DESC, CASE LOWER(v.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
    """
    rows = db.execute(sql, params).fetchall()
    groups = []
    for r in rows:
        d = dict(r)
        ids = [int(x) for x in (d.get("ids") or "").split(",") if x]
        locs = [x for x in (d.get("locations") or "").split("|||") if x]
        cve_ids = [x for x in (d.get("cve_ids") or "").split(",") if x]
        groups.append({
            "key": f"{d['title']}||{d['severity']}||{d['source_tool']}",
            "title": d["title"],
            "severity": d["severity"],
            "source_tool": d["source_tool"] or "",
            "count": d["cnt"] or 0,
            "open_count": d["open_count"] or 0,
            "in_progress_count": d["in_progress_count"] or 0,
            "fixed_count": d["fixed_count"] or 0,
            "ignored_count": d["ignored_count"] or 0,
            "breached_count": d["breached_count"] or 0,
            "first_seen": d["first_seen"],
            "last_seen": d["last_seen"],
            "rep_id": d["rep_id"],
            "ids": ids,
            "cve_id": cve_ids[0] if cve_ids else "",
            "locations": locs,
        })
    db.close()
    return jsonify({"groups": groups, "total_groups": len(groups)})


@scans_bp.route("/vulnerabilities/stats", methods=["GET"])
@login_required
def vulnerabilities_stats():
    """GET /api/scans/vulnerabilities/stats — 漏洞统计概览（不受分页影响，供统计卡片使用）。"""
    db = get_db()
    row = db.execute(
        """SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status='open' AND LOWER(severity)='critical' THEN 1 ELSE 0 END) AS critical,
            SUM(CASE WHEN status='open' AND LOWER(severity)='high' THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN status='open' AND LOWER(severity)='medium' THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN status='open' AND LOWER(severity)='low' THEN 1 ELSE 0 END) AS low,
            SUM(CASE WHEN status='open' AND sla_breached=1 THEN 1 ELSE 0 END) AS breached,
            SUM(CASE WHEN status='fixed' THEN 1 ELSE 0 END) AS fixed
           FROM vulnerabilities"""
    ).fetchone()
    return jsonify({k: (row[k] or 0) for k in row.keys()})


@scans_bp.route("/vulnerabilities/export", methods=["GET"])
@login_required
def export_vulnerabilities():
    """GET /api/scans/vulnerabilities/export — 按当前筛选导出漏洞为 CSV。"""
    import csv
    import io
    db = get_db()
    where, params = _build_vuln_filters()
    rows = db.execute(
        f"""SELECT v.cve_id, v.title, v.severity, v.status, v.cvss_score,
                   v.cwe_id, v.file_path, v.line, v.source_tool,
                   p.name AS project_name, v.assigned_to,
                   v.sla_due_date, v.sla_breached, v.created_at, v.description
            FROM vulnerabilities v
            LEFT JOIN scan_tasks s ON v.scan_id = s.id
            LEFT JOIN projects p ON s.project_id = p.id
            {where}
            ORDER BY CASE LOWER(v.severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, v.created_at DESC""",
        params,
    ).fetchall()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "CVE/编号", "标题", "严重度", "状态", "CVSS", "CWE",
        "文件路径", "行号", "来源工具", "所属项目", "指派人ID",
        "SLA到期", "SLA超时", "发现时间", "描述",
    ])
    for r in rows:
        d = dict(r)
        writer.writerow([
            d.get("cve_id", ""), d.get("title", ""), d.get("severity", ""),
            d.get("status", ""), d.get("cvss_score", ""), d.get("cwe_id", ""),
            d.get("file_path", ""), d.get("line", ""), d.get("source_tool", ""),
            d.get("project_name", ""), d.get("assigned_to", ""),
            d.get("sla_due_date", ""), d.get("sla_breached", ""),
            d.get("created_at", ""),
            (d.get("description", "") or "").replace("\n", " ").replace("\r", " "),
        ])

    # 加 UTF-8 BOM，Excel 打开中文不乱码
    csv_data = "\ufeff" + buf.getvalue()
    from flask import Response
    filename = f"vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_data,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@scans_bp.route("/vulnerabilities/<int:vid>", methods=["PATCH"])
@login_required
@require_permission(RES_VULN, "update")
def update_vulnerability(vid: int):
    """PATCH /api/vulnerabilities/:id — 更新漏洞状态/指派人/备注"""
    data = request.get_json(silent=True) or {}
    db = get_db()

    vuln = db.execute("SELECT * FROM vulnerabilities WHERE id=?", (vid,)).fetchone()
    if not vuln:
        db.close()
        return jsonify({"error": "漏洞不存在"}), 404

    allowed_statuses = ("open", "fixed", "ignored", "in_progress")

    # 状态更新
    new_status = data.get("status")
    if new_status and new_status in allowed_statuses:
        db.execute("UPDATE vulnerabilities SET status=? WHERE id=?", (new_status, vid))
        if new_status in ("fixed", "ignored"):
            db.execute("UPDATE vulnerabilities SET sla_breached=0 WHERE id=?", (vid,))

    # 指派
    assigned_to = data.get("assigned_to")
    if assigned_to is not None:
        user_id = int(assigned_to) if assigned_to else None
        assigner_id = 0
        try:
            assigner_id = int(request.environ.get("sentinel_user_id", 0))
        except (ValueError, TypeError):
            pass
        db.execute(
            "UPDATE vulnerabilities SET assigned_to=?, assigned_by=? WHERE id=?",
            (user_id, assigner_id, vid)
        )
        # ── 自动发送修复通知邮件 ──
        if user_id:
            _send_assignment_notification(db, vuln, user_id, vid)

    # 备注
    note = data.get("note", "").strip()
    if note:
        # 追加到 description
        current_desc = vuln["description"] or ""
        updated_desc = current_desc + f"\n\n[操作备注] {note}"
        db.execute("UPDATE vulnerabilities SET description=? WHERE id=?", (updated_desc, vid))

    db.commit()

    # 审计日志
    if new_status and new_status in allowed_statuses:
        audit_vuln_status(
            getattr(request, 'current_user_id', None), vid,
            vuln["title"] or f"#{vid}", vuln["status"], new_status
        )
    if assigned_to is not None:
        from routes.audit import audit_vuln_assign
        audit_vuln_assign(
            getattr(request, 'current_user_id', None), vid,
            vuln["title"] or f"#{vid}", int(assigned_to) if assigned_to else 0
        )

    updated = db.execute(
        """SELECT v.*, u.name as assignee_name, u.email as assignee_email
           FROM vulnerabilities v LEFT JOIN users u ON v.assigned_to = u.id
           WHERE v.id=?""", (vid,)
    ).fetchone()

    # 计算 SLA 剩余时间
    result = dict(updated)
    result["sla_info"] = _calc_sla(result)

    db.close()
    return jsonify(result)


@scans_bp.route("/vulnerabilities/<int:vid>", methods=["GET"])
@login_required
def get_vulnerability(vid: int):
    """GET /api/scans/vulnerabilities/:id — 返回单条漏洞完整记录（供聚合视图点开具体位置）。"""
    db = get_db()
    row = db.execute(
        """SELECT v.*, p.name AS project_name, u.name AS assignee_name
           FROM vulnerabilities v
           LEFT JOIN scan_tasks s ON v.scan_id = s.id
           LEFT JOIN projects p ON s.project_id = p.id
           LEFT JOIN users u ON v.assigned_to = u.id
           WHERE v.id=?""",
        (vid,)
    ).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "漏洞不存在"}), 404
    result = dict(row)
    result["sla_info"] = _calc_sla(result)
    db.close()
    return jsonify(result)


@scans_bp.route("/vulnerabilities/<int:vid>", methods=["DELETE"])
@login_required
@require_permission(RES_VULN, "delete")
def delete_vulnerability(vid: int):
    """DELETE /api/vulnerabilities/:id — 删除单个漏洞"""
    db = get_db()
    vuln = db.execute("SELECT id, title FROM vulnerabilities WHERE id=?", (vid,)).fetchone()
    if not vuln:
        db.close()
        return jsonify({"error": "漏洞不存在"}), 404
    db.execute("DELETE FROM vulnerabilities WHERE id=?", (vid,))
    db.commit()
    db.close()
    audit_vuln_delete(request.current_user_id, vid, vuln["title"])
    return jsonify({"ok": True, "message": f"漏洞 '{vuln['title']}' 已删除", "id": vid})


@scans_bp.route("/vulnerabilities/batch-delete", methods=["POST"])
@login_required
@require_permission(RES_VULN, "delete")
def batch_delete_vulnerabilities():
    """POST /api/scans/vulnerabilities/batch-delete — 批量删除漏洞"""
    data = request.get_json(silent=True) or {}
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"error": "ids 不能为空"}), 400

    db = get_db()
    placeholders = ",".join("?" * len(ids))
    db.execute(f"DELETE FROM vulnerabilities WHERE id IN ({placeholders})", ids)
    db.commit()
    db.close()
    audit_vuln_batch_delete(request.current_user_id, len(ids))
    return jsonify({"ok": True, "deleted": len(ids)})


@scans_bp.route("/vulnerabilities/batch-fix", methods=["POST"])
@login_required
@admin_required  # 批量修复需要管理员权限（影响面大）
def batch_fix_vulnerabilities():
    """POST /api/scans/vulnerabilities/batch-fix — 批量修复漏洞"""
    data = request.get_json(silent=True) or {}
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"error": "ids 不能为空"}), 400

    db = get_db()
    placeholders = ",".join("?" * len(ids))
    db.execute(
        f"UPDATE vulnerabilities SET status='fixed', sla_breached=0 WHERE id IN ({placeholders})",
        ids
    )
    db.commit()
    db.close()
    return jsonify({"ok": True, "fixed": len(ids)})


# ─── SLA 状态 API ───

def _calc_sla(vuln: dict) -> dict:
    """计算单个漏洞的 SLA 状态。"""
    due = vuln.get("sla_due_date") or ""
    status = vuln.get("status") or "open"

    info = {
        "due_date": due,
        "status": "ok",
        "remaining_hours": 0,
        "remaining_text": "",
        "breached": False,
    }

    if not due or status in ("fixed", "ignored"):
        info["status"] = "closed"
        return info

    try:
        from datetime import datetime, timezone
        due_dt = datetime.strptime(due, "%Y-%m-%d %H:%M:%S")
        now = datetime.now(timezone.utc)
        delta = due_dt - now.replace(tzinfo=None)
        info["remaining_hours"] = round(delta.total_seconds() / 3600, 1)

        if delta.total_seconds() < 0:
            info["status"] = "breached"
            info["breached"] = True
            hours_over = abs(info["remaining_hours"])
            if hours_over >= 24:
                info["remaining_text"] = f"超时 {round(hours_over/24,1)} 天"
            else:
                info["remaining_text"] = f"超时 {round(hours_over,1)} 小时"
        elif delta.total_seconds() < 3600:
            info["status"] = "urgent"
            info["remaining_text"] = f"剩余 {round(delta.total_seconds()/60)} 分钟"
            info["breached"] = False
        elif delta.days > 0:
            info["remaining_text"] = f"剩余 {delta.days} 天"
            info["breached"] = False
        else:
            info["remaining_text"] = f"剩余 {info['remaining_hours']} 小时"
            info["breached"] = False
    except Exception:
        info["status"] = "unknown"

    return info


@scans_bp.route("/vulnerabilities/sla-status", methods=["GET"])
@login_required
def get_sla_status():
    """GET /api/scans/vulnerabilities/sla-status — SLA 概览"""
    db = get_db()

    # 总数统计
    stats = db.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN sla_breached = 1 AND status = 'open' THEN 1 ELSE 0 END) as breached,
            SUM(CASE WHEN status = 'open' AND sla_due_date != '' AND sla_due_date > datetime('now','localtime') THEN 1 ELSE 0 END) as on_track,
            SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) as fixed,
            SUM(CASE WHEN status = 'ignored' THEN 1 ELSE 0 END) as ignored
        FROM vulnerabilities
    """).fetchone()

    # 按严重级别统计超时
    breached_by_sev = db.execute("""
        SELECT severity, COUNT(*) as cnt
        FROM vulnerabilities WHERE sla_breached = 1 AND status = 'open'
        GROUP BY severity ORDER BY cnt DESC
    """).fetchall()

    # 即将到期（24小时内）
    urgent = db.execute("""
        SELECT v.*, p.name as project_name, u.name as assignee_name
        FROM vulnerabilities v
        LEFT JOIN scan_tasks s ON v.scan_id = s.id
        LEFT JOIN projects p ON s.project_id = p.id
        LEFT JOIN users u ON v.assigned_to = u.id
        WHERE v.status = 'open' AND v.sla_breached = 0
            AND v.sla_due_date != ''
            AND v.sla_due_date > datetime('now','localtime')
            AND v.sla_due_date < datetime('now','localtime','+24 hours')
        ORDER BY v.severity, v.sla_due_date
    """).fetchall()

    # 已超时列表（前 20）
    overdue = db.execute("""
        SELECT v.*, p.name as project_name, u.name as assignee_name
        FROM vulnerabilities v
        LEFT JOIN scan_tasks s ON v.scan_id = s.id
        LEFT JOIN projects p ON s.project_id = p.id
        LEFT JOIN users u ON v.assigned_to = u.id
        WHERE v.status = 'open' AND v.sla_breached = 1
        ORDER BY v.severity, v.sla_due_date
        LIMIT 20
    """).fetchall()

    db.close()

    return jsonify({
        "summary": dict(stats),
        "breached_by_severity": [dict(r) for r in breached_by_sev],
        "urgent": [dict(r) for r in urgent],
        "overdue": [dict(r) for r in overdue],
    })


# ─── 修复验证 API ───

@scans_bp.route("/vulnerabilities/<int:vid>/reverify", methods=["POST"])
@login_required
@require_permission(RES_VULN, "verify")
def reverify_vulnerability(vid: int):
    """
    POST /api/scans/vulnerabilities/:id/reverify — 对特定漏洞重新扫描验证。

    重新运行同一类型的扫描器，检查该文件路径的漏洞是否仍然存在。
    返回验证结果：fixed（已修复）或 still_open（仍存在）
    """
    db = get_db()
    vuln = db.execute("SELECT * FROM vulnerabilities WHERE id=?", (vid,)).fetchone()
    if not vuln:
        db.close()
        return jsonify({"error": "漏洞不存在"}), 404

    # 获取关联的扫描和项目信息
    scan = db.execute("SELECT * FROM scan_tasks WHERE id=?", (vuln["scan_id"],)).fetchone()
    if not scan:
        db.close()
        return jsonify({"error": "关联扫描不存在"}), 404

    project = db.execute("SELECT * FROM projects WHERE id=?", (scan["project_id"],)).fetchone()
    tool = db.execute("SELECT * FROM tools WHERE id=?", (scan["tool_id"],)).fetchone()

    if not project or not tool:
        db.close()
        return jsonify({"error": "关联项目或工具不存在"}), 404

    # 创建验证扫描（轻量）
    cur = db.execute(
        """INSERT INTO scan_tasks (project_id, tool_id, tool_type, status, started_at)
           VALUES (?,?,?,'running',datetime('now','localtime'))""",
        (project["id"], tool["id"], scan["tool_type"])
    )
    verify_scan_id = cur.lastrowid
    db.commit()

    try:
        from integrations import REGISTRY as SCANNER_REGISTRY
        _NAME_TO_KEY = {
            "Semgrep": "semgrep", "Trivy": "trivy", "OWASP ZAP": "zap",
            "Gitleaks": "gitleaks", "Dependency-Check": "dependency-check", "CodeQL": "codeql",
        }
        key = _NAME_TO_KEY.get(tool["name"])
        cls = SCANNER_REGISTRY.get(key) if key else None

        if cls:
            scanner = cls(
                mode=SCANNER_MODE,
                api_endpoint=tool["endpoint"] or "",
                api_key=tool["api_key"] or "",
            )
            project_config = dict(project)
            project_config["lang"] = project["language"] or "python"
            scan_result = scanner.run(project_config)

            # 检查同路径同类型漏洞是否仍存在
            # 标准化路径比较：Windows 下路径可能大小写/分隔符不同
            import os as _os
            def _norm(p: str) -> str:
                return _os.path.normcase(_os.path.normpath(p)) if p else ""
            vuln_path = _norm(vuln["file_path"])
            vuln_title = (vuln["title"] or "").strip()
            same_path_found = [
                v for v in scan_result.vulnerabilities
                if _norm(v.file_path) == vuln_path and (v.title or "").strip() == vuln_title
            ]

            # 兜底检查：如果扫描器没找到（可能用了模拟数据/temp 目录），
            # 直接读取原文件检查是否存在对应代码特征
            if not same_path_found and vuln["file_path"] and _os.path.exists(vuln["file_path"]):
                try:
                    with open(vuln["file_path"], "r", encoding="utf-8", errors="ignore") as _f:
                        file_source = _f.read()
                    lines = file_source.split("\n")
                    line_no = int(vuln["line"] or 1) - 1
                    context_start = max(0, line_no - 2)
                    context_end = min(len(lines), line_no + 3)
                    context = "\n".join(lines[context_start:context_end])
                    # 简单启发式：原漏洞所在行非空就算"仍存在"
                    if line_no < len(lines) and lines[line_no].strip():
                        # 构造一个"伪发现"来防止误判已修复
                        from integrations.base import VulnerabilityResult
                        same_path_found = [VulnerabilityResult(
                            cve_id="", title=vuln["title"], severity=vuln["severity"],
                            file_path=vuln["file_path"], line=vuln["line"],
                            description=f"文件直接检查: 漏洞所在行仍存在代码\n> {lines[line_no][:80]}",
                            fix_suggestion="", source_tool="reverify-fallback"
                        )]
                except Exception:
                    pass  # 文件不可读，按扫描器结果判断

            if not same_path_found:
                # 漏洞已修复（扫描器未找到 + 文件检查也未发现）
                db.execute("UPDATE vulnerabilities SET status='fixed', sla_breached=0 WHERE id=?", (vid,))
                db.execute("UPDATE scan_tasks SET status='completed', vuln_count=0, finished_at=datetime('now','localtime') WHERE id=?",
                           (verify_scan_id,))
                db.commit()
                db.close()
                audit_vuln_reverify(request.current_user_id, vid, vuln["title"], "fixed")
                return jsonify({
                    "verified": True,
                    "result": "fixed",
                    "message": "漏洞已不存在，标记为已修复",
                    "verify_scan_id": verify_scan_id,
                })
            else:
                # 仍然存在
                db.execute("UPDATE scan_tasks SET status='completed', vuln_count=?, finished_at=datetime('now','localtime') WHERE id=?",
                           (len(same_path_found), verify_scan_id))
                db.commit()
                db.close()
                audit_vuln_reverify(request.current_user_id, vid, vuln["title"], "still_open")
                return jsonify({
                    "verified": True,
                    "result": "still_open",
                    "message": f"漏洞仍然存在于 {vuln['file_path']}",
                    "verify_scan_id": verify_scan_id,
                    "current_count": len(same_path_found),
                })
        else:
            # 无适配器时的 fallback
            db.execute("UPDATE scan_tasks SET status='completed', vuln_count=0, finished_at=datetime('now','localtime') WHERE id=?",
                       (verify_scan_id,))
            db.commit()
            db.close()
            return jsonify({
                "verified": True,
                "result": "manual_required",
                "message": "该工具需手动验证（当前为模拟模式）",
                "verify_scan_id": verify_scan_id,
            })

    except Exception as e:
        db.execute("UPDATE scan_tasks SET status='failed', finished_at=datetime('now','localtime') WHERE id=?",
                   (verify_scan_id,))
        db.commit()
        db.close()
        return jsonify({"error": f"验证扫描失败: {str(e)}"}), 500


# ─── 修复通知 API ───

@scans_bp.route("/notify/<int:vid>", methods=["POST"])
@login_required
@require_permission(RES_VULN, "update")
def send_fix_notification(vid: int):
    """
    POST /api/scans/vulnerabilities/:id/notify — 手动发送修复通知邮件。

    向被指派人（或请求中指定的邮箱）发送包含 AI 修复建议的邮件。
    请求体可选: { "email": "override@example.com" }  用于发送给未在系统中注册的邮箱。

    返回: { "success": true, "message": "...", "sent_to": "user@example.com" }
    """
    data = request.get_json(silent=True) or {}
    db = get_db()

    row = db.execute("SELECT * FROM vulnerabilities WHERE id=?", (vid,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "漏洞不存在"}), 404
    vuln = dict(row)

    # 确定收件人
    target_email = data.get("email", "").strip()
    target_name = ""

    if not target_email:
        # 使用被指派人邮箱
        if vuln.get("assigned_to"):
            assignee = db.execute(
                "SELECT name, email FROM users WHERE id=?", (vuln["assigned_to"],)
            ).fetchone()
            if assignee and assignee["email"]:
                target_email = assignee["email"]
                target_name = assignee["name"] or ""
        elif "assignee_email" in vuln and vuln["assignee_email"]:
            target_email = vuln["assignee_email"]

    if not target_email:
        db.close()
        return jsonify({"error": "没有收件人。请先指派修复人，或传入 email 参数。"}), 400

    # 查询项目名
    scan = db.execute("SELECT project_id FROM scan_tasks WHERE id=?", (vuln["scan_id"],)).fetchone()
    project_name = "未知项目"
    if scan:
        proj = db.execute("SELECT name FROM projects WHERE id=?", (scan["project_id"],)).fetchone()
        if proj:
            project_name = proj["name"]

    # 构建漏洞数据
    vuln_data = {
        "title": vuln["title"],
        "severity": vuln["severity"],
        "cwe_id": vuln.get("cwe_id", ""),
        "file_path": vuln.get("file_path", ""),
        "line": vuln.get("line", 0),
        "source_tool": vuln.get("source_tool", ""),
        "cvss_score": vuln.get("cvss_score", 0),
        "sla_due_date": vuln.get("sla_due_date", ""),
        "project_name": project_name,
        "description": vuln.get("description", ""),
        "ai_analysis": vuln.get("ai_analysis", ""),  # 扫描阶段预生成的 AI 修复建议，发邮件直接复用
    }

    db.close()

    # 调用通知服务
    success, msg = _notifier.send_fix_notification(vuln_data, target_email, target_name)

    if success:
        return jsonify({
            "success": True,
            "message": f"修复通知已发送至 {target_email}",
            "sent_to": target_email,
        })
    else:
        return jsonify({"error": f"发送失败: {msg}"}), 500
