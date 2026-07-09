# ─── Audit Log API (Phase 1) ───
"""
审计日志查询与管理
- GET /api/audit/logs — 分页查询审计日志（支持筛选）
- GET /api/audit/stats — 审计统计概览
- GET /api/audit/export — 导出审计日志（CSV）
"""

from flask import Blueprint, request, jsonify
from app import get_db
from routes.auth import login_required, admin_required

audit_bp = Blueprint("audit", __name__)


@audit_bp.route("/", methods=["GET"])
@audit_bp.route("", methods=["GET"])
@login_required
def audit_index():
    """GET /api/audit — 重定向到日志列表（别名路由）"""
    return list_audit_logs()


@audit_bp.route("/logs", methods=["GET"])
@login_required
def list_audit_logs():
    """
    GET /api/audit/logs
    Query params:
        page: 页码（默认 1）
        page_size: 每页条数（默认 20，最大 100）
        action: 按操作类型筛选（如 user.login, project.create）
        target_type: 按资源类型筛选（如 user, project, vuln）
        user_id: 按操作人 ID 筛选
        start_date / end_date: 时间范围
    """
    page = max(1, request.args.get("page", type=int) or 1)
    page_size = min(100, max(1, request.args.get("page_size", type=int) or 20))
    action_filter = request.args.get("action", "").strip()
    target_type_filter = request.args.get("target_type", "").strip()
    user_id_filter = request.args.get("user_id", type=int)
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    db = get_db()

    # 构建查询条件
    conditions = []
    params: list = []

    if action_filter:
        conditions.append("action LIKE ?")
        params.append(f"%{action_filter}%")
    if target_type_filter:
        conditions.append("target_type = ?")
        params.append(target_type_filter)
    if user_id_filter:
        conditions.append("user_id = ?")
        params.append(user_id_filter)
    if start_date:
        conditions.append("created_at >= ?")
        params.append(start_date + " 00:00:00")
    if end_date:
        conditions.append("created_at <= ?")
        params.append(end_date + " 23:59:59")

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    # 总数
    count_sql = f"SELECT COUNT(*) as total FROM audit_logs {where_clause}"
    total = db.execute(count_sql, params).fetchone()["total"]

    # 分页数据
    offset = (page - 1) * page_size
    data_sql = f"""
        SELECT al.*,
               COALESCE(u.name, '') as operator_name,
               COALESCE(u.email, '') as operator_email
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        {where_clause}
        ORDER BY al.id DESC
        LIMIT ? OFFSET ?
    """
    rows = db.execute(data_sql, params + [page_size, offset]).fetchall()
    db.close()

    logs = []
    for r in rows:
        logs.append({
            "id": r["id"],
            "user_id": r["user_id"],
            "user_email": r["user_email"] or "",
            "operator_name": r["operator_name"] or "",
            "action": r["action"],
            "target_type": r["target_type"],
            "target_id": r["target_id"],
            "detail": r["detail"] or "",
            "ip_address": r["ip_address"] or "",
            "created_at": r["created_at"],
            # v2 enhanced fields (columns added via migration)
            "result": r["result"],
            "risk_level": r["risk_level"],
            "user_agent": r["user_agent"],
            "duration_ms": r["duration_ms"],
            "request_path": r["request_path"],
            "request_method": r["request_method"],
        })

    return jsonify({
        "data": logs,
        "pagination": {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        },
    })


@audit_bp.route("/stats", methods=["GET"])
@login_required
def audit_stats():
    """GET /api/audit/stats — 审计统计概览。"""
    db = get_db()

    # 今日操作数
    today_count = db.execute("""
        SELECT COUNT(*) as cnt FROM audit_logs
        WHERE date(created_at) = date('now','localtime')
    """).fetchone()["cnt"]

    # 本周操作数
    week_count = db.execute("""
        SELECT COUNT(*) as cnt FROM audit_logs
        WHERE created_at >= datetime('now','localtime','-7 days')
    """).fetchone()["cnt"]

    # 按操作类型分布（Top 10）
    by_action = db.execute("""
        SELECT action, COUNT(*) as cnt FROM audit_logs
        GROUP BY action ORDER BY cnt DESC LIMIT 10
    """).fetchall()

    # 按资源类型分布
    by_target = db.execute("""
        SELECT target_type, COUNT(*) as cnt FROM audit_logs
        GROUP BY target_type ORDER BY cnt DESC
    """).fetchall()

    # 最近的安全事件（登录失败、锁定等）
    security_events = db.execute("""
        SELECT * FROM audit_logs
        WHERE action LIKE 'security.%' OR action LIKE 'user.login_failed%'
        ORDER BY id DESC LIMIT 10
    """).fetchall()

    # 最活跃用户
    top_users = db.execute("""
        SELECT user_id, user_email, COUNT(*) as cnt
        FROM audit_logs WHERE user_id IS NOT NULL
        GROUP BY user_id ORDER BY cnt DESC LIMIT 5
    """).fetchall()

    db.close()

    return jsonify({
        "today_count": today_count,
        "week_count": week_count,
        "by_action": [{"action": r["action"], "count": r["cnt"]} for r in by_action],
        "by_target": [{"type": r["target_type"], "count": r["cnt"]} for r in by_target],
        "security_events": [{
            "id": r["id"], "action": r["action"], "detail": r["detail"],
            "ip_address": r["ip_address"], "created_at": r["created_at"],
        } for r in security_events],
        "top_users": [{
            "user_id": r["user_id"], "email": r["user_email"], "count": r["cnt"]
        } for r in top_users],
    })


@audit_bp.route("/export", methods=["GET"])
@login_required
def export_audit_logs():
    """GET /api/audit/export — 导出审计日志为 CSV 格式。"""
    import csv
    import io
    from flask import Response

    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    db = get_db()
    conditions = []
    params = []
    if start_date:
        conditions.append("created_at >= ?")
        params.append(start_date + " 00:00:00")
    if end_date:
        conditions.append("created_at <= ?")
        params.append(end_date + " 23:59:59")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    rows = db.execute(f"""
        SELECT al.*, COALESCE(u.name, '') as operator_name
        FROM audit_logs al LEFT JOIN users u ON al.user_id = u.id
        {where} ORDER BY al.id DESC
    """, params).fetchall()
    db.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "时间", "操作人ID", "操作人邮箱", "操作人姓名",
        "操作类型", "资源类型", "资源ID", "详情", "IP地址"
    ])
    for r in rows:
        writer.writerow([
            r["id"], r["created_at"], r["user_id"], r["user_email"],
            r["operator_name"], r["action"], r["target_type"],
            r["target_id"], r["detail"], r["ip_address"],
        ])

    output.seek(0)

    from routes.audit import audit_report_export
    audit_report_export(
        getattr(request, "current_user_id", None), len(rows)
    )

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinel-audit-logs.csv"},
    )
