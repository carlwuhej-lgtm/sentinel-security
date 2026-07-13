import logging
logger = logging.getLogger(__name__)
# ─── 工单管理 API ───
"""
简易工单系统：创建、分配、状态流转、评论
一人安全团队核心模块：把"发现问题"变成"追踪修复"
/api/tickets/*
"""
from flask import Blueprint, request, jsonify
import datetime
import json

tickets_bp = Blueprint("tickets", __name__)

from app import get_db
from routes.auth import login_required
from routes.audit import audit_log

VALID_PRIORITIES = ("critical", "high", "medium", "low")


def _push_ticket_feishu(ticket, event="created"):
    """新工单 / 工单解决时，推送到已启用(enabled=1)的飞书渠道。

    渠道配置复用 notification_channels 表（channel_type='feishu'，可选 secret 签名）。
    推送失败不影响工单主流程。
    """
    ticket = dict(ticket)  # sqlite3.Row 没有 .get()，统一转 dict 便于取值
    try:
        from services.notification_service import _send_feishu
        ch_db = get_db()
        channels = ch_db.execute(
            "SELECT webhook_url, secret FROM notification_channels "
            "WHERE channel_type='feishu' AND enabled=1"
        ).fetchall()
        ch_db.close()
        if not channels:
            return
        prefix = "🎫 新工单" if event == "created" else "✅ 工单已解决"
        title = f"{prefix} #{ticket['id']} [{ticket['priority']}] {str(ticket['title'])[:24]}"
        desc = str(ticket.get("description") or "")
        content = (
            f"**优先级**: {ticket['priority']}\n"
            f"**状态**: {ticket['status']}\n"
            f"**描述**: {desc[:200]}\n\n"
            f"> 请登录哨兵安全平台处理"
        )
        for ch in channels:
            ok, msg = _send_feishu(ch["webhook_url"], title, content, ch["secret"] or "")
            logger.info(f"[Ticket] feishu push -> {str(ch['webhook_url'])[:40]}: {'OK' if ok else msg[:80]}")
    except Exception as e:
        logger.error(f"[Ticket] feishu push error: {e}")


# ══════════════════════════════════════════════
#  工单列表
# ══════════════════════════════════════════════

@tickets_bp.route("", methods=["GET"])
@login_required
def list_tickets():
    db = get_db()
    try:
        status = request.args.get("status", "")
        priority = request.args.get("priority", "")
        search = request.args.get("search", "")
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(50, max(1, int(request.args.get("per_page", 20))))

        base_from = "FROM tickets t LEFT JOIN users u ON t.assigned_to = u.id LEFT JOIN users c ON t.created_by = c.id"
        q = f"SELECT t.*, u.name as assignee_name, c.name as creator_name {base_from} WHERE 1=1"
        count_q = f"SELECT COUNT(*) {base_from} WHERE 1=1"
        params = []

        if status:
            q += " AND t.status=?"
            count_q += " AND t.status=?"
            params.append(status)
        if priority:
            q += " AND t.priority=?"
            count_q += " AND t.priority=?"
            params.append(priority)
        if search:
            q += " AND (t.title LIKE ? OR t.description LIKE ?)"
            count_q += " AND (t.title LIKE ? OR t.description LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        total = db.execute(count_q, params).fetchone()[0]

        q += " ORDER BY CASE t.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, t.created_at DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])

        rows = db.execute(q, params).fetchall()

        return jsonify({
            "items": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": max(1, (total + per_page - 1) // per_page)
        })
    finally:
        db.close()


# ══════════════════════════════════════════════
#  工单详情
# ══════════════════════════════════════════════

@tickets_bp.route("/<int:tid>", methods=["GET"])
@login_required
def get_ticket(tid):
    db = get_db()
    try:
        row = db.execute("""
            SELECT t.*, u.name as assignee_name, c.name as creator_name
            FROM tickets t
            LEFT JOIN users u ON t.assigned_to = u.id
            LEFT JOIN users c ON t.created_by = c.id
            WHERE t.id=?
        """, (tid,)).fetchone()
        if not row:
            return jsonify({"error": "工单不存在"}), 404

        # 获取评论
        comments = db.execute("""
            SELECT tc.*, u.name as user_name, u.email as user_email
            FROM ticket_comments tc
            LEFT JOIN users u ON tc.user_id = u.id
            WHERE tc.ticket_id=?
            ORDER BY tc.created_at ASC
        """, (tid,)).fetchall()

        result = dict(row)
        result["comments"] = [dict(c) for c in comments]

        # 如果关联了漏洞/告警，拉取来源详情
        if row["source_type"] == "vuln" and row["source_id"]:
            source = db.execute("""
                SELECT v.*, s.tool_type, p.name as project_name
                FROM vulnerabilities v
                LEFT JOIN scan_tasks s ON v.scan_id = s.id
                LEFT JOIN projects p ON s.project_id = p.id
                WHERE v.id=?
            """, (row["source_id"],)).fetchone()
            if source:
                result["source_detail"] = dict(source)

        elif row["source_type"] == "alert" and row["source_id"]:
            source = db.execute("SELECT * FROM alerts WHERE id=?", (row["source_id"],)).fetchone()
            if source:
                result["source_detail"] = dict(source)

        return jsonify(result)
    finally:
        db.close()


# ══════════════════════════════════════════════
#  创建工单
# ══════════════════════════════════════════════

@tickets_bp.route("", methods=["POST"])
@login_required
def create_ticket():
    data = request.get_json(silent=True) or {}
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"error": "工单标题不能为空"}), 400

    db = get_db()
    try:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        description = data.get("description", "")
        priority = data.get("priority", "medium")
        source_type = data.get("source_type", "manual")
        source_id = int(data.get("source_id", 0))
        source_url = data.get("source_url", "")
        assigned_to = data.get("assigned_to") or None
        created_by = getattr(request, "current_user_id", None)
        due_date = data.get("due_date", "")

        if priority not in VALID_PRIORITIES:
            return jsonify({"error": f"无效优先级: {priority}，有效值: {', '.join(VALID_PRIORITIES)}"}), 400

        cur = db.execute(
            """INSERT INTO tickets (title, description, priority, status, source_type,
               source_id, source_url, assigned_to, created_by, due_date, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (title, description, priority, "open", source_type,
             source_id, source_url, assigned_to, created_by, due_date, now, now)
        )
        db.commit()

        audit_log(
            request.current_user_id, "",
            "ticket.create", "ticket", cur.lastrowid,
            f"创建工单: [{title[:60]}] 优先级={priority}"
        )

        row = db.execute("""
            SELECT t.*, u.name as assignee_name, c.name as creator_name
            FROM tickets t
            LEFT JOIN users u ON t.assigned_to = u.id
            LEFT JOIN users c ON t.created_by = c.id
            WHERE t.id=?
        """, (cur.lastrowid,)).fetchone()
        _push_ticket_feishu(row, "created")
        return jsonify(dict(row)), 201
    finally:
        db.close()


# ══════════════════════════════════════════════
#  更新工单
# ══════════════════════════════════════════════

@tickets_bp.route("/<int:tid>", methods=["PUT"])
@login_required
def update_ticket(tid):
    data = request.get_json(silent=True) or {}
    db = get_db()
    try:
        existing = db.execute("SELECT id, title FROM tickets WHERE id=?", (tid,)).fetchone()
        if not existing:
            return jsonify({"error": "工单不存在"}), 404

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        updatable = ["title", "description", "priority", "assigned_to", "due_date"]
        sets = []
        vals = []
        for k in updatable:
            if k in data:
                if k == "priority" and data[k] not in VALID_PRIORITIES:
                    return jsonify({"error": f"无效优先级: {data[k]}，有效值: {', '.join(VALID_PRIORITIES)}"}), 400
                sets.append(f"{k}=?")
                vals.append(data[k])
        if "status" in data:
            new_status = data["status"]
            if new_status not in ("open", "in_progress", "resolved", "closed"):
                return jsonify({"error": "无效状态"}), 400
            sets.append("status=?")
            vals.append(new_status)
            if new_status == "resolved":
                sets.append("resolved_at=?")
                vals.append(now)

        if sets:
            vals.append(now)
            sets.append("updated_at=?")
            vals.append(tid)
            db.execute(f"UPDATE tickets SET {','.join(sets)} WHERE id=?", vals)
            db.commit()

        row = db.execute("""
            SELECT t.*, u.name as assignee_name, c.name as creator_name
            FROM tickets t
            LEFT JOIN users u ON t.assigned_to = u.id
            LEFT JOIN users c ON t.created_by = c.id
            WHERE t.id=?
        """, (tid,)).fetchone()
        if data.get("status") == "resolved":
            _push_ticket_feishu(row, "resolved")
        return jsonify(dict(row))
    finally:
        db.close()


# ══════════════════════════════════════════════
#  删除工单
# ══════════════════════════════════════════════

@tickets_bp.route("/<int:tid>", methods=["DELETE"])
@login_required
def delete_ticket(tid):
    db = get_db()
    try:
        existing = db.execute("SELECT id, title FROM tickets WHERE id=?", (tid,)).fetchone()
        if not existing:
            return jsonify({"error": "工单不存在"}), 404
        db.execute("DELETE FROM tickets WHERE id=?", (tid,))
        db.commit()
        audit_log(
            request.current_user_id, "",
            "ticket.delete", "ticket", tid,
            f"删除工单: [{existing['title'][:60]}]"
        )
        return jsonify({"message": "已删除"})
    finally:
        db.close()


# ══════════════════════════════════════════════
#  添加评论
# ══════════════════════════════════════════════

@tickets_bp.route("/<int:tid>/comments", methods=["POST"])
@login_required
def add_comment(tid):
    data = request.get_json(silent=True) or {}
    content = data.get("content", "").strip()
    if not content:
        return jsonify({"error": "评论内容不能为空"}), 400

    db = get_db()
    try:
        existing = db.execute("SELECT id FROM tickets WHERE id=?", (tid,)).fetchone()
        if not existing:
            return jsonify({"error": "工单不存在"}), 404

        user_id = getattr(request, "current_user_id", None)
        cur = db.execute(
            "INSERT INTO ticket_comments (ticket_id, user_id, content) VALUES (?,?,?)",
            (tid, user_id, content)
        )
        db.commit()

        row = db.execute(
            "SELECT tc.*, u.name as user_name FROM ticket_comments tc LEFT JOIN users u ON tc.user_id = u.id WHERE tc.id=?",
            (cur.lastrowid,)
        ).fetchone()
        return jsonify(dict(row)), 201
    finally:
        db.close()


# ══════════════════════════════════════════════
#  统计
# ══════════════════════════════════════════════

@tickets_bp.route("/stats", methods=["GET"])
@login_required
def ticket_stats():
    db = get_db()
    try:
        open_count = db.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0]
        in_progress = db.execute("SELECT COUNT(*) FROM tickets WHERE status='in_progress'").fetchone()[0]
        resolved = db.execute("SELECT COUNT(*) FROM tickets WHERE status='resolved'").fetchone()[0]
        by_priority = db.execute(
            "SELECT priority, COUNT(*) as cnt FROM tickets WHERE status IN ('open','in_progress') GROUP BY priority"
        ).fetchall()
        return jsonify({
            "open": open_count,
            "in_progress": in_progress,
            "resolved": resolved,
            "active": open_count + in_progress,
            "by_priority": [dict(r) for r in by_priority]
        })
    finally:
        db.close()
