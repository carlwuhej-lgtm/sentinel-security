# ─── 告警管理 API ───
"""
告警引擎 — 扫描完成后自动生成告警，支持人工确认/关闭
/api/alerts/*
"""

from flask import Blueprint, request, jsonify
import datetime, json

alerts_bp = Blueprint("alerts", __name__)

from app import get_db
from routes.auth import login_required, admin_required
from routes.audit import audit_log


# ══════════════════════════════════════════════
#  告警生成（内部调用 — 扫描完成时触发）
# ══════════════════════════════════════════════

def generate_scan_alert(db, scan_id: int, project_id: int, project_name: str,
                        vuln_count: int, critical: int, high: int) -> int | None:
    """
    扫描完成后，如果有 Critical 或 High 漏洞，自动生成告警。
    支持告警收敛：同一项目 5 分钟内不重复生成相同类型告警。
    返回 alert_id 或 None。
    """
    if critical == 0 and high == 0:
        return None  # 无高危漏洞，不告警

    # 告警收敛检查
    dedup_minutes = 5
    try:
        row = db.execute("SELECT dedup_minutes FROM alert_config WHERE id=1").fetchone()
        if row:
            dedup_minutes = row["dedup_minutes"]
    except Exception:
        pass

    cutoff = (datetime.datetime.now() - datetime.timedelta(minutes=dedup_minutes)).strftime("%Y-%m-%d %H:%M:%S")
    existing = db.execute(
        "SELECT id FROM alerts WHERE source_type='scan' AND source_id=? AND created_at > ? AND status='new'",
        (scan_id, cutoff)
    ).fetchone()
    if existing:
        return None  # 收敛：同一次扫描不重复告警

    # 确定严重级别
    if critical > 0:
        severity = "critical"
    elif high > 0:
        severity = "high"
    else:
        severity = "medium"

    title = f"扫描告警: {project_name} 发现 {critical + high} 个高危漏洞"
    detail = {
        "scan_id": scan_id,
        "critical_count": critical,
        "high_count": high,
        "total_count": vuln_count,
    }

    cur = db.execute(
        """INSERT INTO alerts (alert_type, title, severity, source_type, source_id,
           project_id, project_name, vuln_count, critical_count, high_count, detail_json)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "scan_completed", title, severity, "scan", scan_id,
            project_id, project_name, vuln_count, critical, high,
            json.dumps(detail, ensure_ascii=False)
        )
    )
    db.commit()
    return cur.lastrowid


# ══════════════════════════════════════════════
#  告警列表
# ══════════════════════════════════════════════

@alerts_bp.route("", methods=["GET"])
@login_required
def list_alerts():
    db = get_db()
    try:
        status = request.args.get("status", "")
        severity = request.args.get("severity", "")
        search = request.args.get("search", "")
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 20))))

        q = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if status:
            status_list = [s.strip() for s in status.split(",") if s.strip()]
            if len(status_list) == 1:
                q += " AND status=?"
                params.append(status_list[0])
            elif len(status_list) > 1:
                placeholders = ",".join(["?"] * len(status_list))
                q += f" AND status IN ({placeholders})"
                params.extend(status_list)
        if severity:
            q += " AND severity=?"
            params.append(severity)
        if search:
            q += " AND (title LIKE ? OR project_name LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        # 计数
        count_q = q.replace("SELECT *", "SELECT COUNT(*)")
        total = db.execute(count_q, params).fetchone()[0]

        q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])

        rows = db.execute(q, params).fetchall()
        items = []
        for r in rows:
            d = dict(r)
            if d.get("detail_json") and isinstance(d["detail_json"], str):
                try:
                    d["detail"] = json.loads(d["detail_json"])
                except (json.JSONDecodeError, TypeError):
                    d["detail"] = {}
            else:
                d["detail"] = {}
            items.append(d)

        return jsonify({
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": max(1, (total + per_page - 1) // per_page),
        })
    finally:
        db.close()


# ══════════════════════════════════════════════
#  告警统计
# ══════════════════════════════════════════════

@alerts_bp.route("/stats", methods=["GET"])
@login_required
def alert_stats():
    db = get_db()
    try:
        today = datetime.datetime.now().strftime("%Y-%m-%d")

        # 今日统计
        today_total = db.execute(
            "SELECT COUNT(*) FROM alerts WHERE date(created_at)=?",
            (today,)
        ).fetchone()[0]
        today_new = db.execute(
            "SELECT COUNT(*) FROM alerts WHERE date(created_at)=? AND status='new'",
            (today,)
        ).fetchone()[0]

        # 按状态统计
        by_status = db.execute(
            "SELECT status, COUNT(*) as cnt FROM alerts GROUP BY status"
        ).fetchall()

        # 按严重度统计
        by_severity = db.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts WHERE status='new' GROUP BY severity"
        ).fetchall()

        # 待处理总数
        pending = db.execute(
            "SELECT COUNT(*) FROM alerts WHERE status IN ('new','acknowledged')"
        ).fetchone()[0]

        # 7天趋势
        trend = []
        for i in range(6, -1, -1):
            d = (datetime.datetime.now() - datetime.timedelta(days=i)).strftime("%Y-%m-%d")
            cnt = db.execute(
                "SELECT COUNT(*) FROM alerts WHERE date(created_at)=?", (d,)
            ).fetchone()[0]
            trend.append({"date": d[5:], "count": cnt})  # MM-DD

        # 最近5条未处理告警
        recent = db.execute(
            "SELECT id, title, severity, project_name, status, created_at FROM alerts WHERE status IN ('new','acknowledged') ORDER BY created_at DESC LIMIT 5"
        ).fetchall()

        return jsonify({
            "today_total": today_total,
            "today_new": today_new,
            "pending": pending,
            "by_status": [dict(r) for r in by_status],
            "by_severity": [dict(r) for r in by_severity],
            "trend_7d": trend,
            "recent": [dict(r) for r in recent],
        })
    finally:
        db.close()


# ══════════════════════════════════════════════
#  告警详情
# ══════════════════════════════════════════════

@alerts_bp.route("/<int:aid>", methods=["GET"])
@login_required
def get_alert(aid):
    db = get_db()
    try:
        row = db.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
        if not row:
            return jsonify({"error": "告警不存在"}), 404
        d = dict(row)
        if d.get("detail_json") and isinstance(d["detail_json"], str):
            try:
                d["detail"] = json.loads(d["detail_json"])
            except (json.JSONDecodeError, TypeError):
                d["detail"] = {}
        else:
            d["detail"] = {}
        return jsonify(d)
    finally:
        db.close()


# ══════════════════════════════════════════════
#  更新告警状态
# ══════════════════════════════════════════════

@alerts_bp.route("/<int:aid>", methods=["PUT"])
@login_required
def update_alert(aid):
    data = request.get_json(silent=True) or {}
    new_status = data.get("status", "")
    if new_status not in ("acknowledged", "resolved", "false_positive"):
        return jsonify({"error": "无效状态: 仅支持 acknowledged / resolved / false_positive"}), 400

    db = get_db()
    try:
        existing = db.execute("SELECT id, title, status FROM alerts WHERE id=?", (aid,)).fetchone()
        if not existing:
            return jsonify({"error": "告警不存在"}), 404

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        updates = ["status=?", "updated_at=?"]
        params = [new_status, now]

        if new_status == "resolved":
            updates.append("resolved_at=?")
            params.append(now)

        params.append(aid)
        db.execute(f"UPDATE alerts SET {','.join(updates)} WHERE id=?", params)
        db.commit()

        # 审计日志
        audit_log(
            request.current_user_id, "",
            f"alert.{new_status}", "alert", aid,
            f"告警状态变更: [{existing['title'][:60]}] {existing['status']} -> {new_status}",
            risk_level="medium" if new_status == "resolved" else "low"
        )

        row = db.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
        return jsonify(dict(row))
    finally:
        db.close()


# ══════════════════════════════════════════════
#  批量操作告警
# ══════════════════════════════════════════════

@alerts_bp.route("/batch", methods=["POST"])
@login_required
def batch_update():
    data = request.get_json(silent=True) or {}
    ids = data.get("ids", [])
    action = data.get("action", "")

    if not ids or action not in ("acknowledge", "resolve"):
        return jsonify({"error": "参数错误"}), 400

    new_status = "acknowledged" if action == "acknowledge" else "resolved"
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    db = get_db()
    try:
        placeholders = ",".join("?" * len(ids))
        params = [new_status, now]
        if action == "resolve":
            db.execute(
                f"UPDATE alerts SET status=?, updated_at=?, resolved_at=? WHERE id IN ({placeholders})",
                params + [now] + ids
            )
        else:
            db.execute(
                f"UPDATE alerts SET status=?, updated_at=? WHERE id IN ({placeholders})",
                params + ids
            )
        db.commit()

        audit_log(
            request.current_user_id, "",
            f"alert.batch_{action}", "alert", 0,
            f"批量{action}: {len(ids)} 条告警"
        )

        return jsonify({"message": f"已{action} {len(ids)} 条告警", "count": len(ids)})
    finally:
        db.close()


# ══════════════════════════════════════════════
#  通知渠道管理
# ══════════════════════════════════════════════

@alerts_bp.route("/channels", methods=["GET"])
@login_required
def list_channels():
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM notification_channels ORDER BY channel_type, id").fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        db.close()


@alerts_bp.route("/channels", methods=["POST"])
@admin_required
def create_channel():
    data = request.get_json(silent=True) or {}
    channel_type = data.get("channel_type", "")
    if channel_type not in ("dingtalk", "wecom", "feishu", "webhook"):
        return jsonify({"error": "无效渠道类型"}), 400
    webhook_url = data.get("webhook_url", "").strip()
    if not webhook_url:
        return jsonify({"error": "Webhook URL 不能为空"}), 400

    db = get_db()
    try:
        cur = db.execute(
            """INSERT INTO notification_channels (channel_type, name, webhook_url, secret, enabled, config_json)
               VALUES (?,?,?,?,?,?)""",
            (
                channel_type,
                data.get("name", channel_type),
                webhook_url,
                data.get("secret", ""),
                int(data.get("enabled", True)),
                json.dumps(data.get("config", {}), ensure_ascii=False),
            )
        )
        db.commit()
        row = db.execute("SELECT * FROM notification_channels WHERE id=?", (cur.lastrowid,)).fetchone()
        return jsonify(dict(row)), 201
    finally:
        db.close()


@alerts_bp.route("/channels/<int:cid>", methods=["PUT"])
@admin_required
def update_channel(cid):
    data = request.get_json(silent=True) or {}
    db = get_db()
    try:
        existing = db.execute("SELECT id FROM notification_channels WHERE id=?", (cid,)).fetchone()
        if not existing:
            return jsonify({"error": "渠道不存在"}), 404

        updatable = ["channel_type", "name", "webhook_url", "secret", "enabled", "config_json"]
        sets = []
        vals = []
        for k in updatable:
            if k in data:
                v = data[k]
                if k == "config_json" and isinstance(v, dict):
                    v = json.dumps(v, ensure_ascii=False)
                sets.append(f"{k}=?")
                vals.append(v)

        if sets:
            vals.append(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            sets.append("updated_at=?")
            vals.append(cid)
            db.execute(f"UPDATE notification_channels SET {','.join(sets)} WHERE id=?", vals)
            db.commit()

        row = db.execute("SELECT * FROM notification_channels WHERE id=?", (cid,)).fetchone()
        return jsonify(dict(row))
    finally:
        db.close()


@alerts_bp.route("/channels/<int:cid>", methods=["DELETE"])
@admin_required
def delete_channel(cid):
    db = get_db()
    try:
        db.execute("DELETE FROM notification_channels WHERE id=?", (cid,))
        db.commit()
        return jsonify({"message": "已删除"})
    finally:
        db.close()


@alerts_bp.route("/channels/<int:cid>/test", methods=["POST"])
@admin_required
def test_channel(cid):
    """测试通知渠道是否连通。"""
    db = get_db()
    try:
        row = db.execute("SELECT * FROM notification_channels WHERE id=?", (cid,)).fetchone()
        if not row:
            return jsonify({"error": "渠道不存在"}), 404

        channel = dict(row)
        success, msg = _send_test_notification(channel)
        return jsonify({"success": success, "message": msg})
    finally:
        db.close()


def _send_test_notification(channel: dict) -> tuple:
    """发送测试通知到指定渠道。"""
    import requests as req
    try:
        webhook_url = channel["webhook_url"]
        msg = {
            "msgtype": "text",
            "text": {
                "content": f"【Sentinel 哨兵安全平台】\n通知渠道测试成功！\n渠道: {channel['name']}\n时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n此消息确认该渠道连通正常。"
            }
        }
        r = req.post(webhook_url, json=msg, timeout=10)
        if r.status_code == 200:
            return True, "测试消息发送成功"
        else:
            return False, f"返回状态码 {r.status_code}: {r.text[:100]}"
    except Exception as e:
        return False, str(e)


# ══════════════════════════════════════════════
#  告警配置
# ══════════════════════════════════════════════

@alerts_bp.route("/config", methods=["GET"])
@login_required
def get_alert_config():
    db = get_db()
    try:
        row = db.execute("SELECT * FROM alert_config WHERE id=1").fetchone()
        if not row:
            return jsonify({"dedup_minutes": 5, "severe_alert_on": ["critical", "high"], "auto_resolve_hours": 168})
        d = dict(row)
        try:
            d["severe_alert_on"] = json.loads(d["severe_alert_on"])
        except (json.JSONDecodeError, TypeError):
            d["severe_alert_on"] = ["critical", "high"]
        return jsonify(d)
    finally:
        db.close()


@alerts_bp.route("/config", methods=["PUT"])
@admin_required
def update_alert_config():
    data = request.get_json(silent=True) or {}
    db = get_db()
    try:
        if "dedup_minutes" in data:
            db.execute("UPDATE alert_config SET dedup_minutes=?, updated_at=? WHERE id=1",
                       (int(data["dedup_minutes"]), datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        if "severe_alert_on" in data:
            db.execute("UPDATE alert_config SET severe_alert_on=?, updated_at=? WHERE id=1",
                       (json.dumps(data["severe_alert_on"]), datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        if "auto_resolve_hours" in data:
            db.execute("UPDATE alert_config SET auto_resolve_hours=?, updated_at=? WHERE id=1",
                       (int(data["auto_resolve_hours"]), datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        db.commit()
        return jsonify({"message": "配置已更新"})
    finally:
        db.close()
