# ─── Today 视图 API ───
"""
一人安全团队的今日工作视图
聚合：紧急漏洞、待处理告警、SLA 超时、本周活动
/api/today/*
"""
from flask import Blueprint, jsonify, request
from datetime import datetime
from app import get_db
from routes.auth import login_required

today_bp = Blueprint("today", __name__)


@today_bp.route("", methods=["GET"])
@login_required
def today():
    db = get_db()
    # ── 时间范围解析 ──
    range_param = request.args.get('range', 'today')
    RANGE_SINCE = {
        'today': "datetime('now','localtime','start of day')",
        '7d': "datetime('now','localtime','-7 days')",
        '30d': "datetime('now','localtime','-30 days')",
        'all': None,
    }
    RANGE_LABEL = {'today': '今日', '7d': '近7天', '30d': '本月', 'all': '全部'}
    if range_param not in RANGE_SINCE:
        range_param = 'today'
    since = RANGE_SINCE[range_param]
    vuln_since = f" AND v.created_at >= {since} " if since else " "
    alert_since = f" AND created_at >= {since} " if since else " "
    try:
        # ── 1) 紧急漏洞 (Critical + High, 未关闭) ──
        urgent_vulns = db.execute(f"""
            SELECT v.id, v.title, v.severity, v.cve_id, v.file_path,
                   v.status, v.sla_due_date, v.sla_breached, v.created_at,
                   p.name as project_name
            FROM vulnerabilities v
            LEFT JOIN scan_tasks s ON v.scan_id = s.id
            LEFT JOIN projects p ON s.project_id = p.id
            WHERE v.status IN ('open','in_progress')
              AND v.severity IN ('critical','high')
              {vuln_since}
            ORDER BY
                CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 END,
                v.sla_breached DESC,
                v.created_at DESC
            LIMIT 5
        """).fetchall()

        # ── 2) 新未确认告警 ──
        new_alerts = db.execute(f"""
            SELECT id, title, severity, alert_type, project_name,
                   vuln_count, critical_count, high_count, status, created_at
            FROM alerts
            WHERE status IN ('new', 'acknowledged')
            {alert_since}
            ORDER BY
                CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
                created_at DESC
            LIMIT 5
        """).fetchall()

        # ── 3) SLA 即将到期 (24h 内，未超时，未关闭) ──
        sla_expiring = db.execute("""
            SELECT v.id, v.title, v.severity, v.sla_due_date, v.sla_breached,
                   v.status, v.created_at,
                   p.name as project_name
            FROM vulnerabilities v
            LEFT JOIN scan_tasks s ON v.scan_id = s.id
            LEFT JOIN projects p ON s.project_id = p.id
            WHERE v.status IN ('open','in_progress')
              AND v.sla_breached = 0
              AND v.sla_due_date != ''
              AND v.sla_due_date > datetime('now','localtime')
              AND v.sla_due_date < datetime('now','localtime','+24 hours')
            ORDER BY v.sla_due_date ASC
            LIMIT 5
        """).fetchall()

        # ── 4) SLA 已超时 ──
        sla_breached = db.execute("""
            SELECT v.id, v.title, v.severity, v.sla_due_date, v.sla_breached,
                   v.status, v.created_at,
                   p.name as project_name
            FROM vulnerabilities v
            LEFT JOIN scan_tasks s ON v.scan_id = s.id
            LEFT JOIN projects p ON s.project_id = p.id
            WHERE v.status IN ('open','in_progress')
              AND v.sla_breached = 1
            ORDER BY v.sla_due_date ASC
            LIMIT 5
        """).fetchall()

        # ── 5) 本周统计 ──
        this_week_fixed = db.execute("""
            SELECT COUNT(*) as c FROM vulnerabilities
            WHERE status='fixed'
              AND created_at >= datetime('now','localtime','-7 days')
        """).fetchone()["c"]
        total_open = db.execute("""
            SELECT COUNT(*) as c FROM vulnerabilities
            WHERE status IN ('open','in_progress')
        """).fetchone()["c"]
        total_fixed = db.execute("""
            SELECT COUNT(*) as c FROM vulnerabilities
            WHERE status='fixed'
        """).fetchone()["c"]
        this_week_new_vulns = db.execute("""
            SELECT COUNT(*) as c FROM vulnerabilities
            WHERE created_at >= datetime('now','localtime','-7 days')
        """).fetchone()["c"]

        # ── 5b) 按所选时间范围的统计 ──
        if since:
            range_new = db.execute(f"SELECT COUNT(*) as c FROM vulnerabilities WHERE created_at >= {since}").fetchone()["c"]
            range_fixed = db.execute(f"SELECT COUNT(*) as c FROM vulnerabilities WHERE status='fixed' AND created_at >= {since}").fetchone()["c"]
            range_scans = db.execute(f"SELECT COUNT(*) as c FROM scan_tasks WHERE created_at >= {since}").fetchone()["c"]
        else:
            range_new = db.execute("SELECT COUNT(*) as c FROM vulnerabilities").fetchone()["c"]
            range_fixed = db.execute("SELECT COUNT(*) as c FROM vulnerabilities WHERE status='fixed'").fetchone()["c"]
            range_scans = db.execute("SELECT COUNT(*) as c FROM scan_tasks").fetchone()["c"]

        # ── 6) 告警统计 ──
        alerts_pending = db.execute("""
            SELECT COUNT(*) as c FROM alerts
            WHERE status IN ('new','acknowledged')
        """).fetchone()["c"]
        alerts_critical = db.execute("""
            SELECT COUNT(*) as c FROM alerts
            WHERE severity='critical' AND status='new'
        """).fetchone()["c"]

        # ── 7) 工单统计 (如果表存在) ──
        tickets_open = 0
        try:
            tickets_open = db.execute(
                "SELECT COUNT(*) as c FROM tickets WHERE status IN ('open','in_progress')"
            ).fetchone()["c"]
        except Exception:
            pass

        count_breached = sum(1 for v in urgent_vulns if v["sla_breached"])

        now = datetime.now()
        today_date = now.strftime('%Y-%m-%d')
        today_weekday = ['周一', '周二', '周三', '周四', '周五', '周六', '周日'][now.weekday()]

        return jsonify({
            "range": range_param,
            "range_label": RANGE_LABEL[range_param],
            "today_date": today_date,
            "today_weekday": today_weekday,
            "urgent_vulns": [dict(r) for r in urgent_vulns],
            "new_alerts": [dict(r) for r in new_alerts],
            "sla_expiring": [dict(r) for r in sla_expiring],
            "sla_breached_list": [dict(r) for r in sla_breached],
            "stats": {
                "total_open_vulns": total_open,
                "total_fixed": total_fixed,
                "this_week_fixed": this_week_fixed,
                "this_week_new": this_week_new_vulns,
                "range_new": range_new,
                "range_fixed": range_fixed,
                "scans_in_range": range_scans,
                "alerts_pending": alerts_pending,
                "alerts_critical": alerts_critical,
                "sla_breached_count": count_breached,
                "tickets_open": tickets_open,
                "fix_rate": round(total_fixed / max(total_open + total_fixed, 1) * 100, 1)
            }
        })
    finally:
        db.close()
