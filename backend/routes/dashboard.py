# ─── Dashboard Stats Routes ───
from flask import Blueprint, jsonify
from app import get_db
from routes.auth import login_required

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/stats", methods=["GET"])
@login_required
def stats():
    db = get_db()
    total_users = db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    total_projects = db.execute("SELECT COUNT(*) as c FROM projects").fetchone()["c"]
    total_scans = db.execute("SELECT COUNT(*) as c FROM scan_tasks").fetchone()["c"]
    total_contacts = db.execute("SELECT COUNT(*) as c FROM contacts").fetchone()["c"]
    active_tools = db.execute("SELECT COUNT(*) as c FROM tools WHERE enabled=1").fetchone()["c"]

    # 只统计未关闭的漏洞（open + in_progress）
    vuln = db.execute("SELECT severity, COUNT(*) as c FROM vulnerabilities WHERE status IN ('open','in_progress') GROUP BY severity").fetchall()
    vuln_map = {r["severity"]: r["c"] for r in vuln}

    # 已修复/忽略的数量
    vuln_fixed = db.execute(
        "SELECT COUNT(*) as c FROM vulnerabilities WHERE status='fixed'"
    ).fetchone()["c"]
    vuln_ignored = db.execute(
        "SELECT COUNT(*) as c FROM vulnerabilities WHERE status='ignored'"
    ).fetchone()["c"]
    vuln_open = db.execute(
        "SELECT COUNT(*) as c FROM vulnerabilities WHERE status IN ('open','in_progress')"
    ).fetchone()["c"]

    recent_scans = db.execute("""
        SELECT s.*, p.name as project_name
        FROM scan_tasks s LEFT JOIN projects p ON s.project_id = p.id
        ORDER BY s.created_at DESC LIMIT 10
    """).fetchall()

    recent_vulns = db.execute("""
        SELECT v.*, s.tool_type
        FROM vulnerabilities v LEFT JOIN scan_tasks s ON v.scan_id = s.id
        WHERE v.status IN ('open','in_progress')
        ORDER BY v.created_at DESC LIMIT 10
    """).fetchall()

    # SLA stats
    sla_breached = db.execute(
        "SELECT COUNT(*) as c FROM vulnerabilities WHERE sla_breached=1 AND status IN ('open','in_progress')"
    ).fetchone()["c"]
    sla_urgent = db.execute(
        "SELECT COUNT(*) as c FROM vulnerabilities WHERE status IN ('open','in_progress') AND sla_breached=0 AND sla_due_date!='' AND sla_due_date>datetime('now','localtime') AND sla_due_date<datetime('now','localtime','+24 hours')"
    ).fetchone()["c"]

    # Alert stats (Phase 4)
    try:
        alerts_new = db.execute("SELECT COUNT(*) as c FROM alerts WHERE status='new'").fetchone()["c"]
        alerts_pending = db.execute("SELECT COUNT(*) as c FROM alerts WHERE status IN ('new','acknowledged')").fetchone()["c"]
        alerts_critical = db.execute("SELECT COUNT(*) as c FROM alerts WHERE severity='critical' AND status='new'").fetchone()["c"]
        alerts_high = db.execute("SELECT COUNT(*) as c FROM alerts WHERE severity='high' AND status='new'").fetchone()["c"]
        alert_stats = {
            "new": alerts_new,
            "pending": alerts_pending,
            "critical": alerts_critical,
            "high": alerts_high,
        }
    except Exception:
        alert_stats = {"new": 0, "pending": 0, "critical": 0, "high": 0}

    return jsonify({
        "totalUsers": total_users,
        "totalProjects": total_projects,
        "totalScans": total_scans,
        "totalContacts": total_contacts,
        "totalVulnerabilities": sum(vuln_map.values()),
        "activeTools": active_tools,
        "vulnerabilities": {
            "critical": vuln_map.get("critical", 0),
            "high": vuln_map.get("high", 0),
            "medium": vuln_map.get("medium", 0),
            "low": vuln_map.get("low", 0),
        },
        "sla": {
            "breached": sla_breached,
            "urgent": sla_urgent,
            "fixed": vuln_fixed,
            "open": vuln_open,
            "ignored": vuln_ignored,
            "fixRate": round(vuln_fixed / max(vuln_open + vuln_fixed, 1) * 100, 1),
        },
        "alerts": alert_stats,
        "recentScans": [dict(r) for r in recent_scans],
        "recentVulnerabilities": [dict(r) for r in recent_vulns],
    })
