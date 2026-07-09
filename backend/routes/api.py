# ─── Business API Routes ───
"""Contacts, vulnerability management, threat events, user management."""

import random
from flask import Blueprint, request, jsonify
from app import get_db
from routes.auth import login_required, admin_required
from routes.security import rate_limiter, validate_email

api_bp = Blueprint("api", __name__)


@api_bp.route("/", methods=["GET"])
@api_bp.route("", methods=["GET"])
def api_index():
    """GET /api/ — API 健康检查 & 索引"""
    db = get_db()
    try:
        user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    except Exception:
        user_count = 0
    return jsonify({
        "name": "Sentinel AppSec Platform",
        "version": "4.0",
        "status": "running",
        "users": user_count,
        "endpoints": {
            "auth": "/api/auth/*",
            "projects": "/api/projects/*",
            "scans": "/api/scans/*",
            "vulnerabilities": "/api/vulnerabilities/*",
            "alerts": "/api/alerts/*",
            "tickets": "/api/tickets/*",
            "rules": "/api/rules/*",
            "assets": "/api/assets/*",
            "reports": "/api/reports/*",
            "ai": "/api/ai/*",
            "knowledge_base": "/api/knowledge-base/*",
            "audit": "/api/audit/*",
            "dashboard": "/api/dashboard/*",
            "settings": "/api/settings/*",
            "tools": "/api/tools/*",
            "users": "/api/users",
        }
    })

# ──────────────────────────── Contact ────────────────────────────

@api_bp.route("/contact", methods=["POST"])
@rate_limiter(10, 3600)
def contact():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    if not name or not email:
        return jsonify({"error": "姓名和邮箱不能为空"}), 400
    if not validate_email(email):
        return jsonify({"error": "邮箱格式不正确"}), 400

    db = get_db()
    db.execute(
        "INSERT INTO contacts (name,email,company,phone,message,type) VALUES (?,?,?,?,?,?)",
        (name, email, data.get("company", "").strip(), data.get("phone", "").strip(),
         data.get("message", "").strip(), data.get("type", "contact").strip()),
    )
    db.commit()
    return jsonify({"ok": True, "message": "提交成功"}), 201


@api_bp.route("/contacts", methods=["GET"])
@login_required
def list_contacts():
    db = get_db()
    rows = db.execute("SELECT * FROM contacts ORDER BY created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])


# ──────────────────────────── Vulnerabilities ────────────────────────────

@api_bp.route("/vulnerabilities", methods=["GET"])
@login_required
def list_vulns():
    db = get_db()
    severity = request.args.get("severity")
    status = request.args.get("status")  # 支持逗号分隔多值
    search = request.args.get("search", "")
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(100, max(1, int(request.args.get("per_page", 20))))

    conditions = []
    params: list = []
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
    if search:
        conditions.append("(v.title LIKE ? OR v.cve_id LIKE ? OR v.file_path LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    # 总数
    total = db.execute(
        f"SELECT COUNT(*) FROM vulnerabilities v {where}", params
    ).fetchone()[0]

    # 分页
    rows = db.execute(
        f"""SELECT v.*, s.tool_type, p.name as project_name
           FROM vulnerabilities v
           LEFT JOIN scan_tasks s ON v.scan_id = s.id
           LEFT JOIN projects p ON s.project_id = p.id
           {where}
           ORDER BY v.created_at DESC
           LIMIT ? OFFSET ?""",
        params + [per_page, (page - 1) * per_page]
    ).fetchall()

    return jsonify({
        "items": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    })


@api_bp.route("/vulnerabilities/<int:vid>", methods=["GET", "PATCH", "DELETE"])
@login_required
def get_update_delete_vuln(vid):
    db = get_db()
    row = db.execute(
        """SELECT v.*, s.tool_type, p.name as project_name
           FROM vulnerabilities v
           LEFT JOIN scan_tasks s ON v.scan_id = s.id
           LEFT JOIN projects p ON s.project_id = p.id
           WHERE v.id=?""",
        (vid,)
    ).fetchone()
    if not row:
        return jsonify({"error": "漏洞不存在"}), 404

    if request.method == "GET":
        return jsonify(dict(row))

    if request.method == "DELETE":
        if request.current_user_role != "admin":
            return jsonify({"error": "forbidden", "message": "需要管理员权限"}), 403
        db.execute("DELETE FROM vulnerabilities WHERE id=?", (vid,))
        db.commit()
        return jsonify({"ok": True, "message": "漏洞已删除"})

    # PATCH — 支持更新漏洞字段
    data = request.get_json(silent=True) or {}
    updatable = ["status", "severity", "assigned_to", "ai_analysis", "fix_suggestion"]
    for key in updatable:
        if key in data:
            db.execute(f"UPDATE vulnerabilities SET {key}=? WHERE id=?", (data[key], vid))
    db.commit()
    return jsonify({"ok": True})


# ──────────────────────────── Threat Events ────────────────────────────

@api_bp.route("/threats/seed", methods=["POST"])
@admin_required
def seed_threats():
    types = [
        ("sql_injection", "high"), ("xss_attempt", "medium"), ("brute_force", "high"),
        ("port_scan", "low"), ("directory_traversal", "medium"),
        ("privilege_escalation", "critical"), ("data_exfiltration", "critical"),
        ("malware_detected", "high"),
    ]
    ips = [f"203.0.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(8)]
    db = get_db()
    for _ in range(20):
        t, s = random.choice(types)
        db.execute(
            "INSERT INTO threat_events (event_type,source_ip,severity,blocked,detail) VALUES (?,?,?,?,?)",
            (t, random.choice(ips), s, 1, f"检测到 {t} 攻击，已自动拦截"),
        )
    db.commit()
    return jsonify({"ok": True, "message": "已生成 20 条威胁事件"})


@api_bp.route("/threats", methods=["GET"])
@login_required
def list_threats():
    db = get_db()
    rows = db.execute("SELECT * FROM threat_events ORDER BY created_at DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])


# ──────────────────────────── Users ────────────────────────────

@api_bp.route("/users", methods=["GET"])
@login_required
def list_users():
    """用户列表。
    - admin/security_analyst: 查看完整信息（含 email）
    - 其他角色: 仅查看 id + name（用于分配漏洞）
    """
    db = get_db()
    role = request.current_user_role
    if role in ("admin", "security_analyst"):
        rows = db.execute(
            "SELECT id,email,name,role,created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
    else:
        # 普通用户只能看到基本信息，用于分配漏洞时的下拉选择
        rows = db.execute(
            "SELECT id,name,role FROM users ORDER BY name"
        ).fetchall()
    return jsonify([dict(r) for r in rows])
