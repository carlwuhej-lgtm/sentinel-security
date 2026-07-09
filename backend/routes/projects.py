"""
项目 CRUD — 接入审计日志 + RBAC 权限控制
"""

from flask import Blueprint, request, jsonify
from app import get_db
from routes.auth import login_required, admin_required, require_permission, RES_PROJECT
from routes.security import get_json_body, sanitize_string, validate_project_type
from routes.audit import audit_log

projects_bp = Blueprint("projects", __name__)


@projects_bp.route("", methods=["GET"])
@login_required
@require_permission(RES_PROJECT, "read")
def list_projects():
    db = get_db()
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    offset = (page - 1) * per_page

    total = db.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
    rows = db.execute(
        "SELECT * FROM projects ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (per_page, offset),
    ).fetchall()
    db.close()

    return jsonify({
        "items": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    })


@projects_bp.route("/<int:pid>", methods=["GET"])
@login_required
@require_permission(RES_PROJECT, "read")
def get_project(pid: int):
    db = get_db()
    row = db.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
    db.close()
    if not row:
        return jsonify({"error": "项目不存在"}), 404
    return jsonify(dict(row))


@projects_bp.route("", methods=["POST"])
@login_required
@admin_required
def create_project():
    data = get_json_body()
    if not data:
        return jsonify({"error": "无效的请求数据"}), 400

    name = sanitize_string(data.get("name") or "")
    if not name:
        return jsonify({"error": "项目名称不能为空"}), 400

    repo_url     = sanitize_string(data.get("repo_url", "") or "")
    target_url   = sanitize_string(data.get("target_url", "") or "")
    local_path   = sanitize_string(data.get("local_path", "") or "")
    language     = sanitize_string(data.get("language", "auto") or "auto")
    project_type = sanitize_string(data.get("project_type", "web") or "web")
    description  = sanitize_string(data.get("description", "") or "")

    if not validate_project_type(project_type):
        return jsonify({"error": f"无效的项目类型: {project_type}"}), 400

    db = get_db()
    cur = db.execute(
        """INSERT INTO projects (name, repo_url, target_url, local_path, language, project_type, description)
           VALUES (?,?,?,?,?,?,?)""",
        (name, repo_url, target_url, local_path, language, project_type, description)
    )
    db.commit()
    new_id = cur.lastrowid
    row = db.execute("SELECT * FROM projects WHERE id=?", (new_id,)).fetchone()
    db.close()

    audit_log(
        request.current_user_id, "",
        "project.create", "project", new_id,
        f"创建项目: {name} ({project_type}/{language})"
    )

    return jsonify(dict(row)), 201


@projects_bp.route("/<int:pid>", methods=["PUT"])
@login_required
@admin_required
def update_project(pid: int):
    db = get_db()
    row = db.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "项目不存在"}), 404

    data = get_json_body()
    new_repo_url     = sanitize_string(data.get("repo_url",     row["repo_url"]     or "") or "")
    new_target_url   = sanitize_string(data.get("target_url",   row["target_url"]   or "") or "")
    new_local_path   = sanitize_string(data.get("local_path",   row["local_path"]   or "") or "")
    new_language     = sanitize_string(data.get("language",     row["language"]     or "") or "auto")
    new_project_type = sanitize_string(data.get("project_type", row["project_type"] or "") or "web")
    new_description  = sanitize_string(data.get("description",  row["description"]  or "") or "")
    new_name         = sanitize_string(data.get("name",         row["name"]) or "")

    db.execute(
        """UPDATE projects SET name=?, repo_url=?, target_url=?, local_path=?, language=?, project_type=?, description=? WHERE id=?""",
        (new_name, new_repo_url, new_target_url, new_local_path, new_language, new_project_type, new_description, pid)
    )
    db.commit()
    updated = db.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
    db.close()

    audit_log(
        request.current_user_id, "",
        "project.update", "project", pid,
        f"更新项目: {row['name']}"
    )

    return jsonify(dict(updated))


@projects_bp.route("/<int:pid>", methods=["DELETE"])
@login_required
@admin_required
def delete_project(pid: int):
    db = get_db()
    row = db.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "项目不存在"}), 404

    name = row["name"]
    db.execute("DELETE FROM projects WHERE id=?", (pid,))
    db.commit()
    db.close()

    audit_log(
        request.current_user_id, "",
        "project.delete", "project", pid,
        f"删除项目: {name}"
    )

    return jsonify({"ok": True, "message": "项目已删除"})
