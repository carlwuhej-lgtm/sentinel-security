# ─── Auth Routes (Phase 1 增强) ───
"""
认证路由 — 注册、登录、用户管理
Phase 1 改进：
- 登录暴力破解防护（IP 锁定）
- 登录/注册审计日志
- 密码自动升级（SHA256 → PBKDF2）
- 用户列表支持角色筛选
"""

import re
import html
from flask import Blueprint, request, jsonify, g
from app import get_db
from routes.auth import (
    hash_pw, verify_pw, needs_password_upgrade,
    make_token, decode_token, login_required, admin_required,
    get_all_roles,
)
from routes.security import (
    login_rate_limiter, is_login_locked,
    record_login_failure, record_login_success,
    get_json_body, validate_email, sanitize_string,
    is_account_locked, record_account_login_failure, record_account_login_success,
    rate_limiter,
)
from routes.audit import (
    audit_log, audit_user_register, audit_login_success,
    audit_login_failure, audit_login_blocked, audit_account_locked,
    audit_change_password, audit_role_change,
    audit_user_delete, audit_user_status_change, audit_user_unlock,
    audit_user_create,
)

auth_bp = Blueprint("auth", __name__)


def _validate_password_strength(password: str) -> str | None:
    """M-02: 密码强度校验。返回 None 表示通过，否则返回错误消息。"""
    if len(password) < 8:
        return "密码至少 8 位"
    if not re.search(r'[A-Z]', password):
        return "密码需包含至少一个大写字母"
    if not re.search(r'[a-z]', password):
        return "密码需包含至少一个小写字母"
    if not re.search(r'[0-9]', password):
        return "密码需包含至少一个数字"
    return None


@auth_bp.route("/register", methods=["POST"])
@rate_limiter(5, 300)  # M-07: 每 5 分钟最多 5 次注册
def register():
    # 安全加固：公开注册默认关闭，仅管理员可在「系统设置 → 注册策略」中开启
    from routes.settings import _get_setting
    _db = get_db()
    if _get_setting(_db, 'allow_public_register', 'false') != 'true':
        _db.close()
        return jsonify({"error": "注册已关闭", "message": "请联系管理员申请账号"}), 403
    data = get_json_body()
    if not data:
        return jsonify({"error": "无效的请求数据"}), 400

    email = sanitize_string(data.get("email") or "")
    password = sanitize_string(data.get("password") or "")
    name = html.escape(sanitize_string(data.get("name") or ""))

    if not email or not password:
        return jsonify({"error": "邮箱和密码不能为空"}), 400
    # M-02: 密码强度校验
    pw_error = _validate_password_strength(password)
    if pw_error:
        return jsonify({"error": pw_error}), 400
    if not validate_email(email):
        return jsonify({"error": "邮箱格式不正确"}), 400

    db = get_db()
    exists = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if exists:
        db.close()
        return jsonify({"error": "该邮箱已注册"}), 409

    hashed = hash_pw(password)
    db.execute(
        "INSERT INTO users (email,password,name) VALUES (?,?,?)",
        (email, hashed, name or email.split("@")[0]),
    )
    db.commit()
    user = db.execute("SELECT id,role,token_version FROM users WHERE email=?", (email,)).fetchone()
    token = make_token(user["id"], user["role"], user["token_version"] or 0)
    user_id = user["id"]
    db.close()

    audit_user_register(user_id, email)

    return jsonify({
        "token": token,
        "user": {"id": user_id, "email": email, "role": user["role"]}
    }), 201


@auth_bp.route("/register/status", methods=["GET"])
def register_status():
    """GET /api/auth/register/status — 公开：返回公开注册是否开放。

    供登录/注册页决定「注册」入口是否展示（仅暴露一个布尔值，不泄露其他信息）。
    """
    from routes.settings import _get_setting
    db = get_db()
    open_flag = _get_setting(db, 'allow_public_register', 'false') == 'true'
    db.close()
    return jsonify({"open": open_flag})


@auth_bp.route("/users", methods=["POST"])
@admin_required
def create_user():
    """POST /api/auth/users — 管理员创建账号（邀请/开号）。

    仅管理员可调用。可指定角色与状态；默认 active。
    这是注册关闭后唯一的新增账号途径。
    """
    data = get_json_body()
    if not data:
        return jsonify({"error": "无效的请求数据"}), 400

    email = sanitize_string((data.get("email") or "")).lower()
    password = sanitize_string(data.get("password") or "")
    name = html.escape(sanitize_string(data.get("name") or ""))
    role = sanitize_string(data.get("role") or "viewer")
    status = sanitize_string(data.get("status") or "active")

    if not email or not password:
        return jsonify({"error": "邮箱和密码不能为空"}), 400
    if not validate_email(email):
        return jsonify({"error": "邮箱格式不正确"}), 400
    pw_error = _validate_password_strength(password)
    if pw_error:
        return jsonify({"error": pw_error}), 400
    valid_roles = get_all_roles()
    if role not in valid_roles:
        return jsonify({"error": "无效的角色", "valid_roles": valid_roles}), 400
    if status not in ("active", "disabled"):
        return jsonify({"error": "无效的状态，可选值: active, disabled"}), 400

    db = get_db()
    exists = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if exists:
        db.close()
        return jsonify({"error": "该邮箱已注册"}), 409

    hashed = hash_pw(password)
    db.execute(
        "INSERT INTO users (email, password, name, role, status) VALUES (?, ?, ?, ?, ?)",
        (email, hashed, name or email.split("@")[0], role, status),
    )
    db.commit()
    new_id = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    db.close()

    audit_user_create(request.current_user_id, new_id, email, role)

    return jsonify({
        "message": "用户创建成功",
        "user": {
            "id": new_id,
            "email": email,
            "name": name or email.split("@")[0],
            "role": role,
            "status": status,
        },
    }), 201


@auth_bp.route("/login", methods=["POST"])
@login_rate_limiter
def login():
    data = get_json_body()
    if not data:
        ip = request.remote_addr or "unknown"
        record_login_failure(ip)
        return jsonify({"error": "无效的请求数据"}), 400

    email = sanitize_string(data.get("email") or "").lower()
    password = data.get("password") or ""
    ip = request.remote_addr or "unknown"

    if not email or not password:
        record_login_failure(ip)
        return jsonify({"error": "请填写邮箱和密码"}), 400

    # H-04: 检查账户级锁定（数据库驱动，优于 IP 锁定）
    db = get_db()
    account_locked, acc_remaining = is_account_locked(db, email)
    if account_locked:
        db.close()
        return jsonify({
            "error": "login_failed",
            "message": "邮箱或密码错误",
        }), 429

    # 检查 IP 是否被锁定
    locked, remaining = is_login_locked(ip)
    if locked:
        db.close()
        # 记录安全事件
        audit_login_blocked(ip, f"剩余 {remaining}s")
        return jsonify({
            "error": "account_locked",
            "message": f"登录失败次数过多，请 {remaining} 秒后重试",
        }), 429

    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    if not user or not verify_pw(password, user["password"]):
        record_login_failure(ip)

        # H-04: 记录账户级登录失败
        account_now_locked = record_account_login_failure(db, email)
        db.commit()
        db.close()

        # 检查是否需要 IP 锁定
        locked_after, rem = is_login_locked(ip)
        if locked_after:
            audit_account_locked(ip, email)

        if account_now_locked:
            audit_account_locked(ip, email)

        return jsonify({"error": "邮箱或密码错误"}), 401

    # 登录成功
    record_login_success(ip)
    # H-04: 记录账户级登录成功
    record_account_login_success(db, user["id"])
    token = make_token(user["id"], user["role"], user["token_version"] or 0)

    # 密码升级检查：旧 SHA256 → 新 PBKDF2
    if needs_password_upgrade(user["password"]):
        new_hash = hash_pw(password)
        db.execute("UPDATE users SET password=? WHERE id=?", (new_hash, user["id"]))

    db.commit()

    user_info = {
        "id": user["id"],
        "email": user["email"],
        "name": user.get("name", "") if hasattr(user, "get") else user["name"] or "",
        "role": user["role"],
    }
    # 安全加固：若账户仍在使用默认口令，前端应强制其修改
    must_change_pwd = bool(verify_pw("admin123", user["password"]))
    db.close()

    # 审计日志
    audit_login_success(user["id"], email)

    return jsonify({
        "token": token,
        "user": user_info,
        "must_change_pwd": must_change_pwd,
    })


@auth_bp.route("/me", methods=["GET"])
@login_required
def me():
    db = get_db()
    # 取 password 仅用于服务端判定是否仍为默认口令，绝不回传客户端
    user = db.execute(
        "SELECT id,email,name,role,created_at,password FROM users WHERE id=?",
        (request.current_user_id,),
    ).fetchone()
    db.close()
    if not user:
        return jsonify({"error": "用户不存在"}), 404
    data = dict(user)
    data.pop("password", None)
    # 服务端权威判定：强制改密标记以数据库真实状态为准，避免前端残留粘性标记反复弹窗
    data["must_change_pwd"] = bool(verify_pw("admin123", user["password"]))
    return jsonify(data)


@auth_bp.route("/users", methods=["GET"])
@login_required
def list_users():
    """GET /api/auth/users — 用户列表。
    管理员获取完整信息；普通用户仅获取 id/email/name/role 用于指派下拉。
    """
    db = get_db()
    is_admin = request.current_user_role == "admin"

    if is_admin:
        rows = db.execute("""
            SELECT id, email, name, role, status,
                   created_at, last_login, login_fail_count, locked_until
            FROM users ORDER BY created_at DESC
        """).fetchall()
    else:
        rows = db.execute(
            "SELECT id, email, name, role FROM users WHERE status='active' ORDER BY name"
        ).fetchall()

    db.close()
    users = []
    for r in rows:
        user = dict(r)
        if is_admin:
            # 解析锁定状态
            user["is_locked"] = bool(user.get("locked_until") and user["locked_until"] > "")
        users.append(user)
    return jsonify(users)


@auth_bp.route("/users/<int:user_id>", methods=["PATCH"])
@admin_required
def update_user(user_id: int):
    """PATCH /api/auth/users/:id — 管理员修改用户信息（角色/状态/姓名）。"""
    data = get_json_body()
    if not data:
        return jsonify({"error": "无效的请求数据"}), 400

    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not target:
        db.close()
        return jsonify({"error": "用户不存在"}), 404

    # 收集要更新的字段
    updates = {}
    audit_detail_parts = []

    # 角色变更
    new_role = sanitize_string(data.get("role") or "")
    if new_role and new_role != target["role"]:
        from routes.auth import get_all_roles
        if new_role not in get_all_roles():
            db.close()
            return jsonify({"error": "无效的角色", "valid_roles": get_all_roles()}), 400
        updates["role"] = new_role
        audit_detail_parts.append(f"角色 {target['role']} → {new_role}")
        audit_role_change(request.current_user_id, user_id, target["email"], new_role)

    # 状态变更
    new_status = sanitize_string(data.get("status") or "")
    if new_status and new_status != target["status"]:
        if new_status not in ("active", "disabled"):
            db.close()
            return jsonify({"error": "无效的状态，可选值: active, disabled"}), 400
        # 安全护栏：禁止管理员禁用自己当前登录的账号，避免自锁导致系统无人可管
        if new_status == "disabled" and user_id == request.current_user_id:
            db.close()
            return jsonify({"error": "不能禁用当前登录的管理员账号", "message": "如需停用，请使用其他管理员账号操作"}), 400
        updates["status"] = new_status
        audit_detail_parts.append(f"状态 {target['status']} → {new_status}")
        audit_user_status_change(request.current_user_id, user_id, target["email"], new_status)
        # 禁用用户时自动解锁 + 吊销所有 Token
        if new_status == "disabled":
            if target["locked_until"]:
                updates["locked_until"] = ""
            # M-01: 吊销所有现有 Token
            db.execute("UPDATE users SET token_version = token_version + 1 WHERE id=?", (user_id,))

    # 姓名变更
    new_name = html.escape(sanitize_string(data.get("name") or ""))
    if new_name and new_name != target["name"]:
        updates["name"] = new_name
        audit_detail_parts.append(f"姓名 {target['name']} → {new_name}")

    if not updates:
        db.close()
        return jsonify({"message": "没有需要更新的字段"}), 200

    # 构造 SQL
    set_clause = ", ".join(f"{k}=?" for k in updates)
    values = list(updates.values()) + [user_id]
    db.execute(f"UPDATE users SET {set_clause} WHERE id=?", values)
    db.commit()

    # 查询更新后的用户
    updated = db.execute(
        "SELECT id, email, name, role, status, created_at, last_login, login_fail_count, locked_until FROM users WHERE id=?",
        (user_id,),
    ).fetchone()
    db.close()

    return jsonify({
        "message": "用户信息更新成功",
        "user": dict(updated),
        "changes": audit_detail_parts,
    })


@auth_bp.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id: int):
    """DELETE /api/auth/users/:id — 管理员删除用户。"""
    # 不能删除自己
    if user_id == request.current_user_id:
        return jsonify({"error": "不能删除自己"}), 400

    db = get_db()
    target = db.execute("SELECT id, email, name FROM users WHERE id=?", (user_id,)).fetchone()
    if not target:
        db.close()
        return jsonify({"error": "用户不存在"}), 404

    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    db.close()

    audit_user_delete(request.current_user_id, user_id, target["email"])

    return jsonify({
        "message": f"用户 {target['email']} 已删除",
        "user_id": user_id,
    })


@auth_bp.route("/users/<int:user_id>/unlock", methods=["POST"])
@admin_required
def unlock_user(user_id: int):
    """POST /api/auth/users/:id/unlock — 管理员解锁用户账户。"""
    db = get_db()
    target = db.execute("SELECT id, email, locked_until FROM users WHERE id=?", (user_id,)).fetchone()
    if not target:
        db.close()
        return jsonify({"error": "用户不存在"}), 404

    if not target["locked_until"]:
        db.close()
        return jsonify({"message": "该用户未被锁定"}), 200

    db.execute(
        "UPDATE users SET locked_until='', login_fail_count=0 WHERE id=?",
        (user_id,),
    )
    db.commit()
    db.close()

    audit_user_unlock(request.current_user_id, user_id, target["email"])

    return jsonify({
        "message": f"用户 {target['email']} 已解锁",
        "user_id": user_id,
    })


@auth_bp.route("/roles", methods=["GET"])
@login_required
def list_roles():
    """GET /api/auth/roles — 获取所有可用角色及其权限。"""
    from routes.auth import ROLE_PERMISSIONS, get_role_permissions

    result = []
    for role_name in get_all_roles():
        perms = get_role_permissions(role_name)
        result.append({
            "name": role_name,
            "permissions": perms,
            "permission_count": len(perms),
        })
    return jsonify(result)


@auth_bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    """POST /api/auth/change-password — 当前用户修改自己的密码。

    Body: {"old_password": "...", "new_password": "..."}
    需要验证旧密码。
    """
    data = get_json_body()
    if not data:
        return jsonify({"error": "无效的请求数据"}), 400

    old_password = data.get("old_password") or ""
    new_password = data.get("new_password") or ""

    if not old_password or not new_password:
        return jsonify({"error": "旧密码和新密码不能为空"}), 400
    # M-02: 密码强度校验
    pw_error = _validate_password_strength(new_password)
    if pw_error:
        return jsonify({"error": pw_error}), 400
    if old_password == new_password:
        return jsonify({"error": "新密码不能与旧密码相同"}), 400

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id=?", (request.current_user_id,)
    ).fetchone()

    if not user:
        db.close()
        return jsonify({"error": "用户不存在"}), 404

    # 验证旧密码
    if not verify_pw(old_password, user["password"]):
        db.close()
        return jsonify({"error": "旧密码不正确"}), 403

    # 更新密码 + 吊销所有 Token（含当前会话）
    # 为避免改密后当前 JWT 失效导致前端会话卡死，这里直接签发新 token 一并返回
    new_hash = hash_pw(new_password)
    new_version = (user["token_version"] or 0) + 1
    db.execute(
        "UPDATE users SET password=?, token_version=? WHERE id=?",
        (new_hash, new_version, user["id"]),
    )
    db.commit()

    new_token = make_token(user["id"], user["role"], new_version)

    audit_change_password(request.current_user_id, user["email"])

    db.close()
    return jsonify({"message": "密码修改成功", "token": new_token}), 200


@auth_bp.route("/users/<int:user_id>/role", methods=["PATCH"])
@admin_required
def update_user_role(user_id: int):
    """PATCH /api/auth/users/:id/role — 管理员修改用户角色。"""
    data = get_json_body()
    if not data:
        return jsonify({"error": "无效的请求数据"}), 400

    new_role = sanitize_string(data.get("role") or "")
    valid_roles = get_all_roles()

    if new_role not in valid_roles:
        return jsonify({
            "error": "invalid_role",
            "message": f"无效的角色，可选值: {', '.join(valid_roles)}",
        }), 400

    db = get_db()
    target = db.execute("SELECT id,email,name,role FROM users WHERE id=?", (user_id,)).fetchone()
    if not target:
        db.close()
        return jsonify({"error": "用户不存在"}), 404

    old_role = target["role"]
    db.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
    db.commit()
    db.close()

    audit_role_change(request.current_user_id, user_id, target["email"], new_role)

    return jsonify({
        "message": "角色更新成功",
        "user_id": user_id,
        "old_role": old_role,
        "new_role": new_role,
    })


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """注销当前用户 — 递增 token_version 使所有活跃 token 失效。"""
    db = get_db()
    db.execute(
        "UPDATE users SET token_version = token_version + 1 WHERE id = ?",
        (request.current_user_id,)
    )
    db.commit()
    db.close()
    return jsonify({"message": "注销成功，令牌已失效"}), 200
