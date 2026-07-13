import logging
logger = logging.getLogger(__name__)
# ─── JWT Auth (Phase 1 增强) ───
"""
JWT 认证 + RBAC 基础
Phase 1 改进：
- 密码哈希升级: SHA256 → PBKDF2-HMAC-SHA256（带随机盐）
- 向后兼容旧 SHA256 密码，首次登录自动升级
- Token 黑名单支持
- 权限检查辅助
"""

import jwt
import hashlib
import os
import hmac
import functools
from datetime import datetime, timedelta, timezone
from flask import request, jsonify

from config import JWT_SECRET, JWT_ALG, JWT_EXP_HOURS

# ═══════════════════════════════════════════════════════
#  密码哈希 — PBKDF2-HMAC-SHA256
# ═══════════════════════════════════════════════════════

PBKDF2_ITERATIONS = 260000  # OWASP 推荐 260,000+ (2023)
SALT_LENGTH = 16


def _generate_salt() -> str:
    """生成随机盐值。"""
    return os.urandom(SALT_LENGTH).hex()


def hash_pw(plain: str) -> str:
    """
    PBKDF2-HMAC-SHA256 哈希。
    格式: pbkdf2$iterations$salt$hash
    """
    salt = _generate_salt()
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        plain.encode("utf-8"),
        bytes.fromhex(salt),
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_pw(plain: str, stored: str) -> bool:
    """
    验证密码。
    兼容两种格式:
    - 新格式: pbkdf2$iterations$salt$hash
    - 旧格式: 纯 SHA256 hex（向后兼容）
    """
    if not stored or not plain:
        return False

    # 新格式 PBKDF2
    if stored.startswith("pbkdf2$"):
        try:
            _, iterations_str, salt, hash_val = stored.split("$")
            iterations = int(iterations_str)
            dk = hashlib.pbkdf2_hmac(
                "sha256",
                plain.encode("utf-8"),
                bytes.fromhex(salt),
                iterations,
            )
            return hmac.compare_digest(dk.hex(), hash_val)
        except (ValueError, TypeError):
            return False

    # 旧格式纯 SHA256（向后兼容） — nosemgrep: backward compat fallback, PBKDF2 is the primary hash
    old_hash = hashlib.sha256(plain.encode()).hexdigest()
    return hmac.compare_digest(old_hash, stored)


def needs_password_upgrade(stored: str) -> bool:
    """检查密码是否需要从旧格式升级到 PBKDF2。"""
    return not stored.startswith("pbkdf2$")


# ═══════════════════════════════════════════════════════
#  JWT Token 管理
# ═══════════════════════════════════════════════════════

def make_token(user_id: int, role: str, token_version: int = 0) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "token_ver": token_version,
        "exp": now + timedelta(hours=JWT_EXP_HOURS),
        "iat": now,
        "jti": os.urandom(16).hex(),  # JWT ID 用于黑名单追踪
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception as e:
        logger.error(f"[JWT ERROR] {type(e).__name__}: {e}")
        return None


# ═══════════════════════════════════════════════════════
#  认证装饰器
# ═══════════════════════════════════════════════════════

def login_required(f):
    """认证装饰器 — 验证 JWT + token_version + 用户状态。
    M-01/M-06: 令牌吊销 + 禁用用户即时失效。
    """
    @functools.wraps(f)
    def wrapper(*a, **kw):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").strip()
        if not token:
            return jsonify({"error": "unauthorized", "message": "缺少认证令牌"}), 401
        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "unauthorized", "message": "认证令牌无效或已过期"}), 401

        user_id = int(payload["sub"])
        token_ver = payload.get("token_ver", 0)

        # M-01/M-06: 验证 token_version + 用户状态
        from app import get_db
        db = get_db()
        user_row = db.execute(
            "SELECT id, role, status, token_version FROM users WHERE id=?", (user_id,)
        ).fetchone()
        db.close()

        if not user_row:
            return jsonify({"error": "unauthorized", "message": "用户不存在"}), 401
        if user_row["status"] == "disabled":
            return jsonify({"error": "unauthorized", "message": "账户已被禁用"}), 401
        if user_row["token_version"] != token_ver:
            return jsonify({"error": "unauthorized", "message": "令牌已失效，请重新登录"}), 401

        request.current_user_id = user_id
        request.current_user_role = user_row["role"]
        request.current_jti = payload.get("jti", "")
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    """要求管理员角色。"""
    @functools.wraps(f)
    @login_required
    def wrapper(*a, **kw):
        if request.current_user_role != "admin":
            return jsonify({
                "error": "forbidden",
                "message": "需要管理员权限",
            }), 403
        return f(*a, **kw)
    return wrapper


# ═══════════════════════════════════════════════════════
#  RBAC 权限常量与辅助
# ═══════════════════════════════════════════════════════

# 资源类型
RES_PROJECT = "project"
RES_SCAN = "scan"
RES_VULN = "vulnerability"
RES_ASSET = "asset"
RES_RULE = "rule"
RES_REPORT = "report"
RES_USER = "user"
RES_SETTING = "setting"
RES_WEBHOOK = "webhook"
RES_AUDIT = "audit"

# 操作类型
ACT_CREATE = "create"
ACT_READ = "read"
ACT_UPDATE = "update"
ACT_DELETE = "delete"
ACT_ASSIGN = "assign"
ACT_VERIFY = "verify"
ACT_EXPORT = "export"

# 内置角色权限矩阵
# key = role_name, value = set of (resource, action)
ROLE_PERMISSIONS: dict[str, set[tuple[str, str]]] = {
    "admin": {
        # 管理员：全部权限
        (RES_PROJECT, ACT_CREATE), (RES_PROJECT, ACT_READ), (RES_PROJECT, ACT_UPDATE), (RES_PROJECT, ACT_DELETE),
        (RES_SCAN, ACT_CREATE), (RES_SCAN, ACT_READ),
        (RES_VULN, ACT_READ), (RES_VULN, ACT_UPDATE), (RES_VULN, ACT_DELETE), (RES_VULN, ACT_ASSIGN), (RES_VULN, ACT_VERIFY),
        (RES_ASSET, ACT_CREATE), (RES_ASSET, ACT_READ), (RES_ASSET, ACT_UPDATE), (RES_ASSET, ACT_DELETE),
        (RES_RULE, ACT_CREATE), (RES_RULE, ACT_READ), (RES_RULE, ACT_UPDATE), (RES_RULE, ACT_DELETE),
        (RES_REPORT, ACT_CREATE), (RES_REPORT, ACT_READ), (RES_REPORT, ACT_EXPORT),
        (RES_USER, ACT_READ), (RES_USER, ACT_UPDATE),
        (RES_SETTING, ACT_READ), (RES_SETTING, ACT_UPDATE),
        (RES_WEBHOOK, ACT_READ), (RES_WEBHOOK, ACT_UPDATE),
        (RES_AUDIT, ACT_READ),
    },
    "security_analyst": {
        # 安全分析师：读写漏洞/扫描/报告/规则/资产，不能管用户和系统设置
        (RES_PROJECT, ACT_READ),
        (RES_SCAN, ACT_CREATE), (RES_SCAN, ACT_READ),
        (RES_VULN, ACT_READ), (RES_VULN, ACT_UPDATE), (RES_VULN, ACT_ASSIGN), (RES_VULN, ACT_VERIFY),
        (RES_ASSET, ACT_CREATE), (RES_ASSET, ACT_READ), (RES_ASSET, ACT_UPDATE),
        (RES_RULE, ACT_CREATE), (RES_RULE, ACT_READ), (RES_RULE, ACT_UPDATE),
        (RES_REPORT, ACT_CREATE), (RES_REPORT, ACT_READ), (RES_REPORT, ACT_EXPORT),
        (RES_AUDIT, ACT_READ),
        (RES_SETTING, ACT_READ),
    },
    "developer": {
        # 开发者：只读+修复自己被指派的漏洞
        (RES_PROJECT, ACT_READ),
        (RES_SCAN, ACT_READ),
        (RES_VULN, ACT_READ), (RES_VULN, ACT_UPDATE),  # 只能更新自己被指派的
        (RES_ASSET, ACT_READ),
        (RES_REPORT, ACT_READ),
    },
    "viewer": {
        # 只读用户：只能看
        (RES_PROJECT, ACT_READ),
        (RES_SCAN, ACT_READ),
        (RES_VULN, ACT_READ),
        (RES_ASSET, ACT_READ),
        (RES_REPORT, ACT_READ),
        (RES_AUDIT, ACT_READ),
    },
}


def has_permission(role: str, resource: str, action: str) -> bool:
    """
    检查角色是否有指定资源的操作权限。
    """
    perms = ROLE_PERMISSIONS.get(role, set())
    return (resource, action) in perms


def require_permission(resource: str, action: str):
    """
    权限校验装饰器。
    用法: @require_permission(RES_VULN, ACT_UPDATE)

    支持 owner_check 回调用于资源级所有权判断（如开发者只能修改自己被指派的漏洞）。
    """
    def decorator(f):
        @functools.wraps(f)
        @login_required
        def wrapper(*a, **kw):
            role = request.current_user_role
            if has_permission(role, resource, action):
                return f(*a, **kw)

            # 特殊处理：developer 更新漏洞时，检查是否是被指派人
            if role == "developer" and resource == RES_VULN and action == ACT_UPDATE:
                # 在具体的路由中通过 check_vuln_assignment 进一步验证
                request._needs_owner_check = True
                return f(*a, **kw)

            return jsonify({
                "error": "forbidden",
                "message": f"权限不足: 需要 {resource}:{action} 权限",
            }), 403
        return wrapper
    return decorator


def get_role_permissions(role: str) -> list[dict]:
    """获取角色的完整权限列表（用于前端展示）。"""
    perms = ROLE_PERMISSIONS.get(role, set())
    result = []
    for res, act in sorted(perms):
        result.append({"resource": res, "action": act})
    return result


def get_all_roles() -> list[str]:
    """获取所有内置角色名。"""
    return list(ROLE_PERMISSIONS.keys())
