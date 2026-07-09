# ─── Security Middleware ───
"""
Phase 1: API 安全中间件
- 安全响应头 (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- 全局限流 (基于 IP 的滑动窗口)
- 登录暴力破解防护
- 请求体大小限制
- 输入校验辅助函数
"""

import time
import functools
import hashlib
from collections import defaultdict
from flask import request, jsonify, g

# ═══════════════════════════════════════════════════════
#  配置
# ═══════════════════════════════════════════════════════

# 全局限流: 每个IP每分钟最多请求数
RATE_LIMIT_PER_MINUTE = 120

# 登录限流: 每个IP每分钟最多登录尝试次数
LOGIN_RATE_LIMIT = 5

# 登录失败锁定: 连续失败 N 次后锁定 M 秒
LOGIN_FAIL_LOCK_COUNT = 5
LOGIN_FAIL_LOCK_SECONDS = 300  # 5 分钟

# 账户级锁定阈值（与 IP 锁定共享计数）
ACCOUNT_LOCK_COUNT = 5
ACCOUNT_LOCK_SECONDS = 900  # 15 分钟

# 请求体最大大小 (KB)
MAX_REQUEST_BODY_KB = 5120  # 5MB

# ═══════════════════════════════════════════════════════
#  内存限流器 (生产环境应替换为 Redis)
# ═══════════════════════════════════════════════════════

# {ip: [(timestamp, endpoint), ...]}
_request_log: dict[str, list] = defaultdict(list)

# {ip: [fail_timestamp_1, fail_timestamp_2, ...]}
_login_failures: dict[str, list] = defaultdict(list)


# ═══════════════════════════════════════════════════════
#  H-04: 账户级锁定检查（数据库驱动）
# ═══════════════════════════════════════════════════════

def is_account_locked(db, email: str) -> tuple[bool, int]:
    """
    检查账户是否被数据库级锁定。（调用方负责 db.commit / db.close）
    返回: (is_locked, remaining_seconds)
    """
    row = db.execute(
        "SELECT locked_until, login_fail_count FROM users WHERE email=? AND status='active'",
        (email,),
    ).fetchone()
    if not row:
        return False, 0

    locked_until = row["locked_until"]
    if not locked_until:
        return False, 0

    try:
        from datetime import datetime as dt
        lock_time = dt.strptime(locked_until[:19], "%Y-%m-%d %H:%M:%S")
        remaining = int((lock_time - dt.now()).total_seconds())
        if remaining > 0:
            return True, remaining
    except (ValueError, TypeError):
        pass

    # 锁定时间已过，自动清除
    db.execute("UPDATE users SET locked_until='', login_fail_count=0 WHERE email=?", (email,))
    return False, 0


def record_account_login_failure(db, email: str) -> bool:
    """
    记录账户级登录失败。调用方负责 db.commit / db.close。
    返回 True 表示账户已被锁定。
    """
    row = db.execute(
        "SELECT id, login_fail_count FROM users WHERE email=?", (email,)
    ).fetchone()
    if not row:
        return False

    new_count = (row["login_fail_count"] or 0) + 1
    if new_count >= ACCOUNT_LOCK_COUNT:
        from datetime import datetime as dt, timedelta
        lock_until = (dt.now() + timedelta(seconds=ACCOUNT_LOCK_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
        db.execute(
            "UPDATE users SET login_fail_count=?, locked_until=? WHERE id=?",
            (new_count, lock_until, row["id"]),
        )
        return True

    db.execute("UPDATE users SET login_fail_count=? WHERE id=?", (new_count, row["id"]))
    return False


def record_account_login_success(db, user_id: int) -> None:
    """登录成功后清除账户级失败计数并更新最后登录时间。调用方负责 db.commit / db.close。"""
    from datetime import datetime as dt
    now = dt.now().strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        "UPDATE users SET login_fail_count=0, locked_until='', last_login=? WHERE id=?",
        (now, user_id),
    )


def _cleanup_old_entries(log: list, window_seconds: int) -> None:
    """清理窗口外的旧记录。"""
    cutoff = time.time() - window_seconds
    while log and log[0] < cutoff:
        log.pop(0)


def _check_rate_limit(ip: str, limit: int, window_seconds: int = 60) -> bool:
    """检查是否超过限流阈值。返回 True 表示允许，False 表示超限。"""
    entries = _request_log[ip]
    _cleanup_old_entries(entries, window_seconds)
    if len(entries) >= limit:
        return False
    entries.append(time.time())
    return True


def is_login_locked(ip: str) -> tuple[bool, int]:
    """
    检查 IP 是否被登录锁定。
    返回: (is_locked, remaining_seconds)
    """
    failures = _login_failures[ip]
    _cleanup_old_failures(failures)
    if len(failures) >= LOGIN_FAIL_LOCK_COUNT:
        # 计算最早一次失败后的剩余锁定时间
        earliest = failures[0]
        elapsed = time.time() - earliest
        remaining = LOGIN_FAIL_LOCK_SECONDS - int(elapsed)
        if remaining > 0:
            return True, remaining
        # 锁定时间已过，清除记录
        failures.clear()
    return False, 0


def record_login_failure(ip: str) -> None:
    """记录一次登录失败。"""
    _login_failures[ip].append(time.time())


def record_login_success(ip: str) -> None:
    """登录成功后清除该 IP 的失败记录。"""
    if ip in _login_failures:
        del _login_failures[ip]


def _cleanup_old_failures(failures: list) -> None:
    """清理超出锁定窗口的失败记录。"""
    cutoff = time.time() - LOGIN_FAIL_LOCK_SECONDS - 10  # 多留10秒余量
    while failures and failures[0] < cutoff:
        failures.pop(0)


# ═══════════════════════════════════════════════════════
#  Flask 中间件 / 装饰器
# ═══════════════════════════════════════════════════════

def security_headers(response):
    """after_request 钩子：注入安全响应头。"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    # 开发环境不设 HSTS（避免 localhost 证书问题）
    # 生产环境取消下面注释:
    # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # 移除服务器指纹
    response.headers["Server"] = ""
    return response


def rate_limiter(limit: int = RATE_LIMIT_PER_MINUTE, window: int = 60):
    """
    通用限流装饰器。
    用法: @rate_limiter(30) — 每分钟最多30次
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*a, **kw):
            ip = request.remote_addr or "unknown"
            if not _check_rate_limit(ip, limit, window):
                return jsonify({
                    "error": "rate_limit_exceeded",
                    "message": f"请求过于频繁，请 {window} 秒后重试",
                }), 429
            return f(*a, **kw)
        return wrapper
    return decorator


def login_rate_limiter(f):
    """登录专用限流 + 暴力破解防护。"""
    @functools.wraps(f)
    def wrapper(*a, **kw):
        ip = request.remote_addr or "unknown"

        # 检查是否被锁定
        locked, remaining = is_login_locked(ip)
        if locked:
            return jsonify({
                "error": "account_locked",
                "message": f"登录失败次数过多，请 {remaining} 秒后重试",
            }), 429

        # 检查登录频率限制
        if not _check_rate_limit(ip, LOGIN_RATE_LIMIT, 60):
            return jsonify({
                "error": "rate_limit_exceeded",
                "message": "登录请求过于频繁，请稍后重试",
            }), 429

        result = f(*a, **kw)

        # 根据结果记录成功/失败
        # 注意：这里需要检查响应状态码来判断登录是否成功
        # 由于 result 可能是 response tuple，需要特殊处理
        return result
    return wrapper


# ═══════════════════════════════════════════════════════
#  输入校验辅助函数
# ═══════════════════════════════════════════════════════

def get_json_body(max_kb: int = MAX_REQUEST_BODY_KB) -> dict | None:
    """
    安全地获取并校验 JSON 请求体。
    返回 dict 或 None（解析失败时）。
    """
    content_length = request.content_length or 0
    if content_length > max_kb * 1024:
        return None

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None
    return data


def sanitize_string(value: str, max_length: int = 10000) -> str:
    """
    基本字符串清理：
    - 截断到最大长度
    - 去除首尾空白
    - 替换 null 字节
    """
    if not isinstance(value, str):
        return str(value)[:max_length]
    value = value.replace("\x00", "").strip()
    return value[:max_length]


def validate_email(email: str) -> bool:
    """基础邮箱格式校验。"""
    import re
    email = sanitize_string(email).lower()
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_severity(severity: str) -> bool:
    """校验漏洞严重度值。"""
    return severity in ("critical", "high", "medium", "low", "info")


def validate_project_type(ptype: str) -> bool:
    """校验项目类型。"""
    return ptype in ("web", "api", "mobile", "desktop", "microservice", "library")


def validate_tool_type(ttype: str) -> bool:
    """校验扫描工具类型。"""
    return ttype in ("SAST", "DAST", "SCA", "SECRET", "IAC", "CONTAINER")
