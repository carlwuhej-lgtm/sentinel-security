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
import os
import re
import secrets
import sqlite3
import threading
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
#  持久化限流器 (SQLite WAL 文件，重启/多 worker 不丢状态)
#  表: rl_store(key, ip, ts) — key 区分全局限流/登录限流/登录锁定
# ═══════════════════════════════════════════════════════

_RL_DB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ratelimit.db"))
_rl_write_lock = threading.Lock()
# 超过该时长的记录统一清理（覆盖所有限流窗口，含账户锁定 900s）
RL_PRUNE_SECONDS = 3600


def _rl_conn():
    conn = sqlite3.connect(_RL_DB, timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS rl_store (
        key TEXT NOT NULL,
        ip  TEXT NOT NULL,
        ts  REAL NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rl_key_ip ON rl_store(key, ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rl_ts ON rl_store(ts)")
    return conn


def _rl_prune(conn):
    """清理超过保留期的旧记录（不影响任何活跃窗口）。"""
    cutoff = time.time() - RL_PRUNE_SECONDS
    conn.execute("DELETE FROM rl_store WHERE ts < ?", (cutoff,))


def _rl_count(key: str, ip: str, since_ts: float) -> int:
    conn = _rl_conn()
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM rl_store WHERE key=? AND ip=? AND ts>=?",
            (key, ip, since_ts),
        ).fetchone()[0]
    finally:
        conn.close()


def _rl_insert(key: str, ip: str, ts: float) -> None:
    conn = _rl_conn()
    try:
        conn.execute("INSERT INTO rl_store (key, ip, ts) VALUES (?,?,?)", (key, ip, ts))
        conn.commit()
    finally:
        conn.close()


def _rl_delete(key: str, ip: str) -> None:
    conn = _rl_conn()
    try:
        conn.execute("DELETE FROM rl_store WHERE key=? AND ip=?", (key, ip))
        conn.commit()
    finally:
        conn.close()


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


def _check_rate_limit(ip: str, limit: int, window_seconds: int = 60, key: str = "global") -> bool:
    """检查是否超过限流阈值。返回 True 表示允许，False 表示超限。

    状态持久化到 SQLite（ratelimit.db），重启服务、多 worker 进程间共享。
    """
    now = time.time()
    since = now - window_seconds
    with _rl_write_lock:
        conn = _rl_conn()
        try:
            _rl_prune(conn)
            conn.commit()
            if _rl_count(key, ip, since) >= limit:
                return False
            _rl_insert(key, ip, now)
            return True
        finally:
            conn.close()


def is_login_locked(ip: str) -> tuple[bool, int]:
    """
    检查 IP 是否被登录锁定（持久化状态）。
    返回: (is_locked, remaining_seconds)
    """
    now = time.time()
    since = now - LOGIN_FAIL_LOCK_SECONDS
    count = _rl_count("login_fail", ip, since)
    if count >= LOGIN_FAIL_LOCK_COUNT:
        # 取最早一次失败时间计算剩余锁定
        conn = _rl_conn()
        try:
            row = conn.execute(
                "SELECT ts FROM rl_store WHERE key='login_fail' AND ip=? AND ts>=? ORDER BY ts ASC LIMIT 1",
                (ip, since),
            ).fetchone()
        finally:
            conn.close()
        earliest = row[0] if row else now
        remaining = LOGIN_FAIL_LOCK_SECONDS - int(now - earliest)
        if remaining > 0:
            return True, remaining
        # 锁定已过期，清除该 IP 登录失败记录
        _rl_delete("login_fail", ip)
    return False, 0


def record_login_failure(ip: str) -> None:
    """记录一次登录失败（持久化）。"""
    _rl_insert("login_fail", ip, time.time())


def record_login_success(ip: str) -> None:
    """登录成功后清除该 IP 的失败记录（持久化）。"""
    _rl_delete("login_fail", ip)


# ═══════════════════════════════════════════════════════
#  Flask 中间件 / 装饰器
# ═══════════════════════════════════════════════════════

def security_headers(response):
    """after_request 钩子：注入安全响应头。

    nonce 优先复用视图层（serve_frontend）写入 g.csp_nonce 的值，保证 HTML 里
    <script nonce> 与 CSP 声明完全一致；无则现场生成。
    script-src 已移除 'unsafe-inline'，仅靠 nonce 放行内联脚本，关闭 XSS 口子。
    style-src 保留 'unsafe-inline'：React 通过 style 属性注入内联样式，该属性受
    style-src 约束，去掉会导致整站样式失效；样式不可执行脚本，风险可接受。
    HSTS 仅在 HTTPS 下被浏览器采纳，HTTP/localhost 会被忽略，不影响本地开发。
    """
    nonce = getattr(g, "csp_nonce", None) or secrets.token_hex(16)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
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

        # 检查登录频率限制（独立于全局限流，key 区分）
        if not _check_rate_limit(ip, LOGIN_RATE_LIMIT, 60, key="login_rate"):
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
