"""
哨兵应用安全平台 — 全局配置
修改此文件即可自定义平台行为，无需改动代码。
"""
import logging
logger = logging.getLogger(__name__)
import os
import secrets

# Load .env file if available (python-dotenv)
try:
    from dotenv import load_dotenv
    _env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.isfile(_env_file):
        load_dotenv(_env_file)
except ImportError:
    pass


# ============================================================
# 数据库
# ============================================================
DATABASE_PATH = os.environ.get(
    "SENTINEL_DB_PATH",
    os.path.join(os.path.dirname(__file__), "sentinel.db")
)
logger.info(f"[CONFIG] DATABASE_PATH = {DATABASE_PATH}")


# ============================================================
# JWT 认证
# ============================================================
# 优先级: 环境变量 > 持久化密钥文件 > 自动生成并持久化
# 生产环境请务必设置 SENTINEL_JWT_SECRET 环境变量

def _load_jwt_secret() -> str:
    """加载或生成 JWT 密钥，确保重启后一致。
    1. 环境变量 SENTINEL_JWT_SECRET（最高优先级）
    2. backend/.jwt_secret 持久化文件
    3. 自动生成随机密钥并写入 .jwt_secret
    """
    env_secret = os.environ.get("SENTINEL_JWT_SECRET", "")
    if env_secret:
        return env_secret

    secret_file = os.path.join(os.path.dirname(__file__), ".jwt_secret")
    try:
        if os.path.isfile(secret_file):
            with open(secret_file, "r") as f:
                saved = f.read().strip()
            if len(saved) >= 32:
                return saved
    except OSError:
        pass

    # 自动生成强随机密钥
    generated = secrets.token_hex(64)
    try:
        with open(secret_file, "w") as f:
            f.write(generated + "\n")
        # 仅文件所有者可读写（Unix/Windows 均适用）
        os.chmod(secret_file, 0o600)
        logger.info(f"[Sentinel] 已生成 JWT 密钥并持久化到 {secret_file}")
    except OSError:
        logger.warning("[Sentinel] 警告: 无法持久化 JWT 密钥，重启后 Token 将失效")
    return generated

JWT_SECRET = _load_jwt_secret()
JWT_ALG = "HS256"
JWT_EXP_HOURS = 24

# ============================================================
# SMTP 邮件通知
# ============================================================
SMTP_CONFIG = {
    "enabled": os.environ.get("SENTINEL_SMTP_ENABLED", "false").lower() == "true",
    "host": os.environ.get("SENTINEL_SMTP_HOST", "smtp.example.com"),
    "port": int(os.environ.get("SENTINEL_SMTP_PORT", "587")),
    "username": os.environ.get("SENTINEL_SMTP_USER", "sentinel@company.com"),
    "password": os.environ.get("SENTINEL_SMTP_PASS", ""),
    "use_tls": True,
    "from_addr": os.environ.get("SENTINEL_SMTP_FROM", "sentinel@company.com"),
    "from_name": "哨兵安全平台",
    "recipients": os.environ.get("SENTINEL_ALERT_RECIPIENTS", "").split(",")
    if os.environ.get("SENTINEL_ALERT_RECIPIENTS") else [],
    "alert_on": ["critical", "high"],   # 触发告警的漏洞级别
    "daily_digest": True,
    "base_url": os.environ.get("SENTINEL_BASE_URL", "http://localhost:5000"),
}

# ============================================================
# 工具集成 — 运行模式
# ============================================================
SCANNER_MODE = os.environ.get("SENTINEL_SCANNER_MODE", "real")
# 可选值: "simulated" (模拟) / "real" (调用真实 CLI)

# ============================================================
# AI 集成 (OpenAI 兼容 API / Ollama 本地模型)
# ============================================================

# 纯 env 驱动，不做任何启动时网络探测（避免超时卡死）
_AI_PROVIDER_ENV = os.environ.get("SENTINEL_AI_PROVIDER", "").lower()
_AI_HAS_KEY = bool(os.environ.get("SENTINEL_AI_API_KEY", ""))

AI_ENABLED = _AI_HAS_KEY or _AI_PROVIDER_ENV in ("ollama", "local")
AI_CONFIG = {
    "enabled": AI_ENABLED,
    "api_key": os.environ.get("SENTINEL_AI_API_KEY", "ollama"),
    "api_base": os.environ.get(
        "SENTINEL_AI_BASE",
        "https://api.openai.com/v1"
    ),
    "model": os.environ.get("SENTINEL_AI_MODEL", "gpt-4o-mini"),
}

# ============================================================
# Flask 服务
# ============================================================
FLASK_HOST = os.environ.get("SENTINEL_HOST", "0.0.0.0")
FLASK_PORT = int(os.environ.get("SENTINEL_PORT", "5000"))
FLASK_DEBUG = os.environ.get("SENTINEL_DEBUG", "false").lower() == "true"

# ============================================================
# 前端静态文件路径 (生产模式 Flask 直接 serve React build)
# ============================================================
FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
