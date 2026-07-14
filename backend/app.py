import logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s', handlers=[logging.StreamHandler()])
# ─── Sentinel Security Backend ───
"""
哨兵应用安全平台 — Flask 主应用
一个命令启动全栈: python run.py

架构：
  /api/*      → REST API（认证、项目、扫描、工具、漏洞、仪表盘）
  /*          → React SPA 静态文件（生产模式）
              → 开发模式时由 Vite dev server 提供前端

功能模块：
  - JWT 认证鉴权
  - 项目 CRUD
  - 工具集成框架（Semgrep/Trivy/ZAP/Gitleaks/Dependency-Check/CodeQL）
  - 扫描编排 + 漏洞自动入库
  - 邮件告警通知（Critical/High 漏洞触发）
  - 仪表盘统计
"""

import os
import sqlite3
import sys
from flask import Flask, request, jsonify, send_from_directory

# 确保 integrations 和 notifications 可导入
sys.path.insert(0, os.path.dirname(__file__))

from flask_cors import CORS
from config import (
    DATABASE_PATH, JWT_SECRET, SMTP_CONFIG, SCANNER_MODE,
    FLASK_HOST, FLASK_PORT, FLASK_DEBUG, FRONTEND_DIST,
)
from services.cve_sync_service import init_cve_tables


# ═══════════════════════════════════════════════════════
#  数据库
# ═══════════════════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    # 切换 journal 模式可能与其他进程瞬时竞争而失败；默认即为 DELETE，
    # 失败不应阻断应用启动，故捕获后继续。
    try:
        conn.execute("PRAGMA journal_mode=DELETE")
    except sqlite3.OperationalError:
        pass
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT    UNIQUE NOT NULL,
            password    TEXT    NOT NULL,
            name        TEXT    NOT NULL DEFAULT '',
            role          TEXT    NOT NULL DEFAULT 'user',
            token_version INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS projects (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT    NOT NULL,
            repo_url      TEXT    DEFAULT '',
            language      TEXT    DEFAULT 'auto',
            project_type  TEXT    DEFAULT 'web',
            description   TEXT    DEFAULT '',
            created_at    TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS tools (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            tool_type   TEXT    NOT NULL,
            description TEXT    DEFAULT '',
            endpoint    TEXT    DEFAULT '',
            api_key     TEXT    DEFAULT '',
            enabled     INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS scan_tasks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id  INTEGER,
            tool_id     INTEGER,
            tool_type   TEXT    DEFAULT '',
            status      TEXT    NOT NULL DEFAULT 'pending',
            vuln_count  INTEGER DEFAULT 0,
            result_json TEXT    DEFAULT '',
            started_at  TEXT    DEFAULT '',
            finished_at TEXT    DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL,
            FOREIGN KEY (tool_id) REFERENCES tools(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER,
            cve_id      TEXT    DEFAULT '',
            title       TEXT    NOT NULL,
            severity    TEXT    NOT NULL DEFAULT 'medium',
            file_path   TEXT    DEFAULT '',
            line        INTEGER DEFAULT 0,
            source_tool TEXT    DEFAULT '',
            description TEXT    DEFAULT '',
            fix_suggestion TEXT DEFAULT '',
            status      TEXT    NOT NULL DEFAULT 'open',
            assigned_to INTEGER DEFAULT NULL,
            cvss_score  REAL    DEFAULT 0,
            cwe_id      TEXT    DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (scan_id) REFERENCES scan_tasks(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS contacts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            email       TEXT    NOT NULL,
            company     TEXT    DEFAULT '',
            phone       TEXT    DEFAULT '',
            message     TEXT    DEFAULT '',
            type        TEXT    NOT NULL DEFAULT 'contact',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS threat_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type  TEXT    NOT NULL,
            source_ip   TEXT    DEFAULT '',
            detail      TEXT    DEFAULT '',
            severity    TEXT    NOT NULL DEFAULT 'low',
            blocked     INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS email_config (
            id      INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL DEFAULT 0,
            host    TEXT    DEFAULT '',
            port    INTEGER DEFAULT 587,
            username TEXT   DEFAULT '',
            password TEXT   DEFAULT '',
            from_addr TEXT  DEFAULT '',
            recipients TEXT DEFAULT '',
            alert_on TEXT   DEFAULT '["critical","high"]',
            updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );
    """)
    conn.commit()

    # 默认管理员
    existing = cur.execute("SELECT id FROM users WHERE email=?", ("admin@sentinel.io",)).fetchone()
    if not existing:
        # nosemgrep: SHA256 replaced with PBKDF2 via hash_pw()
        from routes.auth import hash_pw
        pw = hash_pw("admin123")
        cur.execute("INSERT INTO users (email,password,name,role) VALUES (?,?,?,?)",
                    ("admin@sentinel.io", pw, "管理员", "admin"))
        conn.commit()

    # 默认安全工具
    if not cur.execute("SELECT id FROM tools LIMIT 1").fetchone():
        default_tools = [
            ("Semgrep", "SAST", "静态代码分析，支持 30+ 语言，可自定义规则", "", 1),
            ("Trivy", "SCA", "容器镜像、Git 仓库、文件系统漏洞扫描", "", 1),
            ("OWASP ZAP", "DAST", "动态应用安全测试，自动化爬虫与主动扫描", "http://localhost:8080", 0),
            ("Gitleaks", "SECRET", "检测代码仓库中的硬编码密钥和凭证", "", 1),
            ("Dependency-Check", "SCA", "OWASP 开源组件已知漏洞检测", "", 1),
            ("CodeQL", "SAST", "语义级代码分析，变体分析能力", "", 0),
        ]
        cur.executemany(
            "INSERT INTO tools (name, tool_type, description, endpoint, enabled) VALUES (?,?,?,?,?)",
            default_tools
        )
        conn.commit()

    # 初始化邮件配置表
    cur.execute("INSERT OR IGNORE INTO email_config (id) VALUES (1)")
    conn.commit()

    # ── Phase 2: Schema 迁移 (SLA / 审计) ──
    _migrate_phase2(conn)

    # ── Phase 3: Schema 迁移 (规则 / 资产 / 报告) ──
    _migrate_phase3(conn)

    # ── Phase 1: Schema 迁移 (安全增强) ──
    _migrate_phase1(conn)

    # ── Phase 4: Schema 迁移 (告警引擎 + IM 通知渠道) ──
    _migrate_phase4(conn)

    # ── Phase 5: Schema 迁移 (工单系统) ──
    _migrate_phase5(conn)

    # ── Phase 6: CVE 缓存表 ──
    init_cve_tables(conn)

    # ── Phase 7: 知识库 ──
    _migrate_phase7(conn)

    # ── Phase 8: 工具使用统计字段 ──
    _migrate_phase8(conn)

    conn.close()


def _warn_default_admin():
    """启动期安全检查：若默认管理员仍使用出厂口令 admin123，打印显著告警。"""
    try:
        from routes.auth import verify_pw
        _db_path = os.environ.get("SENTINEL_DB_PATH", DATABASE_PATH)
        conn = sqlite3.connect(_db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT password FROM users WHERE email=?", ("admin@sentinel.io",)).fetchone()
        conn.close()
        if row and verify_pw("admin123", row["password"]):
            msg = (
                "\n" + "=" * 64 +
                "\n  [SECURITY WARNING] Default admin 'admin@sentinel.io' still uses"
                "\n  the factory password 'admin123'! Change it immediately after"
                "\n  login, or anyone can take over the system."
                "\n" + "=" * 64 + "\n"
            )
            try:
                logger.info(msg)
            except UnicodeEncodeError:
                logger.info(msg.encode("ascii", "replace").decode("ascii"))
    except Exception as e:
        logger.error(f"[WARN] default admin password check failed: {e}")


def _migrate_phase2(conn):
    """安全升级：为 Phase 2 增加 SLA、审计日志、Webhook 配置等表/列。"""
    cur = conn.cursor()

    # vulnerabilities 表新增 SLA 字段
    try:
        cur.execute("ALTER TABLE vulnerabilities ADD COLUMN sla_due_date TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass  # 列已存在
    try:
        cur.execute("ALTER TABLE vulnerabilities ADD COLUMN sla_breached INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute("ALTER TABLE vulnerabilities ADD COLUMN assigned_by INTEGER DEFAULT NULL")
    except sqlite3.OperationalError:
        pass

    # 审计日志表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER DEFAULT NULL,
            user_email  TEXT    DEFAULT '',
            action      TEXT    NOT NULL,
            target_type TEXT    NOT NULL DEFAULT '',
            target_id   INTEGER DEFAULT 0,
            detail      TEXT    DEFAULT '',
            ip_address  TEXT    DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    # Webhook 配置表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS webhook_config (
            id      INTEGER PRIMARY KEY CHECK (id = 1),
            token   TEXT    NOT NULL DEFAULT '',
            gate_mode TEXT  NOT NULL DEFAULT 'block',
            gate_rules TEXT NOT NULL DEFAULT '{"critical":"block","high":"warn","medium":"pass","low":"pass"}',
            updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )
    """)
    cur.execute("INSERT OR IGNORE INTO webhook_config (id, token) VALUES (1, '')")
    # 为已有漏洞计算 SLA
    cur.execute("""
        UPDATE vulnerabilities SET sla_due_date =
            CASE severity
                WHEN 'critical' THEN datetime(created_at, '+1 day')
                WHEN 'high'     THEN datetime(created_at, '+7 days')
                WHEN 'medium'   THEN datetime(created_at, '+30 days')
                WHEN 'low'      THEN datetime(created_at, '+90 days')
                ELSE datetime(created_at, '+14 days')
            END
        WHERE sla_due_date = '' AND status = 'open'
    """)
    # 标记已超时的
    cur.execute("""
        UPDATE vulnerabilities SET sla_breached = 1
        WHERE sla_due_date != '' AND sla_due_date < datetime('now','localtime') AND status = 'open' AND sla_breached = 0
    """)

    conn.commit()


def _migrate_phase3(conn):
    """Phase 3: 规则管理 / 资产发现 / 报告导出"""
    cur = conn.cursor()

    # ── 1) 规则表 ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            rule_type   TEXT    NOT NULL DEFAULT 'custom_scan',
            category    TEXT    NOT NULL DEFAULT 'generic',
            pattern     TEXT    NOT NULL DEFAULT '',
            severity_filter TEXT NOT NULL DEFAULT '["critical","high","medium","low"]',
            description TEXT    DEFAULT '',
            enabled     INTEGER NOT NULL DEFAULT 1,
            scope       TEXT    NOT NULL DEFAULT 'global',
            project_id  INTEGER DEFAULT NULL,
            created_by  INTEGER DEFAULT NULL,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    # ── 2) 资产表 ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    NOT NULL,
            asset_type      TEXT    NOT NULL DEFAULT 'web_api',
            project_id      INTEGER DEFAULT NULL,
            tech_stack      TEXT    NOT NULL DEFAULT '[]',
            environment     TEXT    NOT NULL DEFAULT 'unknown',
            owner           TEXT    DEFAULT '',
            owner_email     TEXT    DEFAULT '',
            risk_score      REAL    DEFAULT 0,
            risk_level      TEXT    NOT NULL DEFAULT 'info',
            status          TEXT    NOT NULL DEFAULT 'active',
            last_scan_date  TEXT    DEFAULT '',
            last_vuln_count INTEGER DEFAULT 0,
            description     TEXT    DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            updated_at      TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
        )
    """)

    # ── 3) 报告记录表 ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            report_type TEXT    NOT NULL DEFAULT 'security_summary',
            title       TEXT    NOT NULL DEFAULT '',
            format_type TEXT    NOT NULL DEFAULT 'json',
            filters_json TEXT   DEFAULT '{}',
            content_json TEXT   DEFAULT '',
            status      TEXT    NOT NULL DEFAULT 'completed',
            generated_by INTEGER DEFAULT NULL,
            file_size   INTEGER DEFAULT 0,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (generated_by) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    # 从现有项目自动创建初始资产（仅当 assets 表为空时）
    existing_assets = cur.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    if existing_assets == 0:
        cur.execute("""
            INSERT INTO assets (name, asset_type, project_id, tech_stack, owner, risk_score, risk_level)
            SELECT p.name,
                   CASE p.project_type
                       WHEN 'web' THEN 'web_api'
                       WHEN 'api' THEN 'web_api'
                       WHEN 'mobile' THEN 'mobile_app'
                       ELSE 'microservice'
                   END,
                   p.id,
                   json_array(p.language),
                   'system',
                   CASE WHEN (SELECT COUNT(*) FROM vulnerabilities v JOIN scan_tasks s ON s.id=v.scan_id WHERE s.project_id=p.id AND v.status='open') > 5 THEN 75
                        WHEN (SELECT COUNT(*) FROM vulnerabilities v JOIN scan_tasks s ON s.id=v.scan_id WHERE s.project_id=p.id AND v.status='open') > 2 THEN 50
                        ELSE 25 END,
                   CASE WHEN (SELECT COUNT(*) FROM vulnerabilities v JOIN scan_tasks s ON s.id=v.scan_id WHERE s.project_id=p.id AND v.status='open') > 5 THEN 'high'
                        WHEN (SELECT COUNT(*) FROM vulnerabilities v JOIN scan_tasks s ON s.id=v.scan_id WHERE s.project_id=p.id AND v.status='open') > 2 THEN 'medium'
                        ELSE 'low' END
            FROM projects p
        """)

    # 注入默认规则示例（已禁用自动播种）
    if False and not cur.execute("SELECT id FROM rules LIMIT 1").fetchone():
        default_rules = [
            ("第三方依赖漏洞-低风险可忽略", "ignore", "sca", "low", "自动发现的低危依赖CVE，确认无利用路径后可忽略"),
            ("测试代码中的硬编码凭证", "ignore", "secret", "all", "test/、spec/、__tests__/目录下的密钥，仅测试环境使用"),
            ("已知误报-XSS模板转义", "ignore", "sast", "medium", "框架模板引擎已做转义，Semgrep规则误报"),
            ("自定义规则: 禁用eval()", "custom_scan", "sast", "all", "检测Python/JavaScript中eval()使用，高危代码模式"),
            ("自定义规则: 检测硬编码IP", "custom_scan", "secret", "medium", "检测源码中硬编码的IPv4地址"),
        ]
        for name, rtype, cat, sev, desc in default_rules:
            cur.execute(
                "INSERT INTO rules (name,rule_type,category,severity_filter,pattern,description,enabled) VALUES (?,?,?,?,?,?,1)",
                (name, rtype, cat, f'["{sev}"]', '', desc)
            )

    conn.commit()


def _migrate_phase1(conn):
    """Phase 1: 安全增强迁移 — 用户安全字段。"""
    cur = conn.cursor()

    # 用户表增加安全相关列
    for col in [
        ("last_login", "TEXT DEFAULT ''"),
        ("login_fail_count", "INTEGER DEFAULT 0"),
        ("locked_until", "TEXT DEFAULT ''"),
        ("status", "TEXT NOT NULL DEFAULT 'active'"),  # active / disabled
        ("token_version", "INTEGER DEFAULT 0"),
    ]:
        try:
            cur.execute(f"ALTER TABLE users ADD COLUMN {col[0]} {col[1]}")
        except sqlite3.OperationalError:
            pass

    # 创建默认安全分析师角色用户（如果不存在）
    existing_sa = cur.execute("SELECT id FROM users WHERE email=?", ("analyst@sentinel.io",)).fetchone()
    if not existing_sa:
        from routes.auth import hash_pw
        pw_hash = hash_pw("analyst123")
        cur.execute(
            "INSERT INTO users (email, password, name, role) VALUES (?,?,?,?)",
            ("analyst@sentinel.io", pw_hash, "安全分析师", "security_analyst"),
        )

    # 创建默认开发者用户
    existing_dev = cur.execute("SELECT id FROM users WHERE email=?", ("dev@sentinel.io",)).fetchone()
    if not existing_dev:
        from routes.auth import hash_pw
        pw_hash = hash_pw("dev123")
        cur.execute(
            "INSERT INTO users (email, password, name, role) VALUES (?,?,?,?)",
            ("dev@sentinel.io", pw_hash, "开发人员", "developer"),
        )

    conn.commit()


def _migrate_phase4(conn):
    """Phase 4: 告警引擎 + IM 通知渠道。"""
    cur = conn.cursor()

    # ── 告警表 ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type  TEXT    NOT NULL DEFAULT 'vuln_found',
            title       TEXT    NOT NULL,
            severity    TEXT    NOT NULL DEFAULT 'medium',
            source_type TEXT    NOT NULL DEFAULT 'scan',
            source_id   INTEGER DEFAULT 0,
            project_id  INTEGER DEFAULT NULL,
            project_name TEXT   DEFAULT '',
            status      TEXT    NOT NULL DEFAULT 'new',
            detail_json TEXT    DEFAULT '{}',
            vuln_count  INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count  INTEGER DEFAULT 0,
            assigned_to INTEGER DEFAULT NULL,
            resolved_at TEXT    DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL,
            FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    # ── 通知渠道表 ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notification_channels (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_type TEXT   NOT NULL DEFAULT 'dingtalk',
            name        TEXT    NOT NULL DEFAULT '',
            webhook_url TEXT    NOT NULL DEFAULT '',
            secret      TEXT    DEFAULT '',
            enabled     INTEGER NOT NULL DEFAULT 1,
            config_json TEXT    DEFAULT '{}',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
        )
    """)

    # 默认告警收敛配置
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alert_config (
            id          INTEGER PRIMARY KEY CHECK (id = 1),
            dedup_minutes INTEGER NOT NULL DEFAULT 5,
            severe_alert_on TEXT NOT NULL DEFAULT '["critical","high"]',
            auto_resolve_hours INTEGER NOT NULL DEFAULT 168,
            updated_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )
    """)
    cur.execute("INSERT OR IGNORE INTO alert_config (id) VALUES (1)")

    conn.commit()


def _migrate_phase5(conn):
    """Phase 5: 工单系统 + 工单评论。"""
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT    NOT NULL,
            description TEXT    DEFAULT '',
            priority    TEXT    NOT NULL DEFAULT 'medium',
            status      TEXT    NOT NULL DEFAULT 'open',
            source_type TEXT    NOT NULL DEFAULT 'manual',
            source_id   INTEGER DEFAULT 0,
            source_url  TEXT    DEFAULT '',
            assigned_to INTEGER DEFAULT NULL,
            created_by  INTEGER DEFAULT NULL,
            resolved_at TEXT    DEFAULT '',
            due_date    TEXT    DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS ticket_comments (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id   INTEGER NOT NULL,
            user_id     INTEGER DEFAULT NULL,
            content     TEXT    NOT NULL,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    # AI 问答历史 — 持久化用户与 AI 的对话
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ai_chat_history (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            role          TEXT    NOT NULL,          -- 'user' 或 'assistant'
            content       TEXT    NOT NULL,
            vuln_id       INTEGER DEFAULT NULL,       -- 关联漏洞（可空）
            project_id    INTEGER DEFAULT NULL,       -- 关联项目（可空）
            tokens_used   INTEGER DEFAULT 0,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_ai_chat_user
        ON ai_chat_history (user_id, created_at)
    """)

    conn.commit()


def _migrate_phase7(conn):
    """Phase 7: 知识库 — 安全知识沉淀与复用。"""
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS knowledge_articles (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT    NOT NULL,
            content     TEXT    NOT NULL DEFAULT '',
            category    TEXT    NOT NULL DEFAULT 'general',
            tags        TEXT    NOT NULL DEFAULT '[]',
            author_id   INTEGER DEFAULT NULL,
            view_count  INTEGER NOT NULL DEFAULT 0,
            is_published INTEGER NOT NULL DEFAULT 1,
            summary     TEXT    DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    # 全文搜索索引
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_kb_category
        ON knowledge_articles (category, is_published)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_kb_updated
        ON knowledge_articles (updated_at DESC)
    """)

    # ── 种子数据（已禁用自动播种）──
    if False and not cur.execute("SELECT id FROM knowledge_articles LIMIT 1").fetchone():
        admin_user = cur.execute("SELECT id FROM users WHERE email='admin@sentinel.io'").fetchone()
        author_id = admin_user["id"] if admin_user else None

        seed = [
            (
                "SQL 注入防御指南",
                "web_security",
                '["sql注入","owasp","修复","sast"]',
                "SQL 注入的原理、检测方法与修复方案汇总。",
                """## SQL 注入概述

SQL 注入（SQL Injection）是最常见的 Web 安全漏洞之一，攻击者通过将恶意 SQL 代码插入到应用查询中，达到非法访问、篡改或删除数据库数据的目的。

## 常见攻击向量

### 1. 基于用户输入
```python
# 不安全
query = f"SELECT * FROM users WHERE name = '{user_input}'"
```

### 2. 基于 URL 参数
```
https://example.com/product?id=1 OR 1=1--
```

## 防御措施

### 参数化查询（首选）
```python
# Python + SQLite
cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))

# Java JDBC PreparedStatement
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
ps.setString(1, userInput);
```

### ORM 框架
```python
# Django ORM
User.objects.filter(name=user_input)

# SQLAlchemy
session.query(User).filter(User.name == user_input)
```

### 输入校验与白名单
- 对整数 ID 做类型强转
- 字符串做长度和字符集限制
- 排序字段做白名单校验

## Sentinel 平台扫描规则

使用 Semgrep 规则自动检测：
```yaml
rules:
  - id: python-sql-injection
    patterns:
      - pattern: f"...$VAR..."
      - pattern-inside: execute(...)
    message: 可能存在 SQL 注入
    severity: ERROR
```

## 参考
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
""",
            ),
            (
                "XSS 跨站脚本攻击防护",
                "web_security",
                '["xss","owasp","前端安全","修复"]',
                "反射型、存储型、DOM 型 XSS 的原理与完整防护方案。",
                """## XSS 跨站脚本攻击

XSS（Cross-Site Scripting）允许攻击者将恶意脚本注入到其他用户浏览的页面中。

## 三种类型

| 类型 | 攻击方式 | 危害 |
|------|---------|------|
| 反射型 | URL 参数直接回显 | Cookie 窃取 |
| 存储型 | 数据库/文件存储后展示 | 持久化攻击 |
| DOM 型 | 前端 JS 动态写入 | 绕过服务端过滤 |

## 防御方案

### 1. 输出编码
- HTML 上下文：`&lt; &gt; &amp; &quot; &#x27;`
- JS 上下文：`\\x3C` 等 Unicode 转义
- URL 上下文：`encodeURIComponent()`

### 2. CSP (Content Security Policy)
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'
```

### 3. HttpOnly Cookie
```
Set-Cookie: session=xxx; HttpOnly; Secure; SameSite=Strict
```

### 4. 前端框架内置防护
- React: JSX 自动转义 `{userInput}`
- Vue: `{{ }}` 自动转义，`v-html` 需谨慎
- Angular: 默认对所有值进行清洗

## Sentinel 检测
平台已内置增强正则扫描规则：
- `detect_xss` — 检测 `<script>` 注入
- `detect_innerHTML` — 检测 .innerHTML 赋值
- `detect_document_write` — 检测 document.write() 调用
""",
            ),
            (
                "依赖供应链安全 — SCA 最佳实践",
                "supply_chain",
                '["sca","依赖","cve","trivy","供应链"]',
                "如何通过 SCA 工具管理第三方依赖的已知漏洞，建立持续监控流程。",
                """## 软件供应链安全 (SCA)

现代应用 80% 以上的代码来自第三方依赖，SCA 是识别和管理这些依赖中已知漏洞的关键手段。

## Sentinel 支持的 SCA 工具

| 工具 | 适用场景 | 配置 |
|------|---------|------|
| Trivy | 容器镜像、Git 仓库、文件系统 | `trivy fs --severity HIGH,CRITICAL .` |
| Dependency-Check | Java/Maven、.NET/NuGet 项目 | OWASP 官方工具，需配置 NVD API Key |

## 工作流

1. **识别**: 扫描 `requirements.txt` / `package.json` / `pom.xml` 等清单文件
2. **分析**: 对照 NVD/OSV/GHSA 等漏洞库
3. **优先级**: 基于 CVSS 评分 + 实际可达性判断
4. **修复**: `pip install --upgrade` / `npm update` / 版本锁定

## 关键指标

- **MTTR** (Mean Time to Repair): 高危漏洞修复时间 < 7 天
- **依赖健康度**: 无已知 CVE 的依赖占比
- **SBOM**: 每次构建生成软件物料清单

## Sentinel 自动化

```bash
# 在 Sentinel 项目中配置定时扫描
# 每次代码推送触发 SCA 扫描 → 漏洞自动入库 → 告警通知
```

## 参考
- NVD: https://nvd.nist.gov/
- OSV: https://osv.dev/
- OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/
""",
            ),
            (
                "敏感信息泄露 — 密钥/凭证检测指南",
                "data_security",
                '["密钥","凭证","gitleaks","secret","硬编码"]',
                "常见的密钥泄露场景、检测工具配置与修复方案。",
                """## 敏感信息泄露检测

硬编码的 API Key、密码、Token 是代码仓库中最常见的安全隐患之一。

## 常见泄露模式

```
# AWS Access Key
AKIAIOSFODNN7EXAMPLE

# GitHub Token
ghp_xxxxxxxxxxxxxxxxxxxx

# Private Key
-----BEGIN RSA PRIVATE KEY-----

# 数据库连接串
mysql://user:password@host/db
```

## Sentinel 检测方案

### Gitleaks（默认启用）
自动扫描 Git 历史中的所有提交，识别密钥模式。

### 增强正则扫描（46 条 Python + 26 条 JS 规则）
```
- detect_api_key      → 检测 API 密钥模式
- detect_password     → 检测硬编码密码
- detect_token        → 检测各类 Token
- detect_private_key  → 检测私钥文件
```

## 修复方案

### 1. 环境变量
```python
# 不安全
API_KEY = "sk-xxxx"

# 安全
import os
API_KEY = os.environ.get("API_KEY")
```

### 2. 密钥管理服务
- AWS Secrets Manager
- HashiCorp Vault
- Azure Key Vault

### 3. .gitignore
```gitignore
.env
*.pem
credentials.json
```

### 4. 已泄露密钥轮换
1. 立即在服务商后台吊销密钥
2. 生成新密钥，通过环境变量或密钥管理服务分发
3. 使用 `git filter-branch` 或 BFG 清理 Git 历史
4. 强制推送并通知所有协作者重新 clone

## 预防措施
- pre-commit hook: 安装 gitleaks 本地钩子
- CI/CD: 每次 PR 自动扫描
- Sentinel: 定时全量扫描所有项目仓库
""",
            ),
            (
                "安全审计 SOP — 从发现到修复的完整流程",
                "ops_process",
                '["审计","sop","流程","工单","sla"]',
                "Sentinel 平台的标准安全审计操作流程，覆盖漏洞生命周期管理。",
                """## 安全审计标准操作流程

## 漏洞生命周期

```
发现 → 确认 → 分派 → 修复 → 验证 → 关闭
 ↓       ↓      ↓      ↓      ↓       ↓
扫描   人工   责任人  开发  重新扫描  归档
```

## SLA 时限

| 严重度 | 修复时限 | 升级规则 |
|--------|---------|---------|
| Critical | 24 小时 | 超时自动升级至安全负责人 |
| High | 7 天 | 超时触发工单提醒 |
| Medium | 30 天 | 纳入月度安全回顾 |
| Low | 90 天 | 可接受风险，按需修复 |

## Sentinel 平台操作步骤

### 1. 告警响应
- 收到钉钉/企微/飞书通知
- 登录平台查看告警详情
- 确认真实性（确认 / 误报标记）

### 2. 漏洞分析
- 查看漏洞关联的扫描结果
- 使用 AI 分析功能获取修复建议
- 确认影响范围和利用条件

### 3. 工单分派
- 根据项目负责人自动分派工单
- 或手动指定安全分析师处理
- 工单关联原始漏洞

### 4. 修复验证
- 开发人员提交修复代码
- 重新触发扫描验证
- 确认漏洞状态为"已修复"

### 5. 归档复盘
- 关闭工单和告警
- 在知识库沉淀案例
- 更新忽略规则（如有误报）
""",
            ),
            (
                "CodeQL 语义分析 — 变体检测入门",
                "tool_guide",
                '["codeql","sast","变体分析","语义"]',
                "CodeQL 的安装配置、基础查询编写与 Sentinel 集成方法。",
                """## CodeQL 语义代码分析

CodeQL 是 GitHub 推出的语义级代码分析引擎，能将代码转化为数据库并执行类似 SQL 的查询来发现漏洞变体。

## 安装配置

```bash
# 下载 CodeQL CLI
gh extensions install github/gh-codeql

# 创建数据库
codeql database create my-db --language=python --source-root=.

# 运行分析
codeql database analyze my-db --format=sarif --output=results.sarif
```

## 基础查询示例

```ql
// 检测不安全的反序列化 (Python)
import python

from Call call, Name name
where
  call.getFunc() = name and
  name.getId() = "pickle.loads" and
  not exists(Import imp |
    imp.getAnImportedModuleName() = "json"
  )
select call, "不安全的 pickle.loads 调用"
```

## Sentinel 集成

1. 在工具管理中启用 CodeQL
2. 配置 CodeQL 可执行文件路径
3. 扫描时自动创建 CodeQL 数据库并分析
4. 漏洞结果自动入库，关联项目

## 变体分析

CodeQL 的独特优势：发现一个漏洞后，可以编写查询扫描整个代码库中所有相似模式：
- 发现一处 SQL 注入 → 查询所有字符串拼接 + execute 调用
- 发现一处 SSRF → 查询所有用户可控 URL 的 HTTP 请求
- 发现一处路径遍历 → 查询所有 `os.path.join(user_input, ...)` 模式
""",
            ),
        ]
        for title, category, tags, summary, content in seed:
            cur.execute(
                """INSERT INTO knowledge_articles
                   (title, content, category, tags, author_id, summary, is_published)
                   VALUES (?,?,?,?,?,?,1)""",
                (title, content, category, tags, author_id, summary),
            )
        logger.info("[Sentinel] 知识库种子数据已注入 (6 篇安全指南)")

    conn.commit()


def _migrate_phase8(conn):
    """Phase 8: 工具使用统计字段 (scan_count, last_scan_at, vuln_found_total)。"""
    cur = conn.cursor()
    columns = [row[1] for row in cur.execute("PRAGMA table_info(tools)").fetchall()]

    if "scan_count" not in columns:
        cur.execute("ALTER TABLE tools ADD COLUMN scan_count INTEGER NOT NULL DEFAULT 0")
    if "last_scan_at" not in columns:
        cur.execute("ALTER TABLE tools ADD COLUMN last_scan_at TEXT DEFAULT NULL")
    if "vuln_found_total" not in columns:
        cur.execute("ALTER TABLE tools ADD COLUMN vuln_found_total INTEGER NOT NULL DEFAULT 0")

    conn.commit()


# ═══════════════════════════════════════════════════════
#  App 工厂
# ═══════════════════════════════════════════════════════

def create_app():
    app = Flask(
        __name__,
        static_folder=None,  # 我们自己处理静态文件
        template_folder=None,
    )
    app.secret_key = JWT_SECRET

    # M-05: CORS — 从环境变量读取允许的 origins，默认仅允许本地开发环境
    _cors_origins_str = os.environ.get("SENTINEL_CORS_ORIGINS", "")
    if _cors_origins_str:
        _allowed_origins = [o.strip() for o in _cors_origins_str.split(",") if o.strip()]
    else:
        _allowed_origins = [
            "http://localhost:5173", "http://127.0.0.1:5173",
            "http://localhost:5000", "http://127.0.0.1:5000",
        ]
    CORS(app, supports_credentials=True, resources={
        r"/api/*": {"origins": _allowed_origins}
    })

    # L-03: 拒绝 HTTP 方法覆盖请求（防止用 POST 执行 GET 操作）
    BLOCKED_METHOD_HEADERS = {
        "X-HTTP-Method-Override", "X-HTTP-Method",
        "X-Method-Override",
    }
    @app.before_request
    def _block_method_override():
        for header_name in BLOCKED_METHOD_HEADERS:
            if request.headers.get(header_name):
                return jsonify({
                    "error": "bad_request",
                    "message": f"不支持 {header_name} 请求头",
                }), 400

    logger.debug("[DEBUG] calling init_db()...")
    init_db()
    logger.debug("[DEBUG] init_db() done")
    _warn_default_admin()

    # Phase 4: 定时扫描调度迁移
    logger.debug("[DEBUG] calling migrate_scheduler...")
    conn4 = get_db()
    from services.scheduler_service import migrate_scheduler
    migrate_scheduler(conn4)
    conn4.close()
    logger.debug("[DEBUG] migrate_scheduler() done")

    logger.debug("[DEBUG] registering blueprints...")
    from routes.auth_routes import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.api import api_bp
    from routes.projects import projects_bp
    from routes.tools import tools_bp
    from routes.scans import scans_bp
    from routes.settings import settings_bp
    from routes.ai_routes import ai_bp
    from routes.webhooks import webhooks_bp
    from routes.rules import rules_bp
    from routes.assets import assets_bp
    from routes.reports import reports_bp
    from routes.audit_routes import audit_bp
    from routes.schedules import schedules_bp
    from routes.metrics import metrics_bp
    from routes.alerts import alerts_bp
    from routes.today import today_bp
    from routes.tickets import tickets_bp
    from routes.email import email_bp
    from routes.knowledge_base import knowledge_base_bp
    from routes.skills import skills_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(dashboard_bp, url_prefix="/api/dashboard")
    app.register_blueprint(projects_bp, url_prefix="/api/projects")
    app.register_blueprint(tools_bp, url_prefix="/api/tools")
    app.register_blueprint(scans_bp, url_prefix="/api/scans")
    app.register_blueprint(settings_bp, url_prefix="/api/settings")
    app.register_blueprint(ai_bp, url_prefix="/api/ai")
    app.register_blueprint(webhooks_bp, url_prefix="/api/webhooks")
    app.register_blueprint(rules_bp, url_prefix="/api/rules")
    app.register_blueprint(assets_bp, url_prefix="/api/assets")
    app.register_blueprint(reports_bp, url_prefix="/api/reports")
    app.register_blueprint(audit_bp, url_prefix="/api/audit")
    app.register_blueprint(schedules_bp, url_prefix="/api/schedules")
    app.register_blueprint(metrics_bp, url_prefix="/api/metrics")
    app.register_blueprint(alerts_bp, url_prefix="/api/alerts")
    app.register_blueprint(today_bp, url_prefix="/api/today")
    app.register_blueprint(tickets_bp, url_prefix="/api/tickets")
    app.register_blueprint(email_bp, url_prefix="/api/email")
    app.register_blueprint(knowledge_base_bp, url_prefix="/api/knowledge-base")
    app.register_blueprint(skills_bp, url_prefix="/api/skills")
    app.register_blueprint(api_bp, url_prefix="/api")

    # ═══ Phase 1: 安全中间件注册 ═══
    from routes.security import security_headers
    app.after_request(security_headers)

    # 请求体大小限制 (5MB)
    from routes.security import MAX_REQUEST_BODY_KB
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BODY_KB * 1024

    # ─── 前端 SPA 服务 ───
    # 生产模式：Flask 直接 serve React 构建产物
    # 开发模式：前端由 Vite dev server 提供，这里仅作 fallback
    _serve_frontend(app)

    # ─── 启动定时扫描调度器 ───
    try:
        from services.scheduler_service import init_scheduler
        init_scheduler()
        logger.info("[Sentinel] Scan scheduler started")
    except Exception as e:
        logger.warning(f"[Sentinel] Scheduler init skipped: {e}")

    logger.info("=" * 56)
    logger.info("  Sentinel AppSec Platform v4.0 (Phase 1: Security Hardened)")
    logger.info(f"  API:     http://{FLASK_HOST}:{FLASK_PORT}/api/")
    logger.info(f"  Frontend: http://localhost:{FLASK_PORT}/")
    logger.info(f"  Scanner:  {SCANNER_MODE}")
    logger.info(f"  Email:    {'enabled' if SMTP_CONFIG['enabled'] else 'disabled (set SMTP env vars to enable)'}")
    logger.info("=" * 56)

    return app


def _serve_frontend(app: Flask):
    """配置 Flask 提供 React 生产构建产物。"""

    if not os.path.isdir(FRONTEND_DIST):
        logger.info(f"[Sentinel] FRONTEND_DIST not found at {FRONTEND_DIST}")
        logger.info("[Sentinel] 前端未构建，请先执行: cd frontend && npm run build")
        logger.info("[Sentinel] 或使用开发模式: cd frontend && npm run dev")
        return

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def serve_frontend(path):
        """SPA fallback: 所有非 /api/ 路由返回 index.html"""
        if path == "api" or path.startswith("api/"):
            return app.response_class(status=404)
        # 尝试匹配静态文件
        full = os.path.join(FRONTEND_DIST, path)
        if path and os.path.isfile(full):
            return send_from_directory(FRONTEND_DIST, path)
        # SPA fallback
        return send_from_directory(FRONTEND_DIST, "index.html")

    logger.info(f"[Sentinel] Serving frontend from {FRONTEND_DIST}")
