# ─── CI/CD Webhook 触发扫描 + 安全门禁 ───
"""
CI/CD 管道通过 POST /api/webhooks/scan 触发安全扫描，
返回扫描结果 + 安全门禁判断。

接入方式：
  curl -X POST http://sentinel/api/webhooks/scan?token=YOUR_TOKEN \
    -H "Content-Type: application/json" \
    -d '{"project_name":"my-service","tool_type":"SAST","ref":"main"}'

安全门禁规则（可配置）：
  Critical → BLOCK（阻断构建）
  High     → WARN（告警但放行）
  Medium   → PASS
  Low      → PASS

设计要点：
  所有 helper 函数（_verify_token / _evaluate_gate / _audit）接受 db 参数，
  由路由处理函数负责创建和关闭单一连接，避免同一请求内多次 open/close
  导致 WAL 锁竞争。
"""

import json
import re
import uuid
import hmac
import hashlib
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from app import get_db
from routes.auth import login_required
from config import SCANNER_MODE

webhooks_bp = Blueprint("webhooks", __name__)


def _verify_token(db) -> bool:
    """验证 Webhook token。使用 hmac.compare_digest 防止时序攻击。
    未配置 token 时拒绝所有请求。
    调用方负责 db.close()。"""
    row = db.execute("SELECT token FROM webhook_config WHERE id=1").fetchone()
    db_stored = row["token"] if row else ""

    if not db_stored:
        return False  # 未配置 token 时拒绝所有请求

    token = request.args.get("token", "") or request.headers.get("X-Sentinel-Token", "")
    if not token:
        return False
    return hmac.compare_digest(token, db_stored)


def _evaluate_gate(vulnerabilities: list, db) -> dict:
    """
    安全门禁判断。调用方负责 db.close()。

    返回：
      decision: "block" | "warn" | "pass"
      reasons:  阻断/告警原因列表
    """
    rules_row = db.execute(
        "SELECT gate_rules, gate_mode FROM webhook_config WHERE id=1"
    ).fetchone()

    if rules_row:
        try:
            gate_rules = json.loads(rules_row["gate_rules"])
        except (json.JSONDecodeError, TypeError):
            gate_rules = {"critical": "block", "high": "warn", "medium": "pass", "low": "pass"}
        gate_mode = rules_row["gate_mode"] or "block"
    else:
        gate_rules = {"critical": "block", "high": "warn", "medium": "pass", "low": "pass"}
        gate_mode = "block"

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    reasons = []

    for v in vulnerabilities:
        sev = (v.get("severity") or "low").lower()
        counts[sev] = counts.get(sev, 0) + 1

    # 逐级判断
    if counts.get("critical", 0) > 0 and gate_rules.get("critical") == "block":
        reasons.append(f"发现 {counts['critical']} 个 Critical 级别漏洞")
    if counts.get("high", 0) > 0 and gate_rules.get("high") == "block":
        reasons.append(f"发现 {counts['high']} 个 High 级别漏洞")

    if reasons:
        return {"decision": "block", "reasons": reasons, "gate_mode": gate_mode}

    if counts.get("critical", 0) > 0 and gate_rules.get("critical") == "warn":
        reasons.append(f"发现 {counts['critical']} 个 Critical 漏洞（告警）")
    if counts.get("high", 0) > 0 and gate_rules.get("high") == "warn":
        reasons.append(f"发现 {counts['high']} 个 High 漏洞（告警）")

    if reasons:
        return {"decision": "warn", "reasons": reasons, "gate_mode": gate_mode}

    return {"decision": "pass", "reasons": [], "gate_mode": gate_mode}


def _audit(action: str, db, target_type: str = "", target_id: int = 0, detail: str = ""):
    """记录审计日志。调用方负责 db.close()，失败不影响主流程。"""
    try:
        user_id = request.environ.get("sentinel_user_id", 0)
        user_email = request.environ.get("sentinel_user_email", "webhook")
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        db.execute(
            """INSERT INTO audit_logs (user_id, user_email, action, target_type, target_id, detail, ip_address)
               VALUES (?,?,?,?,?,?,?)""",
            (user_id, user_email, action, target_type, target_id, detail, ip)
        )
        db.commit()
    except Exception:
        pass


# ═══════════════════════════════════════════════════════
#  路由
# ═══════════════════════════════════════════════════════

@webhooks_bp.route("/scan", methods=["POST"])
def webhook_scan():
    """
    CI/CD 管道触发扫描 + 安全门禁。

    在整个请求生命周期内使用同一个 DB 连接，避免 WAL 锁竞争。
    """
    # ═══ 鉴权 ═══
    db = get_db()
    try:
        if not _verify_token(db):
            db.close()
            return jsonify({"error": "无效的 Webhook token"}), 401

        data = request.get_json(silent=True) or {}
        project_id = data.get("project_id")
        project_name = data.get("project_name", "").strip()
        tool_type = data.get("tool_type", "").strip()
        source_ref = data.get("ref", "").strip()

        if not tool_type:
            db.close()
            return jsonify({"error": "tool_type 为必填项"}), 400

        # 1. 查找项目
        if project_id:
            project = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        elif project_name:
            project = db.execute("SELECT * FROM projects WHERE name=?", (project_name,)).fetchone()
        else:
            db.close()
            return jsonify({"error": "project_id 或 project_name 为必填项"}), 400

        if not project:
            db.close()
            return jsonify({"error": f"项目不存在: {project_name or project_id}"}), 404

        project_id = project["id"]

        # 2. 查找启用的工具
        tool = db.execute(
            "SELECT * FROM tools WHERE LOWER(tool_type)=LOWER(?) AND enabled=1 LIMIT 1", (tool_type,)
        ).fetchone()
        if not tool:
            db.close()
            return jsonify({"error": f"没有启用的 {tool_type} 工具"}), 400

        # 3. 创建扫描任务
        now_local = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        cur = db.execute(
            """INSERT INTO scan_tasks (project_id, tool_id, tool_type, status, started_at)
               VALUES (?,?,?,'running',?)""",
            (project_id, tool["id"], tool_type, now_local)
        )
        scan_id = cur.lastrowid
        db.commit()

        # 审计日志
        _audit("webhook_scan", db, "scan_task", scan_id,
               f"CI/CD 触发扫描: project={project['name']}, tool={tool_type}, ref={source_ref}")

        # 4. 调用扫描器
        from integrations import REGISTRY as SCANNER_REGISTRY

        _NAME_TO_KEY = {
            "Semgrep": "semgrep", "Trivy": "trivy", "OWASP ZAP": "zap",
            "Gitleaks": "gitleaks", "Dependency-Check": "dependency-check", "CodeQL": "codeql",
        }
        key = _NAME_TO_KEY.get(tool["name"])
        if not key or key not in SCANNER_REGISTRY:
            db.execute("UPDATE scan_tasks SET status='failed', finished_at=? WHERE id=?",
                       (now_local, scan_id))
            db.commit()
            db.close()
            return jsonify({"error": f"不支持的扫描器: {tool['name']}"}), 500

        cls = SCANNER_REGISTRY[key]
        scanner = cls(
            mode=SCANNER_MODE,
            api_endpoint=tool["endpoint"] or "",
            api_key=tool["api_key"] or "",
        )

        try:
            project_config = dict(project)
            project_config["lang"] = project["language"] or "python"
            scan_result = scanner.run(project_config)
        except Exception as e:
            db.execute("UPDATE scan_tasks SET status='failed', finished_at=? WHERE id=?",
                       (now_local, scan_id))
            db.commit()
            db.close()
            return jsonify({"error": f"扫描执行失败: {str(e)}"}), 500

        # 5. 漏洞入库（含 SLA 计算）
        vuln_dicts = []
        sla_due_map = {"critical": "+1 day", "high": "+7 days", "medium": "+30 days", "low": "+90 days"}

        for v in scan_result.vulnerabilities:
            vd = v.to_dict()
            sev = vd["severity"].lower()
            sla_offset = sla_due_map.get(sev, "+14 days")

            db.execute(
                """INSERT INTO vulnerabilities
                   (scan_id, cve_id, title, severity, file_path, line, source_tool,
                    description, fix_suggestion, cvss_score, cwe_id, sla_due_date)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,
                           datetime('now','localtime',?))""",
                (scan_id, vd["cve_id"], vd["title"], vd["severity"],
                 vd["file_path"], vd["line"], tool["name"],
                 vd["description"], vd["recommendation"], vd["cvss_score"],
                 vd["cwe_id"], sla_offset)
            )
            vuln_dicts.append({
                "cve_id": vd["cve_id"], "title": vd["title"],
                "severity": vd["severity"], "file_path": vd["file_path"],
                "line": vd["line"], "description": vd["description"],
                "cvss_score": vd["cvss_score"], "cwe_id": vd["cwe_id"],
                "fix_suggestion": vd["recommendation"], "source_tool": tool["name"],
            })

        # 6. 更新扫描状态
        db.execute(
            "UPDATE scan_tasks SET status='completed', vuln_count=?, finished_at=? WHERE id=?",
            (len(vuln_dicts), now_local, scan_id)
        )
        db.commit()

        # 7. 安全门禁判断（共享同一连接）
        gate_result = _evaluate_gate(vuln_dicts, db)

        # 8. 发送邮件告警
        try:
            from config import SMTP_CONFIG
            if SMTP_CONFIG.get("enabled"):
                from notifications import EmailNotifier
                notifier = EmailNotifier(SMTP_CONFIG)
                critical_high = [v for v in vuln_dicts if v["severity"] in ("critical", "high")]
                if critical_high:
                    notifier.send_scan_alert(project["name"], tool["name"],
                                             critical_high, {"summary": scan_result.summary})
        except Exception:
            pass

        return jsonify({
            "scan_id": scan_id,
            "status": "completed",
            "vuln_count": len(vuln_dicts),
            "gate": gate_result,
            "vulnerabilities": vuln_dicts,
            "summary": scan_result.summary,
            "source_ref": source_ref,
        }), 201

    finally:
        db.close()


@webhooks_bp.route("/gate", methods=["POST"])
def check_gate():
    """
    独立门禁检查（不触发新扫描，检查已有扫描结果）。

    请求体: { "scan_id": 123 }  或  { "project_id": 1 }
    响应:   { "decision": "block"|"warn"|"pass", ... }
    """
    db = get_db()
    try:
        if not _verify_token(db):
            db.close()
            return jsonify({"error": "无效的 Webhook token"}), 401

        data = request.get_json(silent=True) or {}
        scan_id = data.get("scan_id")
        project_id = data.get("project_id")

        if not scan_id and not project_id:
            db.close()
            return jsonify({"error": "scan_id 或 project_id 为必填项"}), 400

        if not scan_id:
            scan = db.execute(
                "SELECT id FROM scan_tasks WHERE project_id=? ORDER BY created_at DESC LIMIT 1",
                (project_id,)
            ).fetchone()
            if not scan:
                db.close()
                return jsonify({"error": "该项目无扫描记录"}), 404
            scan_id = scan["id"]

        vulns = db.execute(
            "SELECT * FROM vulnerabilities WHERE scan_id=? AND status='open'", (scan_id,)
        ).fetchall()

        vuln_dicts = [dict(v) for v in vulns]
        gate_result = _evaluate_gate(vuln_dicts, db)

        return jsonify({
            "scan_id": scan_id,
            "vuln_count": len(vuln_dicts),
            "gate": gate_result,
        })
    finally:
        db.close()


@webhooks_bp.route("/config", methods=["GET"])
@webhooks_bp.route("/config", methods=["PUT"])
@login_required
def webhook_config():
    """GET/PUT /api/webhooks/config — Webhook 配置管理"""
    db = get_db()
    try:
        if request.method == "GET":
            row = db.execute("SELECT * FROM webhook_config WHERE id=1").fetchone()
            if not row:
                return jsonify({
                    "token": "", "gate_mode": "block",
                    "gate_rules": {"critical": "block", "high": "warn", "medium": "pass", "low": "pass"},
                })
            cfg = dict(row)
            try:
                cfg["gate_rules"] = json.loads(cfg["gate_rules"])
            except Exception:
                cfg["gate_rules"] = {"critical": "block", "high": "warn", "medium": "pass", "low": "pass"}
            return jsonify(cfg)

        # PUT
        data = request.get_json(silent=True) or {}
        token = data.get("token", "")
        gate_mode = data.get("gate_mode", "block")
        gate_rules = data.get("gate_rules", {})

        if isinstance(gate_rules, dict):
            gate_rules = json.dumps(gate_rules, ensure_ascii=False)

        db.execute(
            "UPDATE webhook_config SET token=?, gate_mode=?, gate_rules=?, updated_at=datetime('now','localtime') WHERE id=1",
            (token, gate_mode, gate_rules)
        )
        db.commit()

        row = db.execute("SELECT * FROM webhook_config WHERE id=1").fetchone()
        cfg = dict(row)
        try:
            cfg["gate_rules"] = json.loads(cfg["gate_rules"])
        except Exception:
            pass
        return jsonify(cfg)
    finally:
        db.close()


@webhooks_bp.route("/regenerate-token", methods=["POST"])
@login_required
def regenerate_token():
    """POST /api/webhooks/regenerate-token — 重新生成 Webhook token"""
    new_token = uuid.uuid4().hex
    db = get_db()
    try:
        db.execute("UPDATE webhook_config SET token=? WHERE id=1", (new_token,))
        db.commit()
        _audit("webhook_token_regenerated", db, "webhook_config", 1)
        return jsonify({"token": new_token})
    finally:
        db.close()


# ═══════════════════════════════════════════════════════
#  原生 Git 自动触发（GitHub / GitLab push 事件）
# ═══════════════════════════════════════════════════════

def _normalize_repo_url(url: str) -> str:
    """归一化仓库 URL，用于跨协议（https / ssh / git）匹配项目。"""
    if not url:
        return ""
    u = url.strip().lower()
    u = u.replace("git+", "")
    u = re.sub(r"\.git$", "", u)
    u = re.sub(r"^https?://", "", u)
    u = re.sub(r"^ssh://", "", u)
    u = re.sub(r"^git://", "", u)
    if u.startswith("git@"):
        u = u[4:]
    u = u.replace(":", "/")
    if "@" in u:
        u = u.split("@", 1)[1]
    return u.rstrip("/")


def _match_project(db, repo_url: str, repo_name: str):
    """按仓库 URL（归一化）或名称匹配项目。"""
    norm = _normalize_repo_url(repo_url)
    if norm:
        for row in db.execute("SELECT * FROM projects"):
            if _normalize_repo_url(row["repo_url"] or "") == norm:
                return row
    if repo_name:
        row = db.execute("SELECT * FROM projects WHERE name=?", (repo_name,)).fetchone()
        if row:
            return row
    return None


def _verify_signature(sig_header: str, body: bytes) -> bool:
    """用 webhook token 校验 GitHub 的 X-Hub-Signature-256（HMAC-SHA256）。"""
    db = get_db()
    try:
        row = db.execute("SELECT token FROM webhook_config WHERE id=1").fetchone()
        token = row["token"] if row else ""
    finally:
        db.close()
    if not token or not sig_header or not sig_header.startswith("sha256="):
        return False
    expected = hmac.new(token.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig_header[7:], expected)


def _launch_scan(db, project: dict, tool_type: str, source_ref: str = "", source_commit: str = "") -> dict:
    """
    统一的扫描启动逻辑（被 /scan、/github、/gitlab 共用）。
    调用方负责 db 的开关；本函数只使用传入的 db 连接、提交事务，不关闭连接。
    """
    project_id = project["id"]

    tool = db.execute(
        "SELECT * FROM tools WHERE LOWER(tool_type)=LOWER(?) AND enabled=1 LIMIT 1", (tool_type,)
    ).fetchone()
    if not tool:
        return {"error": f"没有启用的 {tool_type} 工具"}

    now_local = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cur = db.execute(
        """INSERT INTO scan_tasks (project_id, tool_id, tool_type, status, started_at)
           VALUES (?,?,?,'running',?)""",
        (project_id, tool["id"], tool_type, now_local)
    )
    scan_id = cur.lastrowid
    db.commit()

    _audit("webhook_scan", db, "scan_task", scan_id,
           f"触发扫描: project={project['name']}, tool={tool_type}, ref={source_ref}, commit={source_commit}")

    from integrations import REGISTRY as SCANNER_REGISTRY

    _NAME_TO_KEY = {
        "Semgrep": "semgrep", "Trivy": "trivy", "OWASP ZAP": "zap",
        "Gitleaks": "gitleaks", "Dependency-Check": "dependency-check", "CodeQL": "codeql",
    }
    key = _NAME_TO_KEY.get(tool["name"])
    if not key or key not in SCANNER_REGISTRY:
        db.execute("UPDATE scan_tasks SET status='failed', finished_at=? WHERE id=?",
                   (now_local, scan_id))
        db.commit()
        return {"error": f"不支持的扫描器: {tool['name']}"}

    cls = SCANNER_REGISTRY[key]
    scanner = cls(
        mode=SCANNER_MODE,
        api_endpoint=tool["endpoint"] or "",
        api_key=tool["api_key"] or "",
    )

    try:
        project_config = dict(project)
        project_config["lang"] = project["language"] or "python"
        scan_result = scanner.run(project_config)
    except Exception as e:
        db.execute("UPDATE scan_tasks SET status='failed', finished_at=? WHERE id=?",
                   (now_local, scan_id))
        db.commit()
        return {"error": f"扫描执行失败: {str(e)}"}

    vuln_dicts = []
    sla_due_map = {"critical": "+1 day", "high": "+7 days", "medium": "+30 days", "low": "+90 days"}

    for v in scan_result.vulnerabilities:
        vd = v.to_dict()
        sev = vd["severity"].lower()
        sla_offset = sla_due_map.get(sev, "+14 days")

        db.execute(
            """INSERT INTO vulnerabilities
               (scan_id, cve_id, title, severity, file_path, line, source_tool,
                description, fix_suggestion, cvss_score, cwe_id, sla_due_date)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,
                       datetime('now','localtime',?))""",
            (scan_id, vd["cve_id"], vd["title"], vd["severity"],
             vd["file_path"], vd["line"], tool["name"],
             vd["description"], vd["recommendation"], vd["cvss_score"],
             vd["cwe_id"], sla_offset)
        )
        vuln_dicts.append({
            "cve_id": vd["cve_id"], "title": vd["title"],
            "severity": vd["severity"], "file_path": vd["file_path"],
            "line": vd["line"], "description": vd["description"],
            "cvss_score": vd["cvss_score"], "cwe_id": vd["cwe_id"],
            "fix_suggestion": vd["recommendation"], "source_tool": tool["name"],
        })

    db.execute(
        "UPDATE scan_tasks SET status='completed', vuln_count=?, finished_at=? WHERE id=?",
        (len(vuln_dicts), now_local, scan_id)
    )
    db.commit()

    gate_result = _evaluate_gate(vuln_dicts, db)

    try:
        from config import SMTP_CONFIG
        if SMTP_CONFIG.get("enabled"):
            from notifications import EmailNotifier
            notifier = EmailNotifier(SMTP_CONFIG)
            critical_high = [v for v in vuln_dicts if v["severity"] in ("critical", "high")]
            if critical_high:
                notifier.send_scan_alert(project["name"], tool["name"],
                                         critical_high, {"summary": scan_result.summary})
    except Exception:
        pass

    return {
        "scan_id": scan_id,
        "status": "completed",
        "vuln_count": len(vuln_dicts),
        "gate": gate_result,
        "vulnerabilities": vuln_dicts,
        "summary": scan_result.summary,
        "source_commit": source_commit,
    }


@webhooks_bp.route("/github", methods=["POST"])
def github_webhook():
    """
    GitHub push 事件自动触发扫描（原生 Git 自动触发）。

    配置：仓库 Settings → Webhooks
      - Payload URL:  https://<你的域名>/api/webhooks/github
      - Content type: application/json
      - Secret:       平台 Webhook token（在 /api/webhooks/config 配置）
      - Events:       仅 Push events
    """
    body = request.get_data()
    if not _verify_signature(request.headers.get("X-Hub-Signature-256", ""), body):
        return jsonify({"error": "签名校验失败或 Webhook token 未配置"}), 401

    event = request.headers.get("X-GitHub-Event", "")
    if event != "push":
        return jsonify({"status": "ignored", "event": event}), 200

    db = get_db()
    try:
        data = request.get_json(silent=True) or {}
        repo = data.get("repository") or {}
        repo_url = repo.get("html_url") or repo.get("url") or ""
        repo_name = repo.get("name", "")
        ref = data.get("ref", "")
        branch = ref.split("/")[-1] if ref else ""
        commit = data.get("after", "") or (data.get("head_commit") or {}).get("id", "")

        project = _match_project(db, repo_url, repo_name)
        if not project:
            db.close()
            return jsonify({"error": f"未匹配到项目: {repo_url or repo_name}"}), 404

        result = _launch_scan(db, dict(project), "SAST", branch, commit)
        if "error" in result:
            return jsonify(result), 400
        return jsonify({**result, "provider": "github",
                        "source_ref": branch, "source_commit": commit}), 201

    finally:
        db.close()


@webhooks_bp.route("/gitlab", methods=["POST"])
def gitlab_webhook():
    """
    GitLab push 事件自动触发扫描（原生 Git 自动触发）。

    配置：项目 Settings → Webhooks
      - URL:          https://<你的域名>/api/webhooks/gitlab
      - Secret Token: 平台 Webhook token（在 /api/webhooks/config 配置）
      - Trigger:      Push events
    """
    # GitLab 使用 X-Gitlab-Token 头做简单等值校验（共享密钥 = 平台 Webhook token）
    gl_token = request.headers.get("X-Gitlab-Token", "")
    db = get_db()
    try:
        row = db.execute("SELECT token FROM webhook_config WHERE id=1").fetchone()
        stored = row["token"] if row else ""
        if not stored or not hmac.compare_digest(gl_token, stored):
            return jsonify({"error": "Token 校验失败"}), 401

        data = request.get_json(silent=True) or {}
        repo = data.get("repository") or {}
        repo_url = (repo.get("url") or repo.get("homepage")
                    or (data.get("project") or {}).get("web_url") or "")
        repo_name = ((data.get("project") or {}).get("name", "")
                     or repo.get("name", ""))
        ref = data.get("ref", "")
        commit = data.get("after", "") or data.get("checkout_sha", "")

        project = _match_project(db, repo_url, repo_name)
        if not project:
            db.close()
            return jsonify({"error": f"未匹配到项目: {repo_url or repo_name}"}), 404

        result = _launch_scan(db, dict(project), "SAST", ref, commit)
        if "error" in result:
            return jsonify(result), 400
        return jsonify({**result, "provider": "gitlab",
                        "source_ref": ref, "source_commit": commit}), 201

    finally:
        db.close()
