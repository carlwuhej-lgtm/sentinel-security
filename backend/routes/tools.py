# ─── Tool Registry Routes ───
import json
import urllib.request
import urllib.error
from flask import Blueprint, request, jsonify
from app import get_db
from routes.auth import login_required, admin_required

tools_bp = Blueprint("tools", __name__)

# ── 扫描适配器映射（工具名 → 适配器 key + 展示信息） ──
_SCANNER_ADAPTERS: dict[str, dict] = {
    "Semgrep":          {"key": "semgrep",          "type": "SAST",   "label": "Semgrep SAST 引擎",    "desc": "多语言语义静态分析"},
    "Trivy":            {"key": "trivy",            "type": "SCA",    "label": "Trivy SCA 引擎",       "desc": "容器/依赖项漏洞扫描"},
    "OWASP ZAP":        {"key": "zap",              "type": "DAST",   "label": "ZAP DAST 引擎",        "desc": "Web 应用动态安全检测"},
    "Gitleaks":         {"key": "gitleaks",         "type": "SECRET", "label": "Gitleaks 密钥检测",    "desc": "Git 历史中的密钥/凭证泄露"},
    "Dependency-Check": {"key": "dependency-check", "type": "SCA",    "label": "Dependency-Check 引擎", "desc": "OWASP 依赖项漏洞检查"},
    "CodeQL":           {"key": "codeql",           "type": "SAST",   "label": "CodeQL 代码分析引擎",  "desc": "深度语义代码分析"},
}


def _resolve_scanner_adapter(name: str, tool_type: str) -> dict | None:
    """根据工具名和类型查找对应的扫描适配器。"""
    # 精确匹配
    if name in _SCANNER_ADAPTERS and _SCANNER_ADAPTERS[name]["type"] == tool_type:
        return _SCANNER_ADAPTERS[name]
    # 模糊匹配（按 key 名）
    name_lower = name.lower().replace(" ", "-").replace("_", "-")
    for adapter_name, info in _SCANNER_ADAPTERS.items():
        if info["key"] == name_lower and info["type"] == tool_type:
            return info
    return None


def _mask_api_key(key: str | None) -> str:
    """脱敏 API Key，仅显示首尾各 4 个字符。"""
    key = (key or "").strip()
    if not key:
        return ""
    if len(key) <= 8:
        return "*" * len(key)
    return key[:4] + "*" * (len(key) - 8) + key[-4:]


@tools_bp.route("", methods=["GET"])
@login_required
def list_tools():
    db = get_db()
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    offset = (page - 1) * per_page

    total = db.execute("SELECT COUNT(*) FROM tools").fetchone()[0]
    rows = db.execute(
        "SELECT id, name, tool_type, description, endpoint, enabled,"
        " scan_count, last_scan_at, vuln_found_total, created_at"
        " FROM tools ORDER BY tool_type, name LIMIT ? OFFSET ?",
        (per_page, offset),
    ).fetchall()
    db.close()

    items = []
    for r in rows:
        item = dict(r)
        # 附加上适配器信息
        adapter = _resolve_scanner_adapter(item["name"], item["tool_type"])
        item["has_adapter"] = adapter is not None
        item["adapter_label"] = adapter["label"] if adapter else None
        item["adapter_desc"] = adapter["desc"] if adapter else None
        items.append(item)

    return jsonify({
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    })


@tools_bp.route("/<int:tid>", methods=["GET"])
@login_required
def get_tool(tid: int):
    db = get_db()
    row = db.execute("SELECT * FROM tools WHERE id=?", (tid,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "工具不存在"}), 404
    result = dict(row)
    result["api_key"] = _mask_api_key(result.get("api_key"))
    # 适配器信息
    adapter = _resolve_scanner_adapter(result["name"], result["tool_type"])
    result["has_adapter"] = adapter is not None
    result["adapter_label"] = adapter["label"] if adapter else None
    result["adapter_desc"] = adapter["desc"] if adapter else None
    db.close()
    return jsonify(result)


@tools_bp.route("/<int:tid>/knowledge", methods=["GET"])
@login_required
def tool_knowledge(tid: int):
    """获取与指定工具相关的知识库文章。"""
    db = get_db()
    tool = db.execute("SELECT * FROM tools WHERE id=?", (tid,)).fetchone()
    if not tool:
        db.close()
        return jsonify({"error": "工具不存在"}), 404

    tool_name = tool["name"]
    tool_type = tool["tool_type"]

    # 工具类型 → 知识库分类映射
    type_to_category = {
        "SAST": "web_security",
        "SCA": "supply_chain",
        "DAST": "web_security",
        "SECRET": "ops_process",
    }

    # 按工具名模糊匹配 + 按分类匹配
    rows = db.execute(
        """SELECT id, title, summary, category, tags, view_count, updated_at
           FROM knowledge_articles
           WHERE is_published = 1
             AND (
               title LIKE ? OR summary LIKE ? OR tags LIKE ?
               OR category = ?
             )
           ORDER BY view_count DESC LIMIT 8""",
        (
            f"%{tool_name}%",
            f"%{tool_name}%",
            f"%{tool_name}%",
            type_to_category.get(tool_type, "general"),
        ),
    ).fetchall()
    db.close()

    items = []
    for r in rows:
        item = dict(r)
        try:
            item["tags"] = json.loads(item["tags"]) if isinstance(item["tags"], str) else (item["tags"] or [])
        except Exception:
            item["tags"] = []
        items.append(item)

    return jsonify({"tool_name": tool_name, "tool_type": tool_type, "articles": items})


@tools_bp.route("", methods=["POST"])
@admin_required
def create_tool():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    tool_type = (data.get("tool_type") or "").strip()
    if not name or not tool_type:
        return jsonify({"error": "名称和类型不能为空"}), 400

    # 校验扫描适配器
    adapter = _resolve_scanner_adapter(name, tool_type)

    db = get_db()
    cur = db.execute(
        """INSERT INTO tools (name, tool_type, description, endpoint, api_key)
           VALUES (?,?,?,?,?)""",
        (name, tool_type, data.get("description", ""), data.get("endpoint", ""),
         data.get("api_key", ""))
    )
    db.commit()
    row = db.execute("SELECT * FROM tools WHERE id=?", (cur.lastrowid,)).fetchone()
    result = dict(row)
    result["has_adapter"] = adapter is not None
    result["adapter_label"] = adapter["label"] if adapter else None
    result["adapter_desc"] = adapter["desc"] if adapter else None
    db.close()
    return jsonify(result), 201


@tools_bp.route("/<int:tid>", methods=["PATCH"])
@admin_required
def update_tool(tid: int):
    db = get_db()
    row = db.execute("SELECT * FROM tools WHERE id=?", (tid,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "工具不存在"}), 404

    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled")
    if enabled is not None:
        db.execute("UPDATE tools SET enabled=? WHERE id=?", (1 if enabled else 0, tid))

    new_name = data.get("name", row["name"])
    if data.get("name"):
        db.execute("UPDATE tools SET name=? WHERE id=?", (data["name"], tid))
    if data.get("endpoint") is not None:
        db.execute("UPDATE tools SET endpoint=? WHERE id=?", (data["endpoint"], tid))
    if data.get("api_key") is not None:
        db.execute("UPDATE tools SET api_key=? WHERE id=?", (data["api_key"], tid))
    if data.get("description"):
        db.execute("UPDATE tools SET description=? WHERE id=?", (data["description"], tid))
    db.commit()

    updated = db.execute("SELECT * FROM tools WHERE id=?", (tid,)).fetchone()
    result = dict(updated)
    # 适配器信息
    adapter = _resolve_scanner_adapter(new_name, row["tool_type"])
    result["has_adapter"] = adapter is not None
    result["adapter_label"] = adapter["label"] if adapter else None
    result["adapter_desc"] = adapter["desc"] if adapter else None
    db.close()
    return jsonify(result)


@tools_bp.route("/<int:tid>", methods=["DELETE"])
@admin_required
def delete_tool(tid: int):
    db = get_db()
    if not db.execute("SELECT id FROM tools WHERE id=?", (tid,)).fetchone():
        db.close()
        return jsonify({"error": "工具不存在"}), 404
    db.execute("DELETE FROM tools WHERE id=?", (tid,))
    db.commit()
    db.close()
    return jsonify({"ok": True, "message": "工具已删除"})


@tools_bp.route("/<int:tid>/test", methods=["POST"])
@admin_required
def test_tool(tid: int):
    """真实连通性检测 — 对工具 endpoint 发起 HTTP HEAD 请求。"""
    db = get_db()
    row = db.execute("SELECT * FROM tools WHERE id=?", (tid,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "工具不存在"}), 404
    if not row["enabled"]:
        db.close()
        return jsonify({"ok": False, "message": "工具未启用"}), 400

    endpoint = (row["endpoint"] or "").strip()
    if not endpoint:
        db.close()
        return jsonify({"ok": False, "message": "未配置 API 端点"}), 400

    db.close()

    # 真实 HTTP 连通性检测
    import time
    try:
        req = urllib.request.Request(endpoint, method="HEAD")
        req.add_header("User-Agent", "Sentinel-Security/1.0")
        # 如配置了 api_key，通过 Authorization 头传递
        api_key = (row["api_key"] or "").strip()
        if api_key:
            req.add_header("Authorization", f"Bearer {api_key}")

        start = time.time()
        resp = urllib.request.urlopen(req, timeout=10)
        elapsed_ms = round((time.time() - start) * 1000)
        status = resp.status

        if 200 <= status < 400:
            return jsonify({
                "ok": True,
                "message": f"与 {row['name']} 连接成功 (HTTP {status})",
                "latency_ms": elapsed_ms,
                "status_code": status,
            })
        else:
            return jsonify({
                "ok": False,
                "message": f"连接 {row['name']} 返回状态码 {status}",
                "latency_ms": elapsed_ms,
                "status_code": status,
            }), 502
    except urllib.error.HTTPError as e:
        elapsed_ms = round((time.time() - start) * 1000)
        return jsonify({
            "ok": False,
            "message": f"连接 {row['name']} 失败：HTTP {e.code}",
            "latency_ms": elapsed_ms,
            "status_code": e.code,
        }), 502
    except urllib.error.URLError as e:
        return jsonify({
            "ok": False,
            "message": f"无法连接 {row['name']}：{e.reason}",
        }), 502
    except Exception as e:
        return jsonify({
            "ok": False,
            "message": f"连接测试异常：{str(e)}",
        }), 502
