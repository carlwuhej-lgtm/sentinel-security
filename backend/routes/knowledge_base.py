# ─── 知识库 API ───
"""
安全知识沉淀与复用
/api/knowledge-base/*
"""

from flask import Blueprint, request, jsonify
import json, datetime

knowledge_base_bp = Blueprint("knowledge_base", __name__)

from app import get_db
from routes.auth import login_required, admin_required
from routes.audit import audit_log


def _parse_tags(raw):
    """安全解析 tags 字段，兼容双层 JSON 编码等异常数据。

    正常值: ["xss"]           → json.loads → list ✅
    双层编码: "[\"xss\"]"      → json.loads → str → 再 json.loads → list ✅
    异常值: "just a string"    → fallback []
    None/空:                   → fallback []
    """
    if not raw:
        return []
    try:
        v = json.loads(raw)
        if isinstance(v, list):
            return v
        if isinstance(v, str) and v.startswith("["):
            return json.loads(v)  # 双层编码兜底
        return [str(v)] if v else []
    except (json.JSONDecodeError, TypeError, ValueError):
        # raw 本身可能就是非 JSON 的普通字符串，尝试简单分割
        if isinstance(raw, str) and "," in raw:
            return [t.strip().strip('"\'') for t in raw.split(",") if t.strip()]
        return []

CATEGORIES = {
    "web_security":    "Web 安全",
    "supply_chain":    "供应链安全",
    "data_security":   "数据安全",
    "ops_process":     "运维与流程",
    "tool_guide":      "工具指南",
    "incident_case":   "事件案例",
    "compliance":      "合规与标准",
    "general":         "综合",
}

# 工具类型 → 知识库分类自动映射
TOOL_TYPE_TO_CATEGORY = {
    "SAST":    "web_security",
    "DAST":    "web_security",
    "SCA":     "supply_chain",
    "SECRET":  "web_security",
    "IAST":    "web_security",
    "FUZZ":    "web_security",
    "CONTAINER": "ops_process",
}

# ══════════════════════════════════════════════
#  分类与标签概览
# ══════════════════════════════════════════════

@knowledge_base_bp.route("/meta", methods=["GET"])
@login_required
def get_meta():
    """返回全部分类和标签列表。"""
    db = get_db()
    try:
        # 按分类统计
        cat_rows = db.execute(
            "SELECT category, COUNT(*) as cnt FROM knowledge_articles WHERE is_published=1 GROUP BY category"
        ).fetchall()
        categories = [
            {"key": r["category"], "label": CATEGORIES.get(r["category"], r["category"]), "count": r["cnt"]}
            for r in cat_rows
        ]

        # 全部标签去重
        rows = db.execute("SELECT tags FROM knowledge_articles WHERE is_published=1").fetchall()
        tag_set = set()
        for r in rows:
            for t in _parse_tags(r["tags"]):
                tag_set.add(t.strip())
        tags = sorted(tag_set)

        return jsonify({"categories": categories, "tags": tags})
    finally:
        db.close()


# ══════════════════════════════════════════════
#  文章列表（搜索 + 筛选 + 分页）
# ══════════════════════════════════════════════

@knowledge_base_bp.route("", methods=["GET"])
@login_required
def list_articles():
    db = get_db()
    try:
        search   = request.args.get("search", "").strip()
        category = request.args.get("category", "").strip()
        tag      = request.args.get("tag", "").strip()
        sort     = request.args.get("sort", "updated_at")
        order    = request.args.get("order", "desc")
        page     = max(1, int(request.args.get("page", 1)))
        per_page = min(50, max(1, int(request.args.get("per_page", 20))))

        # 排序白名单
        ALLOWED_SORT = {"title", "category", "view_count", "created_at", "updated_at"}
        if sort not in ALLOWED_SORT:
            sort = "updated_at"
        safe_order = order.upper() if order.upper() in ("ASC", "DESC") else "DESC"

        q = "SELECT id, title, category, tags, author_id, view_count, summary, created_at, updated_at FROM knowledge_articles WHERE is_published=1"
        params = []

        if search:
            q += " AND (title LIKE ? OR content LIKE ? OR summary LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like, like])

        if category:
            q += " AND category=?"
            params.append(category)

        if tag:
            q += " AND tags LIKE ?"
            params.append(f'%"{tag}"%')

        # 计数
        count_q = q.replace(
            "SELECT id, title, category, tags, author_id, view_count, summary, created_at, updated_at",
            "SELECT COUNT(*)"
        )
        total = db.execute(count_q, params).fetchone()[0]

        q += f" ORDER BY {sort} {safe_order} LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])

        rows = db.execute(q, params).fetchall()
        items = []
        for r in rows:
            d = dict(r)
            d["tags"] = _parse_tags(d["tags"])
            d["category_label"] = CATEGORIES.get(d["category"], d["category"])
            # 关联作者名
            if d.get("author_id"):
                author = db.execute("SELECT name FROM users WHERE id=?", (d["author_id"],)).fetchone()
                d["author_name"] = author["name"] if author else ""
            else:
                d["author_name"] = ""
            items.append(d)

        return jsonify({
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": max(1, (total + per_page - 1) // per_page),
        })
    finally:
        db.close()


# ══════════════════════════════════════════════
#  热门文章
# ══════════════════════════════════════════════

@knowledge_base_bp.route("/popular", methods=["GET"])
@login_required
def popular_articles():
    db = get_db()
    try:
        rows = db.execute(
            "SELECT id, title, category, tags, view_count, summary FROM knowledge_articles WHERE is_published=1 ORDER BY view_count DESC LIMIT 8"
        ).fetchall()
        items = []
        for r in rows:
            d = dict(r)
            d["tags"] = _parse_tags(d["tags"])
            d["category_label"] = CATEGORIES.get(d["category"], d["category"])
            items.append(d)
        return jsonify(items)
    finally:
        db.close()


# ══════════════════════════════════════════════
#  最新文章
# ══════════════════════════════════════════════

@knowledge_base_bp.route("/recent", methods=["GET"])
@login_required
def recent_articles():
    db = get_db()
    try:
        rows = db.execute(
            "SELECT id, title, category, tags, view_count, summary, created_at FROM knowledge_articles WHERE is_published=1 ORDER BY created_at DESC LIMIT 8"
        ).fetchall()
        items = []
        for r in rows:
            d = dict(r)
            d["tags"] = _parse_tags(d["tags"])
            d["category_label"] = CATEGORIES.get(d["category"], d["category"])
            items.append(d)
        return jsonify(items)
    finally:
        db.close()


# ══════════════════════════════════════════════
#  文章详情
# ══════════════════════════════════════════════

@knowledge_base_bp.route("/<int:aid>", methods=["GET"])
@login_required
def get_article(aid):
    db = get_db()
    try:
        row = db.execute("SELECT * FROM knowledge_articles WHERE id=?", (aid,)).fetchone()
        if not row:
            return jsonify({"error": "文章不存在"}), 404

        # 浏览次数 +1
        db.execute("UPDATE knowledge_articles SET view_count = view_count + 1 WHERE id=?", (aid,))
        db.commit()

        d = dict(row)
        try:
            d["tags"] = _parse_tags(d["tags"])
        except (json.JSONDecodeError, TypeError):
            d["tags"] = []
        d["category_label"] = CATEGORIES.get(d["category"], d["category"])

        if d.get("author_id"):
            author = db.execute("SELECT name FROM users WHERE id=?", (d["author_id"],)).fetchone()
            d["author_name"] = author["name"] if author else ""
        else:
            d["author_name"] = ""

        return jsonify(d)
    finally:
        db.close()


# ══════════════════════════════════════════════
#  创建文章
# ══════════════════════════════════════════════

@knowledge_base_bp.route("", methods=["POST"])
@login_required
def create_article():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "标题不能为空"}), 400

    content  = data.get("content", "")
    category = data.get("category", "general")
    if category not in CATEGORIES:
        category = "general"
    tags     = json.dumps(data.get("tags", []), ensure_ascii=False)
    summary  = (data.get("summary") or "").strip()
    if not summary and content:
        # 自动从 content 截取摘要
        import re
        plain = re.sub(r"[#*`\[\]\(\)!\-><|]", "", content)[:200]
        summary = plain.strip()
    is_published = int(data.get("is_published", True))
    author_id = request.current_user_id

    db = get_db()
    try:
        cur = db.execute(
            """INSERT INTO knowledge_articles
               (title, content, category, tags, author_id, summary, is_published)
               VALUES (?,?,?,?,?,?,?)""",
            (title, content, category, tags, author_id, summary, is_published),
        )
        db.commit()

        new_id = cur.lastrowid
        row = db.execute("SELECT * FROM knowledge_articles WHERE id=?", (new_id,)).fetchone()
        d = dict(row)
        try:
            d["tags"] = _parse_tags(d["tags"])
        except (json.JSONDecodeError, TypeError):
            d["tags"] = []

        audit_log(
            author_id, "",
            "kb.create", "knowledge_article", new_id,
            f"创建知识库文章: {title}",
        )

        return jsonify(d), 201
    finally:
        db.close()


# ══════════════════════════════════════════════
#  更新文章
# ══════════════════════════════════════════════

@knowledge_base_bp.route("/<int:aid>", methods=["PUT"])
@login_required
def update_article(aid):
    data = request.get_json(silent=True) or {}
    db = get_db()
    try:
        existing = db.execute("SELECT id, title FROM knowledge_articles WHERE id=?", (aid,)).fetchone()
        if not existing:
            return jsonify({"error": "文章不存在"}), 404

        updatable = ["title", "content", "category", "tags", "summary", "is_published"]
        sets = []
        vals = []
        for k in updatable:
            if k in data:
                v = data[k]
                if k == "tags" and isinstance(v, list):
                    v = json.dumps(v, ensure_ascii=False)
                if k == "category" and v not in CATEGORIES:
                    v = "general"
                sets.append(f"{k}=?")
                vals.append(v)

        if sets:
            vals.append(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            sets.append("updated_at=?")
            vals.append(aid)
            db.execute(f"UPDATE knowledge_articles SET {','.join(sets)} WHERE id=?", vals)
            db.commit()

        row = db.execute("SELECT * FROM knowledge_articles WHERE id=?", (aid,)).fetchone()
        d = dict(row)
        try:
            d["tags"] = _parse_tags(d["tags"])
        except (json.JSONDecodeError, TypeError):
            d["tags"] = []

        audit_log(
            request.current_user_id, "",
            "kb.update", "knowledge_article", aid,
            f"更新知识库文章: {existing['title']}",
        )

        return jsonify(d)
    finally:
        db.close()


# ══════════════════════════════════════════════
#  删除文章
# ══════════════════════════════════════════════

@knowledge_base_bp.route("/<int:aid>", methods=["DELETE"])
@admin_required
def delete_article(aid):
    db = get_db()
    try:
        row = db.execute("SELECT id, title FROM knowledge_articles WHERE id=?", (aid,)).fetchone()
        if not row:
            return jsonify({"error": "文章不存在"}), 404

        db.execute("DELETE FROM knowledge_articles WHERE id=?", (aid,))
        db.commit()

        audit_log(
            request.current_user_id, "",
            "kb.delete", "knowledge_article", aid,
            f"删除知识库文章: {row['title']}",
        )

        return jsonify({"message": "已删除", "id": aid})
    finally:
        db.close()


# ══════════════════════════════════════════════
#  关联漏洞 — 查找与指定漏洞相关的知识库
# ══════════════════════════════════════════════

@knowledge_base_bp.route("/related/<int:vid>", methods=["GET"])
@login_required
def related_articles(vid):
    """根据漏洞的标题/描述/CWE 搜索相关知识库文章。"""
    db = get_db()
    try:
        vuln = db.execute("SELECT title, severity, cwe_id FROM vulnerabilities WHERE id=?", (vid,)).fetchone()
        if not vuln:
            return jsonify({"error": "漏洞不存在"}), 404

        search_terms = []
        if vuln["title"]:
            search_terms.append(vuln["title"])
        if vuln["cwe_id"]:
            search_terms.append(vuln["cwe_id"])

        if not search_terms:
            return jsonify([])

        results = []
        for term in search_terms:
            rows = db.execute(
                "SELECT id, title, category, summary FROM knowledge_articles WHERE is_published=1 AND (title LIKE ? OR content LIKE ?) ORDER BY updated_at DESC LIMIT 5",
                (f"%{term}%", f"%{term}%"),
            ).fetchall()
            for r in rows:
                if r["id"] not in {x["id"] for x in results}:
                    d = dict(r)
                    d["category_label"] = CATEGORIES.get(d["category"], d["category"])
                    results.append(d)

        return jsonify(results[:10])
    finally:
        db.close()


# ══════════════════════════════════════════════
#  漏洞统计 — 知识库编辑器关联展示
# ══════════════════════════════════════════════

@knowledge_base_bp.route("/vuln-stats", methods=["GET"])
@login_required
def vuln_stats():
    """获取系统中与指定 CWE / 关键词相关的漏洞统计。
    可选参数: cwe_ids（逗号分隔）, keywords（逗号分隔）, category
    返回各严重级别 + 待处理状态的漏洞数量。
    """
    cwe_ids_param = request.args.get("cwe_ids", "")
    keywords_param = request.args.get("keywords", "")
    category_param = request.args.get("category", "")

    db = get_db()
    try:
        where_parts = ["v.status IN ('open', 'in_progress')"]
        params: list = []

        # CWE ID 匹配
        cwe_ids = [c.strip() for c in cwe_ids_param.split(",") if c.strip()]
        if cwe_ids:
            placeholders = ",".join("?" for _ in cwe_ids)
            where_parts.append(f"v.cwe_id IN ({placeholders})")
            params.extend(cwe_ids)

        # 关键词匹配
        keywords = [k.strip() for k in keywords_param.split(",") if k.strip()]
        if keywords:
            keyword_clauses = []
            for kw in keywords:
                keyword_clauses.append("(v.title LIKE ? OR v.description LIKE ?)")
                params.extend([f"%{kw}%", f"%{kw}%"])
            where_parts.append("(" + " OR ".join(keyword_clauses) + ")")

        # 按知识库分类映射 CWE/Severity 过滤
        category_to_severity = {
            "web_security": ("CRITICAL", "HIGH", "MEDIUM"),
            "supply_chain": ("HIGH", "MEDIUM"),
            "data_security": ("CRITICAL", "HIGH"),
            "ops_process": ("MEDIUM", "LOW"),
        }

        where_clause = " AND ".join(where_parts)

        # 按严重级别统计
        severities = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        stats_by_severity = {}
        for sev in severities:
            count = db.execute(
                f"SELECT COUNT(*) FROM vulnerabilities v WHERE {where_clause} AND v.severity = ?",
                tuple(params) + (sev,),
            ).fetchone()[0]
            stats_by_severity[sev.lower()] = count

        total = sum(stats_by_severity.values())

        # 按 source_tool 统计
        tool_rows = db.execute(
            f"SELECT v.source_tool, COUNT(*) as cnt FROM vulnerabilities v WHERE {where_clause} GROUP BY v.source_tool ORDER BY cnt DESC",
            tuple(params),
        ).fetchall()
        by_tool = {r["source_tool"] or "unknown": r["cnt"] for r in tool_rows}

        # Top CWE
        cwe_rows = db.execute(
            f"SELECT v.cwe_id, COUNT(*) as cnt FROM vulnerabilities v WHERE {where_clause} AND v.cwe_id != '' GROUP BY v.cwe_id ORDER BY cnt DESC LIMIT 10",
            tuple(params),
        ).fetchall()

        return jsonify({
            "total": total,
            "by_severity": stats_by_severity,
            "by_tool": by_tool,
            "top_cwe": [{"cwe_id": r["cwe_id"], "count": r["cnt"]} for r in cwe_rows],
        })
    finally:
        db.close()


# ══════════════════════════════════════════════
#  推荐撰写 — 高频漏洞但无知识库沉淀
# ══════════════════════════════════════════════

@knowledge_base_bp.route("/recommendations", methods=["GET"])
@login_required
def writing_recommendations():
    """查找系统中高频出现但知识库尚未覆盖的漏洞类型，推荐撰写文章。"""
    db = get_db()
    try:
        days = max(1, min(90, int(request.args.get("days", 30))))

        # 1. 收集近 N 天的高频 CWE（status IN open/in_progress/remediated）
        cwe_rows = db.execute(
            """SELECT cwe_id, severity, COUNT(*) as cnt, 
                      MAX(created_at) as last_seen
               FROM vulnerabilities 
               WHERE cwe_id != '' 
                 AND cwe_id IS NOT NULL
                 AND created_at >= date('now', ? || ' days')
               GROUP BY cwe_id 
               HAVING cnt >= 2
               ORDER BY cnt DESC""",
            (f"-{days}",),
        ).fetchall()

        if not cwe_rows:
            return jsonify({"recommendations": [], "hint": "近期没有足够数据"})

        # 2. 检查哪些 CWE 已经有知识库文章
        kb_cwe_set = set()
        all_articles = db.execute(
            "SELECT title, content, tags FROM knowledge_articles WHERE is_published=1"
        ).fetchall()
        for a in all_articles:
            text = (a["title"] or "") + " " + (a["content"] or "")
            text += " " + " ".join(_parse_tags(a["tags"]))
            text_lower = text.lower()
            # 检查是否被已有文章覆盖（标题/内容/标签中提到 CWE）
            for r in cwe_rows:
                cwe = r["cwe_id"]
                if cwe.upper().replace("-", "") in text_lower.replace("-", ""):
                    kb_cwe_set.add(cwe)

        # 3. 生成推荐列表（未覆盖的）
        recommendations = []
        for r in cwe_rows:
            if r["cwe_id"] in kb_cwe_set:
                continue
            recommendations.append({
                "cwe_id": r["cwe_id"],
                "severity": r["severity"],
                "count": r["cnt"],
                "last_seen": r["last_seen"],
            })
            if len(recommendations) >= 6:
                break

        return jsonify({
            "recommendations": recommendations,
            "total_covered": len(kb_cwe_set),
            "total_uncovered": len(recommendations),
            "days": days,
        })
    finally:
        db.close()
