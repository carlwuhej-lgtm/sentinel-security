# ─── 规则管理 API ───
"""
规则 CRUD + 忽略/白名单 + 自定义扫描规则
/api/rules/*
"""

from flask import Blueprint, request, jsonify
import json, datetime

rules_bp = Blueprint("rules", __name__)

from app import get_db
from routes.auth import login_required, admin_required
from routes.audit import audit_rule_op, audit_rule_toggle


# ══════════════════════════════════════════════
#  工具
# ══════════════════════════════════════════════

def _row_to_dict(row):
    d = dict(row)
    # JSON 字段自动解析
    for f in ("severity_filter", "tech_stack"):
        if f in d and isinstance(d[f], str) and d[f]:
            try:
                d[f] = json.loads(d[f])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


# ══════════════════════════════════════════════
#  规则列表（支持筛选）
# ══════════════════════════════════════════════

@rules_bp.route("", methods=["GET"])
@login_required
def list_rules():
    db = get_db()
    try:
        rule_type = request.args.get("type", "")      # custom_scan / ignore
        category = request.args.get("category", "")    # sast / sca / secret / ...
        enabled   = request.args.get("enabled", "")    # "1" / "0" / ""
        project_id = request.args.get("project_id", "")
        scope     = request.args.get("scope", "")
        sort      = request.args.get("sort", "created_at")
        order     = request.args.get("order", "desc")

        # H-02 修复: sort 参数白名单校验
        ALLOWED_SORT = {"name", "rule_type", "category", "enabled", "created_at", "updated_at", "scope"}
        if sort not in ALLOWED_SORT:
            sort = "created_at"
        safe_order = order.upper() if order.upper() in ("ASC", "DESC") else "DESC"

        q = "SELECT * FROM rules WHERE 1=1"
        params = []
        if rule_type:
            q += " AND rule_type=?"
            params.append(rule_type)
        if category:
            q += " AND category=?"
            params.append(category)
        if enabled != "":
            q += " AND enabled=?"
            params.append(int(enabled))
        if project_id:
            q += " AND project_id=?"
            params.append(int(project_id))
        elif scope == "global":
            q += " AND scope='global'"
        q += f" ORDER BY {sort} {safe_order}"

        rows = db.execute(q, params).fetchall()
        result = [_row_to_dict(r) for r in rows]

        # 统计摘要
        total = len(result)
        enabled_count = sum(1 for r in result if r["enabled"])

        return jsonify({
            "items": result,
            "total": total,
            "enabled": enabled_count,
            "disabled": total - enabled_count,
        })
    finally:
        db.close()


@rules_bp.route("/stats", methods=["GET"])
@login_required
def rule_stats():
    db = get_db()
    try:
        by_type = db.execute("""
            SELECT rule_type, COUNT(*) as cnt FROM rules GROUP BY rule_type
        """).fetchall()

        by_category = db.execute("""
            SELECT category, COUNT(*) as cnt FROM rules WHERE enabled=1 GROUP BY category
        """).fetchall()

        return jsonify({
            "total_rules": db.execute("SELECT COUNT(*) FROM rules").fetchone()[0],
            "enabled_rules": db.execute("SELECT COUNT(*) FROM rules WHERE enabled=1").fetchone()[0],
            "ignore_rules": db.execute("SELECT COUNT(*) FROM rules WHERE rule_type='ignore'").fetchone()[0],
            "custom_scan_rules": db.execute("SELECT COUNT(*) FROM rules WHERE rule_type='custom_scan'").fetchone()[0],
            "by_type": [dict(r) for r in by_type],
            "by_category": [dict(r) for r in by_category],
        })
    finally:
        db.close()


# ══════════════════════════════════════════════
#  创建规则
# ══════════════════════════════════════════════

@rules_bp.route("", methods=["POST"])
@admin_required
def create_rule():
    data = request.get_json(silent=True) or {}
    required = ("name", "rule_type")
    for f in required:
        if not data.get(f):
            return jsonify({"error": f"缺少必填字段: {f}"}), 400

    user_id = request.current_user_id
    db = get_db()
    try:
        cur = db.execute(
            """INSERT INTO rules
               (name, rule_type, category, pattern, severity_filter,
                description, enabled, scope, project_id, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                data["name"].strip(),
                data["rule_type"],
                data.get("category", "generic"),
                data.get("pattern", ""),
                json.dumps(data.get("severity_filter", ["critical","high","medium","low"]), ensure_ascii=False),
                data.get("description", ""),
                int(data.get("enabled", True)),
                data.get("scope", "global"),
                data.get("project_id"),
                user_id,
            )
        )
        db.commit()
        rid = cur.lastrowid
        rule = db.execute("SELECT * FROM rules WHERE id=?", (rid,)).fetchone()
        audit_rule_op(user_id, "create", rid, data["name"].strip())
        return jsonify(_row_to_dict(rule)), 201
    finally:
        db.close()


# ══════════════════════════════════════════════
#  单条规则详情 / 更新 / 删除
# ══════════════════════════════════════════════

@rules_bp.route("/<int:rid>", methods=["GET"])
@login_required
def get_rule(rid):
    db = get_db()
    try:
        row = db.execute("SELECT * FROM rules WHERE id=?", (rid,)).fetchone()
        if not row:
            return jsonify({"error": "规则不存在"}), 404
        return jsonify(_row_to_dict(row))
    finally:
        db.close()


@rules_bp.route("/<int:rid>", methods=["PUT"])
@admin_required
def update_rule(rid):
    data = request.get_json(silent=True) or {}
    db = get_db()
    try:
        existing = db.execute("SELECT id FROM rules WHERE id=?", (rid,)).fetchone()
        if not existing:
            return jsonify({"error": "规则不存在"}), 404

        updatable = ["name","rule_type","category","pattern","severity_filter",
                     "description","enabled","scope","project_id"]
        sets = []
        vals = []
        for k in updatable:
            if k in data:
                v = data[k]
                if k in ("severity_filter",) and isinstance(v, list):
                    v = json.dumps(v, ensure_ascii=False)
                sets.append(f"{k}=?")
                vals.append(v)

        if sets:
            vals.append(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            sets.append("updated_at=?")
            vals.append(rid)
            db.execute(f"UPDATE rules SET {','.join(sets)} WHERE id=?", vals)
            db.commit()

        row = db.execute("SELECT * FROM rules WHERE id=?", (rid,)).fetchone()
        audit_rule_op(request.current_user_id, "update", rid,
                      row["name"], extra=",".join(k for k in data if k in updatable))
        return jsonify(_row_to_dict(row))
    finally:
        db.close()


@rules_bp.route("/<int:rid>", methods=["DELETE"])
@admin_required
def delete_rule(rid):
    db = get_db()
    try:
        row = db.execute("SELECT id, name FROM rules WHERE id=?", (rid,)).fetchone()
        if not row:
            return jsonify({"error": "规则不存在"}), 404
        db.execute("DELETE FROM rules WHERE id=?", (rid,))
        db.commit()
        audit_rule_op(request.current_user_id, "delete", rid, row["name"])
        return jsonify({"message": "已删除", "id": rid})
    finally:
        db.close()


@rules_bp.route("/<int:rid>/toggle", methods=["POST"])
@admin_required
def toggle_rule(rid):
    db = get_db()
    try:
        row = db.execute("SELECT name, enabled FROM rules WHERE id=?", (rid,)).fetchone()
        if not row:
            return jsonify({"error": "规则不存在"}), 404
        new_val = 0 if row["enabled"] else 1
        db.execute("UPDATE rules SET enabled=?, updated_at=? WHERE id=?",
                   (new_val, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), rid))
        db.commit()
        audit_rule_toggle(request.current_user_id, rid, row["name"], bool(new_val))
        return jsonify({"id": rid, "enabled": bool(new_val)})
    finally:
        db.close()
