# ─── 资产管理 API ───
"""
资产发现 + 清单 + 风险评分
/api/assets/*
"""

from flask import Blueprint, request, jsonify, Response
import json, datetime, re, csv, io

assets_bp = Blueprint("assets", __name__)

from app import get_db
from routes.auth import login_required, admin_required
from routes.audit import audit_asset_op, audit_asset_sync, audit_asset_recalc_risk

# 风险等级阈值
RISK_THRESHOLDS = {"critical": 80, "high": 60, "medium": 35, "low": 10}


def _row_to_dict(row):
    d = dict(row)
    if isinstance(d.get("tech_stack"), str) and d["tech_stack"]:
        try:
            d["tech_stack"] = json.loads(d["tech_stack"])
        except (json.JSONDecodeError, TypeError):
            pass
    return d


def _calc_risk_score(asset: dict) -> tuple:
    """根据漏洞数量、扫描频率、环境等因素计算风险分。返回 (score, level)。"""
    score = 0.0

    # 漏洞因子（权重最高）
    open_vulns = asset.get("last_vuln_count", 0) or 0
    if open_vulns > 10:
        score += 40
    elif open_vulns > 5:
        score += 28
    elif open_vulns > 2:
        score += 16
    elif open_vulns >= 1:
        score += 8

    # 环境因子
    env = asset.get("environment", "unknown")
    if env == "production" or env == "prod":
        score += 25
    elif env == "staging":
        score += 12

    # 资产类型因子
    atype = asset.get("asset_type", "")
    if atype in ("web_api",):
        score += 15
    elif atype in ("infrastructure",):
        score += 20

    # 扫描时效（超过 30 天未扫描加分）
    last_scan = asset.get("last_scan_date", "")
    if last_scan:
        try:
            from datetime import datetime as dt
            days_ago = (dt.now() - dt.strptime(last_scan[:19], "%Y-%m-%d %H:%M:%S")).days
            if days_ago > 90:
                score += 20
            elif days_ago > 30:
                score += 10
        except Exception:
            pass
    else:
        score += 15  # 从未扫描

    # 归一化到 0-100
    score = min(100.0, max(0.0, round(score)))

    for lvl, thresh in RISK_THRESHOLDS.items():
        if score >= thresh:
            return (score, lvl)
    return (score, "info")


@assets_bp.route("", methods=["GET"])
@login_required
def list_assets():
    db = get_db()
    try:
        atype     = request.args.get("type", "")
        risk_level = request.args.get("risk_level", "")
        status    = request.args.get("status", "")
        search    = request.args.get("search", "").strip()
        sort      = request.args.get("sort", "updated_at")
        order     = request.args.get("order", "desc")

        # H-02 修复: sort 参数白名单校验，防止 SQL 注入
        ALLOWED_SORT = {
            "name", "asset_type", "risk_score", "risk_level",
            "created_at", "updated_at", "status", "last_scan_date",
            "last_vuln_count",
        }
        if sort not in ALLOWED_SORT:
            sort = "updated_at"

        q = "SELECT * FROM assets WHERE 1=1"
        p = []
        if atype:
            q += " AND asset_type=?"; p.append(atype)
        if risk_level:
            q += " AND risk_level=?"; p.append(risk_level)
        if status:
            q += " AND status=?"; p.append(status)
        if search:
            q += " AND (name LIKE ? OR owner LIKE ? OR description LIKE ?)"
            kw = f"%{search}%"
            p.extend([kw, kw, kw])

        safe_order = order.upper() if order.upper() in ("ASC","DESC") else "DESC"
        q += f" ORDER BY {sort} {safe_order}"

        rows = db.execute(q, p).fetchall()
        items = [_row_to_dict(r) for r in rows]

        # 统计摘要
        stats = {
            "total": len(items),
            "by_type": {},
            "by_risk": {},
            "by_env": {},
        }
        for a in items:
            t = a["asset_type"]
            stats["by_type"][t] = stats["by_type"].get(t, 0) + 1
            r = a["risk_level"]
            stats["by_risk"][r] = stats["by_risk"].get(r, 0) + 1
            e = a.get("environment","unknown")
            stats["by_env"][e] = stats["by_env"].get(e, 0) + 1

        return jsonify({"items": items, **stats})
    finally:
        db.close()


@assets_bp.route("/stats", methods=["GET"])
@login_required
def asset_stats():
    db = get_db()
    try:
        total = db.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        active = db.execute("SELECT COUNT(*) FROM assets WHERE status='active'").fetchone()[0]
        high_risk = db.execute("SELECT COUNT(*) FROM assets WHERE risk_level IN ('critical','high')").fetchone()[0]

        # 各风险等级分布 → 转为 {critical:N, high:N, ...} 格式供前端直接用
        by_risk_rows = db.execute("""
            SELECT risk_level, COUNT(*) as cnt FROM assets GROUP BY risk_level ORDER BY
                CASE risk_level WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
        """).fetchall()
        by_risk = {r["risk_level"]: r["cnt"] for r in by_risk_rows}

        # 各类型分布 → 同上
        by_type_rows = db.execute("SELECT asset_type, COUNT(*) as cnt FROM assets GROUP BY asset_type").fetchall()
        by_type = {r["asset_type"]: r["cnt"] for r in by_type_rows}

        # 总开放漏洞数
        total_open_vulns = db.execute("""
            SELECT COALESCE(SUM(last_vuln_count), 0) FROM assets WHERE status='active'
        """).fetchone()[0]

        return jsonify({
            "total_assets": total,
            "active_assets": active,
            "high_risk_assets": high_risk,
            "avg_risk_score": round(
                db.execute("SELECT COALESCE(AVG(risk_score), 0) FROM assets").fetchone()[0], 1),
            "total_open_vulns": total_open_vulns,
            "by_risk": by_risk,
            "by_type": by_type,
        })
    finally:
        db.close()


@assets_bp.route("/<int:aid>", methods=["GET"])
@login_required
def get_asset(aid):
    db = get_db()
    try:
        row = db.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
        if not row:
            return jsonify({"error": "资产不存在"}), 404
        asset = _row_to_dict(row)

        # 关联的最近扫描记录
        scans = db.execute("""
            SELECT s.id, s.tool_type, s.status, s.vuln_count,
                   s.started_at, s.finished_at
            FROM scan_tasks s
            WHERE s.project_id = ?
            ORDER BY s.created_at DESC LIMIT 5
        """, (asset.get("project_id"),)).fetchall()
        asset["recent_scans"] = [dict(s) for s in scans]

        # 关联的开放漏洞
        vulns = db.execute("""
            SELECT v.id, v.cve_id, v.title, v.severity, v.cvss_score, v.file_path,
                   v.created_at, v.sla_due_date, v.sla_breached
            FROM vulnerabilities v
            JOIN scan_tasks s ON s.id = v.scan_id
            WHERE s.project_id = ? AND v.status = 'open'
            ORDER BY v.severity DESC LIMIT 20
        """, (asset.get("project_id"),)).fetchall()
        asset["open_vulnerabilities"] = [dict(v) for v in vulns]

        return jsonify(asset)
    finally:
        db.close()


@assets_bp.route("", methods=["POST"])
@admin_required
def create_asset():
    data = request.get_json(silent=True) or {}
    if not data.get("name"):
        return jsonify({"error": "缺少资产名称"}), 400

    tech_stack = json.dumps(data.get("tech_stack", []), ensure_ascii=False)
    db = get_db()
    try:
        # 计算初始风险分
        temp_asset = {
            "last_vuln_count": 0,
            "environment": data.get("environment", "unknown"),
            "asset_type": data.get("asset_type", "web_api"),
            "last_scan_date": "",
        }
        score, level = _calc_risk_score(temp_asset)

        cur = db.execute(
            """INSERT INTO assets
               (name, asset_type, project_id, tech_stack, environment,
                owner, owner_email, risk_score, risk_level, status, description)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                data["name"].strip(),
                data.get("asset_type", "web_api"),
                data.get("project_id"),
                tech_stack,
                data.get("environment", "unknown"),
                data.get("owner", ""),
                data.get("owner_email", ""),
                score,
                level,
                data.get("status", "active"),
                data.get("description", ""),
            )
        )
        db.commit()
        aid = cur.lastrowid
        row = db.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
        audit_asset_op(request.current_user_id, "create", aid, data["name"].strip())
        return jsonify(_row_to_dict(row)), 201
    finally:
        db.close()


@assets_bp.route("/<int:aid>", methods=["PUT"])
@admin_required
def update_asset(aid):
    data = request.get_json(silent=True) or {}
    db = get_db()
    try:
        existing = db.execute("SELECT id FROM assets WHERE id=?", (aid,)).fetchone()
        if not existing:
            return jsonify({"error": "资产不存在"}), 404

        updatable = ["name","asset_type","project_id","tech_stack","environment",
                     "owner","owner_email","status","description"]
        sets, vals = [], []
        for k in updatable:
            if k in data:
                v = data[k]
                if k == "tech_stack" and isinstance(v, list):
                    v = json.dumps(v, ensure_ascii=False)
                sets.append(f"{k}=?")
                vals.append(v)

        if sets:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            sets.append("updated_at=?")
            vals.append(now)
            vals.append(aid)
            db.execute(f"UPDATE assets SET {','.join(sets)} WHERE id=?", vals)

            # 更新后重新计算风险分
            full = dict(db.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone())
            new_score, new_level = _calc_risk_score(full)
            db.execute("UPDATE assets SET risk_score=?, risk_level=? WHERE id=?",
                       (new_score, new_level, aid))

        db.commit()
        row = db.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
        audit_asset_op(request.current_user_id, "update", aid, data.get("name", row["name"]),
                       extra=",".join(k for k in data if k in updatable and k not in ("tech_stack",)))
        return jsonify(_row_to_dict(row))
    finally:
        db.close()


@assets_bp.route("/<int:aid>", methods=["DELETE"])
@admin_required
def delete_asset(aid):
    db = get_db()
    try:
        row = db.execute("SELECT id, name FROM assets WHERE id=?", (aid,)).fetchone()
        if not row:
            return jsonify({"error": "资产不存在"}), 404
        db.execute("DELETE FROM assets WHERE id=?", (aid,))
        db.commit()
        audit_asset_op(request.current_user_id, "delete", aid, row["name"])
        return jsonify({"message": "已删除", "id": aid})
    finally:
        db.close()


@assets_bp.route("/<int:aid>/recalc-risk", methods=["POST"])
@admin_required
def recalc_risk(aid):
    """手动触发重新计算某个资产的风险分。"""
    db = get_db()
    try:
        row = db.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
        if not row:
            return jsonify({"error": "资产不存在"}), 404
        asset = _row_to_dict(row)
        score, level = _calc_risk_score(asset)
        db.execute("UPDATE assets SET risk_score=?, risk_level=?, updated_at=? WHERE id=?",
                   (score, level, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), aid))
        db.commit()
        audit_asset_recalc_risk(request.current_user_id, aid, asset["name"], score, level)
        return jsonify({"id": aid, "risk_score": score, "risk_level": level})
    finally:
        db.close()


@assets_bp.route("/sync-from-projects", methods=["POST"])
@admin_required
def sync_from_projects():
    """从 projects 表同步/更新资产清单，自动创建新项目对应的资产条目。"""
    db = get_db()
    try:
        projects = db.execute("SELECT * FROM projects").fetchall()
        created = 0
        updated = 0

        for proj in (dict(p) for p in projects):
            existing = db.execute(
                "SELECT id, name, risk_score FROM assets WHERE project_id=?",
                (proj["id"],)
            ).fetchone()

            # 重新计算当前漏洞数
            vuln_cnt = db.execute("""
                SELECT COUNT(*) FROM vulnerabilities v
                JOIN scan_tasks s ON s.id=v.scan_id
                WHERE s.project_id=? AND v.status='open'
            """, (proj["id"],)).fetchone()[0]

            if not existing:
                score = 25 + min(50, vuln_cnt * 7)
                level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
                db.execute(
                    """INSERT INTO assets (name, asset_type, project_id, tech_stack,
                       environment, owner, risk_score, risk_level, last_vuln_count, last_scan_date)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (proj["name"],
                     "web_api" if proj["project_type"] in ("web","api") else "microservice",
                     proj["id"], json.dumps([proj["language"]] if proj.get("language") else []),
                     "unknown", "system", score, level, vuln_cnt,
                     datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )
                created += 1
            else:
                db.execute(
                    "UPDATE assets SET last_vuln_count=?, last_scan_date=?, updated_at=? WHERE id=?",
                    (vuln_cnt, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), existing["id"])
                )
                updated += 1

        db.commit()
        audit_asset_sync(request.current_user_id, created, updated)
        return jsonify({
            "message": "同步完成",
            "created": created,
            "updated": updated,
            "total_projects": len(list(projects)),
        })
    finally:
        db.close()


# ─── CSV 导出 ───
EXPORT_COLUMNS = [
    "id", "name", "asset_type", "project_id", "tech_stack", "environment",
    "owner", "owner_email", "risk_score", "risk_level", "status",
    "last_vuln_count", "last_scan_date", "description", "created_at", "updated_at",
]


@assets_bp.route("/export", methods=["GET"])
@login_required
def export_assets_csv():
    """导出全部资产为 CSV（UTF-8-SIG，Excel 直接打开中文不乱码）。"""
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM assets ORDER BY id").fetchall()
    finally:
        db.close()

    buf = io.StringIO()
    buf.write("\ufeff")  # BOM，保证 Excel 正确识别 UTF-8 中文
    writer = csv.DictWriter(buf, fieldnames=EXPORT_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        d = dict(r)
        ts = d.get("tech_stack")
        if isinstance(ts, str) and ts:
            try:
                d["tech_stack"] = "、".join(json.loads(ts))
            except (json.JSONDecodeError, TypeError):
                pass
        writer.writerow(d)

    return Response(
        buf.getvalue().encode("utf-8-sig"),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=assets_export.csv"},
    )


# ─── CSV 导入（仅管理员） ───
@assets_bp.route("/import", methods=["POST"])
@admin_required
def import_assets_csv():
    """从 CSV 批量导入资产。要求 multipart/form-data，字段名 file。

    列名兼容 /export 输出：name(必填), asset_type, project_id, tech_stack,
    environment, owner, owner_email, risk_score, risk_level, status, description。
    """
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "缺少上传文件（字段名应为 file）"}), 400

    try:
        raw = f.read().decode("utf-8-sig")
    except Exception:
        try:
            raw = f.read().decode("utf-8")
        except Exception:
            return jsonify({"error": "文件编码无法识别，请使用 UTF-8 编码的 CSV"}), 400

    reader = csv.DictReader(io.StringIO(raw))
    db = get_db()
    created = 0
    skipped = 0
    try:
        for lineno, row in enumerate(reader, start=2):  # 表头为第 1 行
            name = (row.get("name") or "").strip()
            if not name:
                skipped += 1
                continue

            asset_type = (row.get("asset_type") or "web_api").strip() or "web_api"
            environment = (row.get("environment") or "unknown").strip() or "unknown"
            status = (row.get("status") or "active").strip() or "active"

            ts_raw = (row.get("tech_stack") or "").strip()
            if ts_raw.startswith("["):
                try:
                    tech_stack = json.loads(ts_raw)
                except json.JSONDecodeError:
                    tech_stack = []
            else:
                tech_stack = [x.strip() for x in ts_raw.split("、") if x.strip()]

            pid_raw = (row.get("project_id") or "").strip()
            project_id = int(pid_raw) if pid_raw.isdigit() else None

            # 风险分：优先用 CSV 提供值，否则按规则计算
            score, level = _calc_risk_score({
                "last_vuln_count": 0, "environment": environment,
                "asset_type": asset_type, "last_scan_date": "",
            })
            rs = (row.get("risk_score") or "").strip()
            rl = (row.get("risk_level") or "").strip()
            try:
                risk_score = float(rs) if rs else score
                risk_level = rl or level
            except (ValueError, TypeError):
                risk_score, risk_level = score, level

            db.execute(
                """INSERT INTO assets
                   (name, asset_type, project_id, tech_stack, environment,
                    owner, owner_email, risk_score, risk_level, status, description)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (name, asset_type, project_id, json.dumps(tech_stack, ensure_ascii=False),
                 environment, (row.get("owner") or "").strip(),
                 (row.get("owner_email") or "").strip(), risk_score, risk_level,
                 status, (row.get("description") or "").strip()),
            )
            created += 1

        db.commit()
    except Exception as e:
        db.rollback()
        return jsonify({"error": f"导入失败：{e}"}), 500
    finally:
        db.close()

    audit_asset_op(request.current_user_id, "import_csv", 0, f"批量导入 {created} 条（跳过 {skipped} 条空行）")
    return jsonify({"message": "导入完成", "created": created, "skipped": skipped})
