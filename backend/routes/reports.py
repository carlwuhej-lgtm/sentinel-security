# ─── 报告导出 API ───
"""
安全报告生成 / 导出 / 历史
/api/reports/*
"""

from flask import Blueprint, request, jsonify, send_file
import json, datetime, os, io

reports_bp = Blueprint("reports", __name__)

from app import get_db
from routes.auth import login_required, admin_required
from routes.audit import audit_report_gen, audit_report_delete, audit_report_download


def _row_to_dict(row):
    d = dict(row)
    for f in ("filters_json", "content_json"):
        if f in d and isinstance(d[f], str) and d[f]:
            try:
                d[f] = json.loads(d[f])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


@reports_bp.route("", methods=["GET"])
@login_required
def list_reports():
    """报告历史列表。"""
    db = get_db()
    try:
        rtype = request.args.get("type", "")
        limit = min(int(request.args.get("limit", "20")), 100)

        q = "SELECT r.*, u.name as generator_name FROM reports r LEFT JOIN users u ON u.id=r.generated_by WHERE 1=1"
        p = []
        if rtype:
            q += " AND r.report_type=?"; p.append(rtype)
        q += " ORDER BY r.created_at DESC LIMIT ?"
        p.append(limit)

        rows = db.execute(q, p).fetchall()
        items = [_row_to_dict(r) for r in rows]

        # 去掉 content_json（列表页不返回完整内容，节省带宽）
        for item in items:
            item.pop("content_json", None)

        total = db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        by_type = db.execute("SELECT report_type, COUNT(*) as cnt FROM reports GROUP BY report_type").fetchall()

        return jsonify({
            "items": items,
            "total": total,
            "by_type": [dict(t) for t in by_type],
        })
    finally:
        db.close()


@reports_bp.route("/<int:rid>", methods=["GET"])
@login_required
def get_report(rid):
    """获取单份报告（含完整内容）。"""
    db = get_db()
    try:
        row = db.execute(
            "SELECT r.*, u.name as generator_name FROM reports r LEFT JOIN users u ON u.id=r.generated_by WHERE r.id=?",
            (rid,)
        ).fetchone()
        if not row:
            return jsonify({"error": "报告不存在"}), 404
        return jsonify(_row_to_dict(row))
    finally:
        db.close()


VALID_REPORT_TYPES = ["security_summary", "vuln_detail", "sla_report", "trend", "compliance"]
TYPE_LABELS = {
    "security_summary": "安全总览报告", "vuln_detail": "漏洞明细报告",
    "sla_report": "SLA 合规报告", "trend": "趋势分析报告", "compliance": "合规检查清单",
}


@reports_bp.route("/generate", methods=["POST"])
@login_required
def generate_report():
    """
    根据请求参数生成安全报告。
    支持的报告类型：
      - security_summary   安全总览
      - vuln_detail        漏洞明细
      - sla_report         SLA 合规报告
      - trend              趋势分析（按月）
      - compliance         合规检查清单

    支持的格式：json / csv / markdown
    """
    data = request.get_json(silent=True) or {}
    report_type = data.get("report_type", "security_summary")
    format_type = data.get("format_type", "json")
    title = data.get("title", "")

    user_id = request.current_user_id

    # ── 收集数据 ──
    db = get_db()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        filters = {}
        project_id = data.get("project_id")
        if project_id:
            filters["project_id"] = int(project_id)
        severity_filter = data.get("severity")  # list or string
        if severity_filter:
            filters["severity"] = severity_filter

        content = {}

        if report_type == "security_summary":
            content = _build_security_summary(db, filters)

        elif report_type == "vuln_detail":
            content = _build_vuln_detail(db, filters)

        elif report_type == "sla_report":
            content = _build_sla_report(db, filters)

        elif report_type == "trend":
            content = _build_trend_report(db, filters)

        elif report_type == "compliance":
            content = _build_compliance_report(db, filters)

        else:
            types_help = ", ".join([f"{t}({TYPE_LABELS.get(t, t)})" for t in VALID_REPORT_TYPES])
            return jsonify({
                "error": f"未知报告类型: {report_type}",
                "available_types": VALID_REPORT_TYPES,
                "available_types_help": types_help,
            }), 400

        # 元信息
        content["_meta"] = {
            "generated_at": now_str,
            "report_type": report_type,
            "format_type": format_type,
            "filters": filters,
            "platform": "Sentinel AppSec v3.0",
        }

        # 存库
        content_json = json.dumps(content, ensure_ascii=False, indent=2)
        file_size = len(content_json.encode("utf-8"))

        cur = db.execute(
            """INSERT INTO reports
               (report_type, title, format_type, filters_json, content_json,
                status, generated_by, file_size)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                report_type,
                title or f"{_report_type_label(report_type)} - {now_str[:10]}",
                format_type,
                json.dumps(filters, ensure_ascii=False),
                content_json,
                "completed",
                user_id,
                file_size,
            )
        )
        db.commit()
        rid = cur.lastrowid
        audit_report_gen(user_id, rid, report_type, format_type, title)

        result = {
            "id": rid,
            "report_type": report_type,
            "title": title,
            "format_type": format_type,
            "file_size": file_size,
            "status": "completed",
            "created_at": now_str,
        }

        # 如果要求 CSV 或 Markdown 格式，直接返回文件下载链接
        if format_type in ("csv", "markdown"):
            raw_data = _export_format(content, format_type)
            filename = f"sentinel-report-{report_type}-{now_str[:10]}"
            ext = ".csv" if format_type == "csv" else ".md"

            # 用临时文件方式返回
            filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_tmp_report" + ext)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(raw_data)

            result["download_url"] = f"/api/reports/{rid}/download?format={format_type}"

        result["content"] = content  # JSON 格式直接内联

        return jsonify(result), 201

    finally:
        db.close()


@reports_bp.route("/<int:rid>/download", methods=["GET"])
@login_required
def download_report(rid):
    """下载已生成的报告。"""
    fmt = request.args.get("format", "json")
    db = get_db()
    try:
        row = db.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
        if not row:
            return jsonify({"error": "报告不存在"}), 404

        audit_report_download(request.current_user_id, rid, fmt)

        content = row["content_json"]
        if fmt == "json":
            return jsonify(json.loads(content))

        # CSV / Markdown 转换
        parsed = json.loads(content) if isinstance(content, str) else content
        raw = _export_format(parsed, fmt)
        filename = f"sentinel-report-{row['report_type']}-{str(row['created_at'])[:10]}"

        import mimetypes
        ct = "text/csv; charset=utf-8" if fmt == "csv" else "text/markdown; charset=utf-8"
        ext = ".csv" if fmt == "csv" else ".md"

        output = io.BytesIO()
        output.write(raw.encode("utf-8"))
        output.seek(0)
        return send_file(output, mimetype=ct, as_attachment=True,
                         download_name=filename + ext)
    finally:
        db.close()


@reports_bp.route("/<int:rid>/pdf", methods=["GET"])
@login_required
def pdf_report(rid):
    """导出报告为 PDF 文件（可视化版，委托 render_pdf_report）。"""
    db = get_db()
    try:
        row = db.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
        if not row:
            return jsonify({"error": "报告不存在"}), 404
        row = dict(row)

        content = row["content_json"]
        parsed = json.loads(content) if isinstance(content, str) else content
        meta = parsed.pop("_meta", {}) if isinstance(parsed, dict) else {}
        from routes.report_pdf import render_pdf_report
        try:
            output = render_pdf_report(parsed, meta, dict(row))
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({"error": f"PDF 生成失败: {str(e)}"}), 500
        filename = f"sentinel-{meta.get('report_type', row['report_type'])}-{str(row['created_at'])[:10]}.pdf"
        return send_file(output, mimetype="application/pdf", as_attachment=True, download_name=filename)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"PDF 生成失败: {str(e)}"}), 500
    finally:
        db.close()


@reports_bp.route("/<int:rid>/html", methods=["GET"])
@login_required
def html_report(rid):
    """导出报告为自包含 HTML 文件（可视化版，委托 render_html_report）。"""
    db = get_db()
    try:
        row = db.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
        if not row:
            return jsonify({"error": "报告不存在"}), 404
        row = dict(row)

        content = row["content_json"]
        parsed = json.loads(content) if isinstance(content, str) else content
        meta = parsed.pop("_meta", {}) if isinstance(parsed, dict) else {}
        title = row.get("title") or ""
        from routes.report_html import render_html_report
        try:
            html = render_html_report(parsed, meta, title)
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({"error": f"HTML 生成失败: {str(e)}"}), 500
        output = io.BytesIO(html.encode("utf-8"))
        output.seek(0)
        filename = f"sentinel-{meta.get('report_type', row['report_type'])}-{str(row['created_at'])[:10]}.html"
        return send_file(output, mimetype="text/html", as_attachment=True, download_name=filename)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"HTML 生成失败: {str(e)}"}), 500
    finally:
        db.close()


@reports_bp.route("/<int:rid>", methods=["DELETE"])
@admin_required
def delete_report(rid):
    db = get_db()
    try:
        if not db.execute("SELECT id FROM reports WHERE id=?", (rid,)).fetchone():
            return jsonify({"error": "报告不存在"}), 404
        db.execute("DELETE FROM reports WHERE id=?", (rid,))
        db.commit()
        audit_report_delete(request.current_user_id, rid)
        return jsonify({"message": "已删除", "id": rid})
    finally:
        db.close()


# ══════════════════════════════════════════════
#  报告构建器
# ══════════════════════════════════════════════

def _report_type_label(rt):
    labels = {
        "security_summary": "安全总览报告",
        "vuln_detail": "漏洞明细报告",
        "sla_report": "SLA合规报告",
        "trend": "趋势分析报告",
        "compliance": "合规检查清单",
    }
    return labels.get(rt, rt)


def _build_security_summary(db, filters):
    """安全总览：项目数、漏洞分布、风险概要、工具覆盖、知识库、修复率。"""
    pid = filters.get("project_id")

    # 项目统计
    proj_q = "SELECT * FROM projects"
    p_params = []
    if pid:
        proj_q += " WHERE id=?"; p_params.append(pid)
    projects = [dict(p) for p in db.execute(proj_q, p_params).fetchall()]

    # 漏洞汇总
    vuln_q = """
        SELECT v.severity, v.status, COUNT(*) as cnt,
               s.project_id, p.name as project_name
        FROM vulnerabilities v
        JOIN scan_tasks s ON s.id=v.scan_id
        LEFT JOIN projects p ON p.id=s.project_id
        WHERE 1=1
    """
    vp = []
    if pid:
        vuln_q += " AND s.project_id=?"; vp.append(pid)
    sev = filters.get("severity")
    if sev:
        if isinstance(sev, list):
            placeholders = ",".join(["?" for _ in sev])
            vuln_q += f" AND v.severity IN ({placeholders})"
            vp.extend(sev)
        else:
            vuln_q += " AND v.severity=?"; vp.append(sev)
    vuln_q += " GROUP BY v.severity, v.status, s.project_id"
    vulns = [dict(v) for v in db.execute(vuln_q, vp).fetchall()]

    # 按严重度聚合
    severity_breakdown = {}
    status_breakdown = {}
    for v in vulns:
        sv = v["severity"]
        st = v["status"]
        severity_breakdown[sv] = severity_breakdown.get(sv, 0) + v["cnt"]
        status_breakdown[st] = status_breakdown.get(st, 0) + v["cnt"]

    # ── 修复率 (按严重度) ──
    fix_rate_q = """
        SELECT v.severity,
               COUNT(*) as total,
               SUM(CASE WHEN v.status IN ('fixed','ignored') THEN 1 ELSE 0 END) as closed
        FROM vulnerabilities v
        JOIN scan_tasks s ON s.id=v.scan_id
        WHERE 1=1
    """
    frp = []
    if pid:
        fix_rate_q += " AND s.project_id=?"; frp.append(pid)
    fix_rate_q += " GROUP BY v.severity"
    fix_rows = db.execute(fix_rate_q, frp).fetchall()
    fix_rate = {}
    for r in fix_rows:
        total = r["total"] or 1
        fix_rate[r["severity"]] = round(r["closed"] / total * 100, 1)

    # ── 工具覆盖情况 ──
    tool_q = "SELECT id, name, tool_type, enabled, scan_count, last_scan_at, vuln_found_total FROM tools WHERE 1=1"
    tools = [dict(t) for t in db.execute(tool_q).fetchall()]
    active_tools = sum(1 for t in tools if t.get("enabled"))
    tool_summary = {
        "total": len(tools),
        "active": active_tools,
        "inactive": len(tools) - active_tools,
        "total_scans": sum(t.get("scan_count", 0) or 0 for t in tools),
        "total_vulns_found": sum(t.get("vuln_found_total", 0) or 0 for t in tools),
    }

    # ── 知识库统计 ──
    kb_stats = {}
    try:
        kb_total = db.execute("SELECT COUNT(*) FROM knowledge_articles").fetchone()[0]
        kb_by_cat = db.execute(
            "SELECT category, COUNT(*) as cnt FROM knowledge_articles GROUP BY category"
        ).fetchall()
        kb_stats = {
            "total_articles": kb_total,
            "categories": len(kb_by_cat),
            "by_category": {r["category"]: r["cnt"] for r in kb_by_cat},
        }
    except Exception:
        kb_stats = {"total_articles": 0, "categories": 0, "by_category": {}}

    # ── 风险评估 ──
    total_vulns = sum(severity_breakdown.values())
    open_count = status_breakdown.get("open", 0)
    critical_count = severity_breakdown.get("critical", 0)
    high_count = severity_breakdown.get("high", 0)

    if critical_count > 5 or (critical_count + high_count) > 20:
        risk_level = "严重"
    elif critical_count > 0 or high_count > 10:
        risk_level = "高"
    elif high_count > 0 or open_count > 30:
        risk_level = "中"
    else:
        risk_level = "低"

    risk_assessment = {
        "level": risk_level,
        "critical_open": critical_count,
        "high_open": high_count,
        "open_total": open_count,
        "recommendation": (
            "建议立即修复所有严重和高危漏洞，建立定期扫描机制" if risk_level in ("严重", "高")
            else "建议按优先级逐步修复中高危漏洞" if risk_level == "中"
            else "当前安全态势良好，保持定期扫描和监控"
        ),
    }

    # Top 高危漏洞
    top_vulns_q = """
        SELECT v.id, v.title, v.severity, v.cvss_score, v.cve_id,
               v.file_path, v.sla_due_date, v.sla_breached,
               p.name as project_name
        FROM vulnerabilities v
        JOIN scan_tasks s ON s.id=v.scan_id
        LEFT JOIN projects p ON p.id=s.project_id
        WHERE v.status='open'
    """
    tvp = []
    if pid:
        top_vulns_q += " AND s.project_id=?"; tvp.append(pid)
    top_vulns_q += " ORDER BY CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END, v.cvss_score DESC LIMIT 20"
    top_vulns = [dict(v) for v in db.execute(top_vulns_q, tvp).fetchall()]

    return {
        "summary": {
            "total_projects": len(projects),
            "total_vulnerabilities": total_vulns,
            "open_vulnerabilities": open_count,
            "fixed_vulnerabilities": status_breakdown.get("fixed", 0),
            "ignored_vulnerabilities": status_breakdown.get("ignored", 0),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": severity_breakdown.get("medium", 0),
            "low_count": severity_breakdown.get("low", 0),
            "overall_fix_rate": round(
                (status_breakdown.get("fixed", 0) + status_breakdown.get("ignored", 0))
                / max(total_vulns, 1) * 100, 1
            ),
        },
        "risk_assessment": risk_assessment,
        "projects": projects,
        "severity_distribution": severity_breakdown,
        "status_distribution": status_breakdown,
        "fix_rate": fix_rate,
        "tool_coverage": tool_summary,
        "knowledge_base_stats": kb_stats,
        "top_vulnerabilities": top_vulns,
    }


def _build_vuln_detail(db, filters):
    """漏洞明细：每条漏洞完整信息 + CWE分布 + 工具来源 + 受影响资产。"""
    pid = filters.get("project_id")

    q = """
        SELECT v.id, v.cve_id, v.title, v.severity, v.cvss_score, v.cwe_id,
               v.file_path, v.line, v.source_tool, v.description,
               v.fix_suggestion, v.status, v.sla_due_date, v.sla_breached,
               v.created_at,
               p.name as project_name, s.tool_type
        FROM vulnerabilities v
        JOIN scan_tasks s ON s.id=v.scan_id
        LEFT JOIN projects p ON p.id=s.project_id
        WHERE 1=1
    """
    p = []
    if pid:
        q += " AND s.project_id=?"; p.append(pid)

    sev = filters.get("severity")
    if sev:
        if isinstance(sev, list):
            q += " AND v.severity IN ({})".format(",".join(["?" for _ in sev]))
            p.extend(sev)
        else:
            q += " AND v.severity=?"; p.append(sev)

    st = filters.get("status")
    if st:
        q += " AND v.status=?"; p.append(st)

    q += " ORDER BY CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, v.id DESC"
    rows = [dict(r) for r in db.execute(q, p).fetchall()]

    # 按严重度统计
    totals = {}
    for r in rows:
        totals[r["severity"]] = totals.get(r["severity"], 0) + 1

    # ── CWE 分布统计 ──
    cwe_dist = {}
    for r in rows:
        cwe = r.get("cwe_id") or "N/A"
        cwe_dist[cwe] = cwe_dist.get(cwe, 0) + 1
    top_cwes = sorted(cwe_dist.items(), key=lambda x: x[1], reverse=True)[:10]

    # ── 工具来源分布 ──
    tool_dist = {}
    for r in rows:
        tool = r.get("source_tool") or r.get("tool_type") or "Unknown"
        tool_dist[tool] = tool_dist.get(tool, 0) + 1

    # ── 受影响资产 ──
    project_files = {}
    for r in rows:
        proj = r.get("project_name") or "未指定"
        fpath = r.get("file_path") or ""
        if proj not in project_files:
            project_files[proj] = set()
        if fpath:
            project_files[proj].add(fpath)
    affected_assets = [
        {"project": proj, "file_count": len(files)}
        for proj, files in sorted(project_files.items(), key=lambda x: len(x[1]), reverse=True)
    ]

    # ── CVSS 分档统计 ──
    cvss_ranges = {"严重 (9.0-10.0)": 0, "高危 (7.0-8.9)": 0, "中危 (4.0-6.9)": 0, "低危 (0.1-3.9)": 0, "未评分": 0}
    for r in rows:
        score = r.get("cvss_score")
        if score is None or score == 0:
            cvss_ranges["未评分"] += 1
        elif score >= 9.0:
            cvss_ranges["严重 (9.0-10.0)"] += 1
        elif score >= 7.0:
            cvss_ranges["高危 (7.0-8.9)"] += 1
        elif score >= 4.0:
            cvss_ranges["中危 (4.0-6.9)"] += 1
        else:
            cvss_ranges["低危 (0.1-3.9)"] += 1

    return {
        "total": len(rows),
        "totals": totals,
        "cwe_distribution": dict(top_cwes),
        "cvss_distribution": cvss_ranges,
        "tool_source": tool_dist,
        "affected_assets": affected_assets,
        "items": rows,
    }


def _build_sla_report(db, filters):
    """SLA 合规：超时/即将到期/正常/修复率 + 处理人表现 + 平均修复时间。"""
    pid = filters.get("project_id")

    q = """
        SELECT v.id, v.title, v.severity, v.sla_due_date, v.sla_breached,
               v.status, v.assigned_to, v.created_at,
               u.name as assignee_name, p.name as project_name
        FROM vulnerabilities v
        LEFT JOIN users u ON u.id=v.assigned_to
        JOIN scan_tasks s ON s.id=v.scan_id
        LEFT JOIN projects p ON p.id=s.project_id
        WHERE v.sla_due_date != ''
    """
    p_params = []
    if pid:
        q += " AND s.project_id=?"; p_params.append(pid)
    q += " ORDER BY v.sla_due_date ASC"

    rows = [dict(r) for r in db.execute(q, p_params).fetchall()]
    now = datetime.datetime.now()

    breached = []
    urgent = []   # < 24h
    on_track = []
    closed_fixed = []

    for v in rows:
        due_str = v.get("sla_due_date", "")
        try:
            due = datetime.datetime.strptime(due_str[:19], "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            continue
        delta = (due - now).total_seconds()

        if v["status"] in ("fixed", "ignored"):
            closed_fixed.append(v)
        elif delta < 0:
            breached.append(v)
        elif delta < 86400:
            urgent.append(v)
        else:
            on_track.append(v)

    # ── 处理人 SLA 表现 ──
    assignee_stats = {}
    for v in rows:
        name = v.get("assignee_name") or "未分配"
        if name not in assignee_stats:
            assignee_stats[name] = {"total": 0, "breached": 0, "fixed": 0, "on_time": 0}
        assignee_stats[name]["total"] += 1
        if v.get("sla_breached"):
            assignee_stats[name]["breached"] += 1
        if v["status"] in ("fixed", "ignored"):
            assignee_stats[name]["fixed"] += 1
        elif v["status"] == "open":
            # 判断是否按时
            due_str = v.get("sla_due_date", "")
            try:
                due = datetime.datetime.strptime(due_str[:19], "%Y-%m-%d %H:%M:%S")
                if (due - now).total_seconds() > 0:
                    assignee_stats[name]["on_time"] += 1
            except (ValueError, TypeError):
                pass

    assignee_performance = []
    for name, stats in sorted(assignee_stats.items(), key=lambda x: x[1]["breached"], reverse=True):
        sla_rate = round(
            (stats["total"] - stats["breached"]) / max(stats["total"], 1) * 100, 1
        )
        assignee_performance.append({
            "assignee": name,
            "total": stats["total"],
            "breached": stats["breached"],
            "fixed": stats["fixed"],
            "on_time": stats["on_time"],
            "sla_rate": sla_rate,
        })

    # ── 平均修复时间 (已修复漏洞) ──
    fix_times = []
    for v in closed_fixed:
        created = v.get("created_at", "")
        try:
            c = datetime.datetime.strptime(created[:19], "%Y-%m-%d %H:%M:%S")
            # 已修复的漏洞：使用从创建到当前时间作为修复时间估算
            hours = (now - c).total_seconds() / 3600
            fix_times.append(hours)
        except (ValueError, TypeError):
            pass

    avg_fix_hours = round(sum(fix_times) / max(len(fix_times), 1), 1) if fix_times else 0

    return {
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_tracked": len(rows),
            "compliance_rate": round(
                len(closed_fixed) / max(len(rows), 1) * 100, 1) if rows else 0,
        },
        "breached": {"count": len(breached), "items": breached},
        "urgent": {"count": len(urgent), "items": urgent},
        "on_track": {"count": len(on_track), "items": on_track},
        "closed_or_fixed": {"count": len(closed_fixed), "items": closed_fixed},
        "assignee_performance": assignee_performance,
        "avg_time_to_fix": {
            "hours": avg_fix_hours,
            "days": round(avg_fix_hours / 24, 1),
            "samples": len(fix_times),
        },
    }


def _build_trend_report(db, filters):
    """趋势分析：按月统计扫描/漏洞/修复率/工具使用。"""
    pid = filters.get("project_id")

    # 月度扫描统计
    scan_q = """
        SELECT strftime('%Y-%m', created_at) as month,
               COUNT(*) as scan_count,
               SUM(vuln_count) as total_vulns
        FROM scan_tasks
        WHERE status='completed' AND created_at > datetime('now','-12 months')
    """
    sp = []
    if pid:
        scan_q += " AND project_id=?"; sp.append(pid)
    scan_q += " GROUP BY strftime('%Y-%m', created_at) ORDER BY month"
    monthly_scans = [dict(s) for s in db.execute(scan_q, sp).fetchall()]

    # 月度漏洞新增（按严重度）
    vuln_q = """
        SELECT strftime('%Y-%m', v.created_at) as month,
               v.severity, COUNT(*) as cnt
        FROM vulnerabilities v
        JOIN scan_tasks s ON s.id=v.scan_id
        WHERE v.created_at > datetime('now','-12 months')
    """
    vp = []
    if pid:
        vuln_q += " AND s.project_id=?"; vp.append(pid)
    vuln_q += " GROUP BY strftime('%Y-%m', v.created_at), v.severity ORDER BY month"
    monthly_vulns = [dict(v) for v in db.execute(vuln_q, vp).fetchall()]

    # ── 月度修复率趋势 ──
    fix_trend_q = """
        SELECT strftime('%Y-%m', v.created_at) as month,
               COUNT(*) as total,
               SUM(CASE WHEN v.status IN ('fixed','ignored') THEN 1 ELSE 0 END) as fixed
        FROM vulnerabilities v
        JOIN scan_tasks s ON s.id=v.scan_id
        WHERE v.created_at > datetime('now','-12 months')
    """
    ftp = []
    if pid:
        fix_trend_q += " AND s.project_id=?"; ftp.append(pid)
    fix_trend_q += " GROUP BY strftime('%Y-%m', v.created_at) ORDER BY month"
    fix_trend_rows = db.execute(fix_trend_q, ftp).fetchall()
    fix_rate_trend = []
    for r in fix_trend_rows:
        total = r["total"] or 1
        fix_rate_trend.append({
            "month": r["month"],
            "total": r["total"],
            "fixed": r["fixed"],
            "fix_rate": round(r["fixed"] / total * 100, 1),
        })

    # ── 工具使用趋势 ──
    tool_trend_q = """
        SELECT strftime('%Y-%m', created_at) as month,
               tool_type, COUNT(*) as cnt
        FROM scan_tasks
        WHERE status='completed' AND created_at > datetime('now','-12 months')
    """
    ttp = []
    if pid:
        tool_trend_q += " AND project_id=?"; ttp.append(pid)
    tool_trend_q += " GROUP BY strftime('%Y-%m', created_at), tool_type ORDER BY month"
    tool_trend_rows = db.execute(tool_trend_q, ttp).fetchall()
    tool_usage = {}
    for r in tool_trend_rows:
        tt = r["tool_type"] or "unknown"
        if tt not in tool_usage:
            tool_usage[tt] = []
        tool_usage[tt].append({"month": r["month"], "count": r["cnt"]})

    return {
        "period": "最近 12 个月",
        "monthly_scans": monthly_scans,
        "monthly_vulns_by_severity": monthly_vulns,
        "total_scans_in_period": sum(s["scan_count"] for s in monthly_scans),
        "total_vulns_in_period": sum(s["total_vulns"] or 0 for s in monthly_scans),
        "fix_rate_trend": fix_rate_trend,
        "tool_usage": tool_usage,
    }


def _build_compliance_report(db, filters):
    """合规检查清单 — 基于 OWASP ASVS 简化版 + 实际漏洞数据自评估。"""
    pid = filters.get("project_id")

    # 查询实际漏洞数据，用于自动评估
    actual_vulns = []
    try:
        vq = """
            SELECT v.cwe_id, v.severity, v.title, v.description, v.source_tool
            FROM vulnerabilities v
            JOIN scan_tasks s ON s.id=v.scan_id
            WHERE 1=1
        """
        vp = []
        if pid:
            vq += " AND s.project_id=?"; vp.append(pid)
        actual_vulns = [dict(v) for v in db.execute(vq, vp).fetchall()]
    except Exception:
        pass

    # 自动评估辅助函数
    def find_evidence(keywords, vulns):
        """在漏洞数据中查找匹配的证据。"""
        found = []
        for v in vulns:
            title = (v.get("title") or "").lower()
            desc = (v.get("description") or "").lower()
            cwe = (v.get("cwe_id") or "").lower()
            for kw in keywords:
                if kw.lower() in title or kw.lower() in desc or kw.lower() in cwe:
                    found.append({
                        "cwe": v.get("cwe_id") or "N/A",
                        "severity": v.get("severity"),
                        "title": v.get("title") or "未知",
                    })
                    break
        return found

    check_items = [
        {
            "id": "ASVS-001", "category": "认证",
            "name": "是否使用强密码策略？", "weight": 3,
            "keywords": ["password", "密码", "weak crypt", "弱加密", "hash", "哈希"],
        },
        {
            "id": "ASVS-002", "category": "认证",
            "name": "是否实现了账户锁定/多因素认证？", "weight": 3,
            "keywords": ["lockout", "锁定", "mfa", "2fa", "otp", "brute force", "暴力破解"],
        },
        {
            "id": "ASVS-003", "category": "会话管理",
            "name": "Session Token 是否随机且足够长？", "weight": 3,
            "keywords": ["session", "token", "jwt", "cookie", "会话"],
        },
        {
            "id": "ASVS-004", "category": "访问控制",
            "name": "是否实施了 RBAC / 权限控制？", "weight": 2,
            "keywords": ["rbac", "access control", "权限", "authorization", "idor", "越权"],
        },
        {
            "id": "ASVS-005", "category": "访问控制",
            "name": "API 是否有速率限制？", "weight": 2,
            "keywords": ["rate limit", "速率", "throttle", "dos", "ddos"],
        },
        {
            "id": "ASVS-006", "category": "输入验证",
            "name": "是否有 SQL 注入防护？", "weight": 3,
            "keywords": ["sql injection", "sqli", "sql 注入", "cwe-89"],
        },
        {
            "id": "ASVS-007", "category": "输入验证",
            "name": "是否有 XSS 防护？", "weight": 3,
            "keywords": ["xss", "cross-site", "跨站", "cwe-79", "html injection"],
        },
        {
            "id": "ASVS-008", "category": "加密",
            "name": "敏感数据是否加密存储？", "weight": 3,
            "keywords": ["encrypt", "加密", "plaintext", "明文", "hardcoded", "硬编码", "secret", "密钥"],
        },
        {
            "id": "ASVS-009", "category": "加密",
            "name": "传输是否使用 TLS/HTTPS？", "weight": 2,
            "keywords": ["tls", "ssl", "https", "cleartext", "明文传输", "insecure"],
        },
        {
            "id": "ASVS-010", "category": "日志审计",
            "name": "关键操作是否有审计日志？", "weight": 2,
            "keywords": ["audit", "审计", "log", "日志", "logging"],
        },
        {
            "id": "ASVS-011", "category": "日志审计",
            "name": "日志中不应包含敏感数据", "weight": 1,
            "keywords": ["log sensitive", "日志敏感", "pii in log", "password in log"],
        },
        {
            "id": "ASVS-012", "category": "错误处理",
            "name": "错误信息不应泄露栈信息", "weight": 2,
            "keywords": ["stack trace", "栈", "error message", "debug", "traceback", "exception"],
        },
        {
            "id": "ASVS-013", "category": "数据保护",
            "name": "是否有数据脱敏/掩码处理？", "weight": 2,
            "keywords": ["mask", "脱敏", "anonymize", "pii", "个人信息", "privacy"],
        },
        {
            "id": "ASVS-014", "category": "依赖管理",
            "name": "第三方依赖是否存在已知漏洞？", "weight": 3,
            "keywords": ["cve-", "dependency", "依赖", "vulnerable library", "outdated", "cwe-937"],
        },
        {
            "id": "ASVS-015", "category": "配置安全",
            "name": "是否存在不安全的默认配置？", "weight": 2,
            "keywords": ["config", "配置", "default", "默认", "debug mode", "misconfig"],
        },
    ]

    checks = []
    for item in check_items:
        evidence = find_evidence(item["keywords"], actual_vulns)
        # 自动评估
        critical_or_high = any(e["severity"] in ("critical", "high") for e in evidence)
        has_any = len(evidence) > 0

        if critical_or_high:
            status = "fail"
            status_label = "未通过"
        elif has_any:
            status = "warning"
            status_label = "需关注"
        else:
            status = "pass"
            status_label = "已通过"

        checks.append({
            "id": item["id"],
            "category": item["category"],
            "name": item["name"],
            "weight": item["weight"],
            "status": status,
            "status_label": status_label,
            "evidence_count": len(evidence),
            "evidence": evidence[:5],  # 最多 5 条证据
            "risk_level": "high" if item["weight"] >= 3 else "medium" if item["weight"] >= 2 else "low",
        })

    # 汇总
    passed = sum(1 for c in checks if c["status"] == "pass")
    warning = sum(1 for c in checks if c["status"] == "warning")
    failed = sum(1 for c in checks if c["status"] == "fail")
    total_weight = sum(c["weight"] for c in checks)
    score = sum(c["weight"] for c in checks if c["status"] == "pass")
    weighted_score = round(score / max(total_weight, 1) * 100, 1)

    # 按分类汇总
    category_summary = {}
    for c in checks:
        cat = c["category"]
        if cat not in category_summary:
            category_summary[cat] = {"total": 0, "pass": 0, "fail": 0, "warning": 0}
        category_summary[cat]["total"] += 1
        category_summary[cat][c["status"]] += 1

    categories_list = []
    for cat, stats in category_summary.items():
        cat_score = round(stats["pass"] / max(stats["total"], 1) * 100, 1)
        categories_list.append({
            "name": cat,
            "total": stats["total"],
            "pass": stats["pass"],
            "warning": stats["warning"],
            "fail": stats["fail"],
            "score": cat_score,
        })

    return {
        "framework": "OWASP Application Security Verification Standard (ASVS) 扩展版",
        "summary": {
            "total_checks": len(checks),
            "passed": passed,
            "warning": warning,
            "failed": failed,
            "weighted_score": weighted_score,
            "grade": (
                "A" if weighted_score >= 90 else "B" if weighted_score >= 75
                else "C" if weighted_score >= 60 else "D" if weighted_score >= 40 else "F"
            ),
        },
        "categories": categories_list,
        "checks": checks,
        "compliance_details": {
            "total_checks": len(checks),
            "estimated_score": weighted_score,
            "data_based": len([v for v in actual_vulns if v.get("cwe_id")]) > 0,
        },
    }


# ══════════════════════════════════════════════
#  格式导出
# ══════════════════════════════════════════════

def _export_format(content, fmt):
    """将结构化内容转为 CSV 或 Markdown 文本。"""
    meta = content.pop("_meta", {})

    if fmt == "csv":
        lines = []
        # 尝试找 items 列表
        items = content.get("items") or content.get("top_vulnerabilities") or []
        if items and isinstance(items, list) and items:
            headers = list(items[0].keys())
            lines.append(",".join(headers))
            for item in items:
                row = []
                for h in headers:
                    val = item.get(h, "")
                    val = str(val).replace('"', '""').replace("\n", " ")
                    row.append(f'"{val}"')
                lines.append(",".join(row))
        else:
            # 非表格数据 → key-value 形式
            lines.append("key,value")
            def flatten(d, prefix=""):
                out = []
                for k, v in d.items():
                    key = f"{prefix}.{k}" if prefix else k
                    if isinstance(v, dict):
                        out.extend(flatten(v, key))
                    elif isinstance(v, list):
                        out.append((key, json.dumps(v, ensure_ascii=False)))
                    else:
                        out.append((key, str(v)))
                return out
            for k, v in flatten(content):
                lines.append(f'"{k}","{v}"')
        return "\n".join(lines)

    elif fmt == "markdown":
        md_lines = [f"# {_report_type_label(meta.get('report_type', ''))}\n"]
        md_lines.append(f"> 生成时间: {meta.get('generated_at', '')} | 平台: {meta.get('platform', '')}\n")

        label_map = {
            "summary": "## 总览",
            "severity_distribution": "## 严重度分布",
            "status_distribution": "## 漏洞状态分布",
            "top_vulnerabilities": "## TOP 高危漏洞",
            "items": "## 明细列表",
            "totals": "### 按严重度统计",
            "breached": "## 已超时 SLA",
            "urgent": "## 即将到期（<24h）",
            "on_track": "## 正常跟踪",
            "closed_or_fixed": "## 已关闭/已修复",
            "monthly_scans": "## 月度扫描趋势",
            "monthly_vulns_by_severity": "## 月度漏洞发现趋势",
            "checks": "## 合规检查项",
            "tool_coverage": "## 工具覆盖情况",
            "knowledge_base_stats": "## 知识库统计",
            "fix_rate": "## 修复率分析",
            "risk_assessment": "## 风险评估",
            "cwe_distribution": "## CWE 类型分布",
            "cvss_distribution": "## CVSS 分档统计",
            "tool_source": "## 扫描工具来源",
            "affected_assets": "## 受影响资产",
            "assignee_performance": "## 处理人 SLA 表现",
            "avg_time_to_fix": "## 平均修复时间",
            "fix_rate_trend": "## 修复率趋势",
            "tool_usage": "## 工具使用趋势",
            "categories": "## 分类汇总",
            "compliance_details": "## 合规详情",
            "projects": "## 项目列表",
        }

        for section_key, section_val in content.items():
            if section_key in ("period", "framework", "generated_at",
                               "total", "total_tracked", "total_scans_in_period",
                               "total_vulns_in_period", "estimated_score", "compliance_rate"):
                # 这些字段已内嵌到其他 section
                continue

            title = label_map.get(section_key, f"## {section_key}")
            md_lines.append(f"\n{title}\n")

            if isinstance(section_val, list):
                if section_val and isinstance(section_val[0], dict):
                    keys = list(section_val[0].keys())[:6]
                    md_lines.append("| " + " | ".join(keys) + " |")
                    md_lines.append("| " + " | ".join("---" for _ in keys) + " |")
                    for item in section_val:
                        vals = [str(item.get(k, ""))[:60] for k in keys]
                        md_lines.append("| " + " | ".join(vals) + " |")
                else:
                    for item in section_val:
                        md_lines.append(f"- {item}")

            elif isinstance(section_val, (int, float)):
                md_lines.append(f"\n**{section_val}**\n")

            elif isinstance(section_val, dict):
                for sk, sv in section_val.items():
                    if isinstance(sv, (list, dict)):
                        if isinstance(sv, list) and sv:
                            sub_label = f"### {sk}"
                            md_lines.append(f"\n{sub_label}\n")
                            if isinstance(sv[0], dict):
                                keys = list(sv[0].keys())[:5]
                                md_lines.append("| " + " | ".join(keys) + " |")
                                md_lines.append("| " + " | ".join("---" for _ in keys) + " |")
                                for item in sv:
                                    vals = [str(item.get(k, ""))[:50] for k in keys]
                                    md_lines.append("| " + " | ".join(vals) + " |")
                            else:
                                for item in sv:
                                    md_lines.append(f"- {item}")
                        continue
                    md_lines.append(f"- **{sk}**: {sv}")

        return "\n".join(md_lines)

    return json.dumps(content, ensure_ascii=False, indent=2)
