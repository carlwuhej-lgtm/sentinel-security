# ─── 漂亮的自包含 HTML 安全报告渲染器 ───
"""
render_html_report(content, meta) -> 完整 HTML 字符串（自包含，内联 CSS + 内联 SVG，
无外部依赖，双击即开，浏览器可打印成 PDF）。

设计目标：把前端「查看」弹窗里那些好看的 KPI 卡片 / 严重度配色 / 趋势柱图 / 合规评分卡
原样搬到一份可下载的文件里——解决「下载出去的是裸数据」的痛点。

颜色 / 图表与现有前端（Reports.tsx）保持一致，方便后续双向同步。
"""

from html import escape as _h

# ════════════ 配色 ════════════
SEV_COLORS = {
    "critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
    "low": "#3b82f6", "info": "#64748b", "unknown": "#64748b",
}
SEV_LABELS = {
    "critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
    "info": "信息", "unknown": "未知",
}
STATUS_COLORS = {
    "open": "#f59e0b", "fixed": "#22c55e", "ignored": "#64748b",
    "breached": "#ef4444", "urgent": "#f97316", "on_track": "#22c55e",
    "pass": "#22c55e", "warning": "#eab308", "fail": "#ef4444",
    "pending": "#64748b",
}
RISK_COLORS = {
    "严重": "#ef4444", "高": "#f97316", "中": "#eab308", "低": "#22c55e",
}


def _esc(s, limit=400):
    if s is None:
        return ""
    return _h(str(s)[:limit], quote=True)


def _sev_color(key):
    k = str(key).lower()
    return SEV_COLORS.get(k, "#64748b")


def _grade_color(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "#64748b"
    if s >= 90:
        return "#4ade80"
    if s >= 75:
        return "#a3e635"
    if s >= 60:
        return "#fbbf24"
    return "#f87171"


# ════════════ SVG 图表 ════════════
def _svg_donut(data: dict, color_of, size=160):
    """data: {label: value} -> 环形图 SVG + 图例。"""
    items = [(k, v) for k, v in data.items() if isinstance(v, (int, float)) and v]
    total = sum(v for _, v in items) or 1
    r = size / 2 - 14
    cx = cy = size / 2
    circ = 2 * 3.141592653589793 * r
    parts = []
    offset = 0
    for k, v in items:
        frac = v / total
        seg = frac * circ
        col = color_of(k)
        parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{col}" '
            f'stroke-width="14" stroke-dasharray="{seg:.2f} {circ - seg:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>'
        )
        offset += seg
    legend = "".join(
        f'<div style="display:flex;align-items:center;gap:6px;margin:2px 0;font-size:12px;">'
        f'<span style="width:10px;height:10px;border-radius:3px;background:{color_of(k)};display:inline-block;"></span>'
        f'<span style="color:#cbd5e1;">{_esc(SEV_LABELS.get(str(k).lower(), k))}</span>'
        f'<span style="margin-left:auto;color:#e2e8f0;font-weight:600;">{v}</span></div>'
        for k, v in items
    )
    return f'''
    <div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap;">
      <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
        <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#1e293b" stroke-width="14"/>
        {''.join(parts)}
        <text x="{cx}" y="{cy - 4}" text-anchor="middle" fill="#f1f5f9" font-size="22" font-weight="700">{total}</text>
        <text x="{cx}" y="{cy + 16}" text-anchor="middle" fill="#64748b" font-size="11">总计</text>
      </svg>
      <div style="min-width:150px;">{legend}</div>
    </div>'''


def _svg_hbars(data: dict, color_of=None, unit=""):
    """水平柱状条。data: {label: value}。"""
    items = [(k, v) for k, v in data.items() if isinstance(v, (int, float))]
    if not items:
        return ""
    mx = max(v for _, v in items) or 1
    color_of = color_of or (lambda k: "#3b82f6")
    rows = []
    for k, v in items:
        pct = (v / mx) * 100
        col = color_of(k)
        rows.append(f'''
        <div style="margin:6px 0;">
          <div style="display:flex;justify-content:space-between;font-size:12px;color:#cbd5e1;margin-bottom:3px;">
            <span>{_esc(SEV_LABELS.get(str(k).lower(), k))}</span><span style="color:#e2e8f0;font-weight:600;">{v}{unit}</span>
          </div>
          <div style="background:#1e293b;border-radius:6px;height:10px;overflow:hidden;">
            <div style="width:{pct:.1f}%;background:{col};height:100%;border-radius:6px;"></div>
          </div>
        </div>''')
    return f'<div style="width:100%;">{"" .join(rows)}</div>'


def _svg_vbars(items, value_key="scan_count", label_key="month", color="#3b82f6", height=150):
    """垂直柱状图。items: list[dict]。"""
    if not items:
        return ""
    nums = [float(it.get(value_key, 0) or 0) for it in items]
    mx = max(nums) or 1
    bars = []
    for it, n in zip(items, nums):
        h = (n / mx) * (height - 24)
        lbl = str(it.get(label_key, ""))[-5:] if it.get(label_key) else ""
        bars.append(f'''
        <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
          <span style="font-size:10px;color:#94a3b8;">{int(n)}</span>
          <div style="width:70%;max-width:30px;height:{h:.0f}px;background:{color};border-radius:4px 4px 0 0;min-height:2px;"></div>
          <span style="font-size:9px;color:#64748b;">{_esc(lbl)}</span>
        </div>''')
    return f'<div style="display:flex;align-items:flex-end;gap:4px;height:{height}px;padding:6px 4px;">{"" .join(bars)}</div>'


# ════════════ 卡片 / 区块 ════════════
def _kpi_cards(cards):
    """cards: list[(label, value, color)]。"""
    inner = []
    for label, value, color in cards:
        inner.append(f'''
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:14px;text-align:center;flex:1;min-width:90px;">
          <div style="font-size:22px;font-weight:800;color:{color};">{_esc(value)}</div>
          <div style="font-size:11px;color:#64748b;margin-top:4px;line-height:1.3;">{_esc(label)}</div>
        </div>''')
    return f'<div style="display:flex;gap:10px;flex-wrap:wrap;margin:10px 0;">{"" .join(inner)}</div>'


def _risk_banner(level, critical_open=0, high_open=0, recommendation=""):
    col = RISK_COLORS.get(level, "#64748b")
    chips = ""
    if critical_open:
        chips += f'<span style="font-size:12px;background:rgba(239,68,68,.15);color:#fca5a5;padding:2px 8px;border-radius:999px;margin-left:8px;">严重开放 {critical_open}</span>'
    if high_open:
        chips += f'<span style="font-size:12px;background:rgba(249,115,22,.15);color:#fdba74;padding:2px 8px;border-radius:999px;margin-left:8px;">高危开放 {high_open}</span>'
    return f'''
    <div style="background:{col}14;border:1px solid {col}55;border-radius:12px;padding:16px;margin:10px 0;">
      <div style="display:flex;align-items:center;flex-wrap:wrap;">
        <span style="font-size:18px;font-weight:800;color:{col};">风险等级：{_esc(level)}</span>{chips}
      </div>
      <div style="font-size:12px;color:#cbd5e1;margin-top:6px;opacity:.9;">{_esc(recommendation)}</div>
    </div>'''


def _section(title, body_html):
    return f'''
    <section style="background:#0b1220;border:1px solid #1e293b;border-radius:14px;padding:18px;margin:14px 0;">
      <h2 style="font-size:15px;color:#60a5fa;margin:0 0 12px;font-weight:700;display:flex;align-items:center;gap:8px;">
        <span style="width:4px;height:16px;background:#3b82f6;border-radius:2px;display:inline-block;"></span>{_esc(title)}
      </h2>
      {body_html}
    </section>'''


def _table(headers, rows, row_color_fn=None):
    head = "".join(f'<th style="text-align:left;padding:8px 10px;color:#94a3b8;font-size:12px;font-weight:600;border-bottom:1px solid #1e293b;">{_esc(h)}</th>' for h in headers)
    body_rows = []
    for it in rows:
        style = ""
        if row_color_fn:
            c = row_color_fn(it)
            if c:
                style = f' style="background:{c}12;"'
        cells = "".join(f'<td style="padding:7px 10px;font-size:12px;color:#e2e8f0;border-bottom:1px solid #152033;">{_esc(v)}</td>' for v in it)
        body_rows.append(f'<tr{style}>{cells}</tr>')
    return f'''
    <div style="overflow-x:auto;">
      <table style="width:100%;border-collapse:collapse;">
        <thead><tr>{head}</tr></thead>
        <tbody>{"".join(body_rows)}</tbody>
      </table>
    </div>'''


def _top_vulns(items):
    if not items:
        return '<div style="color:#64748b;font-size:12px;">无</div>'
    rows = []
    for v in items[:15]:
        sev = str(v.get("severity", "")).lower()
        col = SEV_COLORS.get(sev, "#64748b")
        badge = f'<span style="font-weight:700;color:{col};">[{_esc(SEV_LABELS.get(sev, sev).upper())}]</span>'
        cve = f' <span style="color:#64748b;font-size:11px;">{_esc(v.get("cve_id"))}</span>' if v.get("cve_id") else ""
        sla = ' <span style="color:#ef4444;font-weight:700;font-size:11px;">SLA超时</span>' if v.get("sla_breached") else ""
        fname = _esc(str(v.get("file_path", "")).split("/")[-1]) if v.get("file_path") else ""
        rows.append(f'''
        <div style="display:flex;justify-content:space-between;gap:12px;padding:8px 10px;background:#0f172a;border:1px solid #1e293b;border-radius:8px;margin:5px 0;">
          <div style="font-size:12px;color:#e2e8f0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{badge} {_esc(v.get("title"))}{cve}{sla}</div>
          <div style="font-size:11px;color:#64748b;white-space:nowrap;shrink:0;">{fname}</div>
        </div>''')
    return "".join(rows)


def _compliance_block(content):
    out = ""
    s = content.get("summary") or {}
    if "weighted_score" in s:
        grade = s.get("grade", "")
        out += f'''
        <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:14px;">
          <div style="width:120px;height:120px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;
                      background:conic-gradient({_grade_color(s['weighted_score'])} {float(s['weighted_score'])*3.6:.0f}deg, #1e293b 0);">
            <div style="width:92px;height:92px;border-radius:50%;background:#0b1220;display:flex;flex-direction:column;align-items:center;justify-content:center;">
              <span style="font-size:26px;font-weight:800;color:{_grade_color(s['weighted_score'])};">{_esc(s['weighted_score'])}</span>
              <span style="font-size:11px;color:#64748b;">评级 {_esc(grade)}</span>
            </div>
          </div>
          <div style="display:flex;gap:10px;">
            {_kpi_cards([("检查项", s.get("total_checks", 0), "#e2e8f0"),
                         ("已通过", s.get("passed", 0), "#22c55e"),
                         ("需关注", s.get("warning", 0), "#eab308"),
                         ("未通过", s.get("failed", 0), "#ef4444")])}
          </div>
        </div>'''
    if content.get("categories"):
        cards = []
        for c in content["categories"]:
            sc = float(c.get("score", 0))
            cards.append(f'''
            <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:12px;flex:1;min-width:130px;">
              <div style="font-size:13px;color:#e2e8f0;font-weight:600;">{_esc(c.get("name"))}</div>
              <div style="font-size:11px;margin-top:6px;color:#94a3b8;">
                <span style="color:#22c55e;">{c.get("pass", c.get("passed", 0))}通过</span>
                {f'<span style="color:#eab308;margin-left:6px;">{c.get("warning", 0)}关注</span>' if c.get("warning") else ""}
                {f'<span style="color:#ef4444;margin-left:6px;">{c.get("fail", c.get("failed", 0))}失败</span>' if (c.get("fail", c.get("failed", 0)) or 0) else ""}
              </div>
              <div style="font-size:18px;font-weight:800;margin-top:4px;color:{_grade_color(sc)};">{sc}分</div>
            </div>''')
        out += f'<div style="display:flex;gap:10px;flex-wrap:wrap;margin:10px 0;">{"" .join(cards)}</div>'
    if content.get("checks"):
        rows = []
        for c in content["checks"]:
            dot = STATUS_COLORS.get(c.get("status"), "#64748b")
            rows.append(f'''
            <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:10px 12px;margin:5px 0;">
              <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;">
                <div style="display:flex;align-items:center;gap:8px;">
                  <span style="width:8px;height:8px;border-radius:50%;background:{dot};display:inline-block;"></span>
                  <code style="font-size:10px;color:#64748b;">{_esc(c.get("id"))}</code>
                  <span style="font-size:12px;color:#cbd5e1;">{_esc(c.get("name"))}</span>
                </div>
                <span style="font-size:11px;font-weight:700;color:{dot};">{_esc(c.get("status_label"))}</span>
              </div>
            </div>''')
        out += "".join(rows)
    return out


# ════════════ 主渲染 ════════════
def render_html_report(content: dict, meta: dict, title: str = "") -> str:
    """content: 报告结构化数据（不含 _meta 亦可）；meta: _meta 或等价字典。"""
    if not isinstance(content, dict):
        content = {}
    meta = meta or {}
    rtype = meta.get("report_type") or "security_summary"
    gen_at = meta.get("generated_at") or meta.get("created_at") or ""
    filters = meta.get("filters") or {}
    title = title or meta.get("title") or {
        "security_summary": "安全总览报告", "vuln_detail": "漏洞明细报告",
        "sla_report": "SLA 合规报告", "trend": "趋势分析报告",
        "compliance": "合规检查清单",
    }.get(rtype, rtype)

    sections = []
    rendered = set()

    # 总览 KPI
    if "summary" in content and isinstance(content["summary"], dict) and rtype != "compliance":
        s = content["summary"]
        cards = []
        labelmap = {
            "total_projects": ("项目数", "#e2e8f0"), "total_vulnerabilities": ("漏洞总数", "#e2e8f0"),
            "open_vulnerabilities": ("未修复", "#f59e0b"), "fixed_vulnerabilities": ("已修复", "#22c55e"),
            "critical_count": ("严重", "#ef4444"), "high_count": ("高危", "#f97316"),
            "medium_count": ("中危", "#eab308"), "low_count": ("低危", "#3b82f6"),
            "overall_fix_rate": ("整体修复率", "#60a5fa"), "total_tracked": ("跟踪中", "#e2e8f0"),
            "compliance_rate": ("SLA合规率", "#60a5fa"),
        }
        for k, (lab, col) in labelmap.items():
            if k in s:
                val = f'{s[k]}%' if "rate" in k else s[k]
                cards.append((lab, val, col))
        if cards:
            sections.append(_section("总览", _kpi_cards(cards)))
            rendered.add("summary")

    # 风险评估
    if "risk_assessment" in content and isinstance(content["risk_assessment"], dict):
        ra = content["risk_assessment"]
        sections.append(_section("风险评估", _risk_banner(
            ra.get("level", ""), ra.get("critical_open", 0), ra.get("high_open", 0), ra.get("recommendation", ""))))
        rendered.add("risk_assessment")

    # security_summary 专属
    if rtype == "security_summary":
        if "severity_distribution" in content:
            sections.append(_section("严重度分布",
                _svg_donut(content["severity_distribution"], _sev_color)))
            rendered.add("severity_distribution")
        if "status_distribution" in content:
            sections.append(_section("漏洞状态分布",
                _svg_hbars(content["status_distribution"], lambda k: STATUS_COLORS.get(str(k).lower(), "#64748b"))))
            rendered.add("status_distribution")
        if "fix_rate" in content and isinstance(content["fix_rate"], dict):
            cards = [(SEV_LABELS.get(str(k).lower(), k), f"{v}%", _sev_color(k)) for k, v in content["fix_rate"].items()]
            sections.append(_section("修复率分析", _kpi_cards(cards)))
            rendered.add("fix_rate")
        if "tool_coverage" in content and isinstance(content["tool_coverage"], dict):
            tc = content["tool_coverage"]
            cards = [(k.replace("_", " "), v, "#60a5fa") for k, v in tc.items()]
            sections.append(_section("工具覆盖情况", _kpi_cards(cards)))
            rendered.add("tool_coverage")
        if "knowledge_base_stats" in content and isinstance(content["knowledge_base_stats"], dict):
            kb = content["knowledge_base_stats"]
            sections.append(_section("知识库统计", _kpi_cards([
                ("总文章数", kb.get("total_articles", 0), "#22c55e"),
                ("分类数", kb.get("categories", 0), "#22c55e")])))
            rendered.add("knowledge_base_stats")
        if "top_vulnerabilities" in content:
            sections.append(_section("TOP 高危漏洞", _top_vulns(content["top_vulnerabilities"])))
            rendered.add("top_vulnerabilities")

    # vuln_detail 专属
    if rtype == "vuln_detail":
        if "totals" in content:
            sections.append(_section("按严重度统计", _svg_hbars(content["totals"], _sev_color)))
            rendered.add("totals")
        if "cwe_distribution" in content:
            sections.append(_section("Top CWE 类型分布", _svg_hbars(content["cwe_distribution"], lambda k: "#8b5cf6")))
            rendered.add("cwe_distribution")
        if "cvss_distribution" in content:
            sections.append(_section("CVSS 分档统计", _svg_hbars(content["cvss_distribution"], lambda k: "#a855f7")))
            rendered.add("cvss_distribution")
        if "tool_source" in content:
            tags = "".join(f'<span style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:4px 10px;font-size:12px;color:#cbd5e1;margin:3px;">{_esc(t)}: <b style="color:#60a5fa;">{n}</b></span>' for t, n in content["tool_source"].items())
            sections.append(_section("扫描工具来源", f'<div>{tags}</div>'))
            rendered.add("tool_source")
        if "affected_assets" in content and isinstance(content["affected_assets"], list):
            cards = [(a.get("project", "?"), f'{a.get("file_count", 0)} 文件', "#e2e8f0") for a in content["affected_assets"][:6]]
            sections.append(_section("受影响资产", _kpi_cards(cards)))
            rendered.add("affected_assets")
        if "items" in content and isinstance(content["items"], list):
            rows = [[_esc(v.get("severity", "")).upper(), _esc(v.get("title")), _esc(v.get("cve_id")),
                     _esc(str(v.get("file_path", "")).split("/")[-1])] for v in content["items"][:30]]
            sections.append(_section(f"漏洞明细（{content.get('total', len(content['items']))} 条，预览前 {len(rows)}）",
                _table(["严重度", "标题", "CVE", "文件"], rows,
                       row_color_fn=lambda it: SEV_COLORS.get(str(it[0]).lower(), None))))
            rendered.add("items")

    # sla_report 专属
    if rtype == "sla_report":
        for key, lab, col in [("breached", "已超时 SLA", "#ef4444"), ("urgent", "即将到期 <24h", "#f97316"),
                              ("on_track", "正常跟踪", "#22c55e"), ("closed_or_fixed", "已关闭/修复", "#60a5fa")]:
            if key in content and isinstance(content[key], dict) and "count" in content[key]:
                sections.append(_section(lab, _kpi_cards([(lab, content[key]["count"], col)])))
                rendered.add(key)
        if "assignee_performance" in content and isinstance(content["assignee_performance"], list):
            rows = [[_esc(a.get("assignee")), a.get("total", 0), a.get("breached", 0),
                     a.get("fixed", 0), f'{a.get("sla_rate", 0)}%'] for a in content["assignee_performance"]]
            sections.append(_section("处理人 SLA 表现", _table(
                ["处理人", "总数", "超时", "已修", "SLA率"], rows)))
            rendered.add("assignee_performance")
        if "avg_time_to_fix" in content and isinstance(content["avg_time_to_fix"], dict):
            t = content["avg_time_to_fix"]
            sections.append(_section("平均修复时间", _kpi_cards([
                ("平均(小时)", t.get("hours", 0), "#60a5fa"), ("平均(天)", t.get("days", 0), "#60a5fa"),
                ("样本数", t.get("samples", 0), "#94a3b8")])))
            rendered.add("avg_time_to_fix")

    # trend 专属
    if rtype == "trend":
        if "monthly_scans" in content:
            sections.append(_section("月度扫描趋势", _svg_vbars(content["monthly_scans"], "scan_count", "month", "#3b82f6")))
            rendered.add("monthly_scans")
        if "fix_rate_trend" in content:
            sections.append(_section("修复率趋势", _svg_vbars(content["fix_rate_trend"], "fix_rate", "month", "#22c55e")))
            rendered.add("fix_rate_trend")
        if "tool_usage" in content and isinstance(content["tool_usage"], dict):
            tags = "".join(f'<span style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:4px 10px;font-size:12px;color:#cbd5e1;margin:3px;">{_esc(t)}: <b style="color:#a855f7;">{len(d)}月</b></span>' for t, d in content["tool_usage"].items())
            sections.append(_section("工具使用趋势", f'<div>{tags}</div>'))
            rendered.add("tool_usage")

    # compliance 专属
    if rtype == "compliance":
        sections.append(_section("合规评估", _compliance_block(content)))
        rendered.update({"summary", "categories", "checks", "compliance_details"})

    # 通用兜底：渲染未处理过的顶级 dict / list（保证数据不丢）
    for k, v in content.items():
        if k in rendered or k == "_meta":
            continue
        if isinstance(v, dict):
            sec = _svg_hbars(v, lambda kk: "#64748b")
            if sec:
                sections.append(_section(str(k), sec))
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            rows = [[_esc(it.get(kk)) for kk in list(v[0].keys())[:5]] for it in v[:20]]
            sections.append(_section(str(k), _table(list(v[0].keys())[:5], rows)))
        elif isinstance(v, list):
            items = "".join(f'<div style="font-size:12px;color:#cbd5e1;padding:3px 0;">• {_esc(x)}</div>' for x in v[:20])
            sections.append(_section(str(k), items or "<div style='color:#64748b'>空</div>"))
        elif isinstance(v, (int, float, str)):
            sections.append(_section(str(k), f'<div style="font-size:20px;font-weight:800;color:#e2e8f0;">{_esc(v)}</div>'))

    filter_str = ", ".join(f"{k}={v}" for k, v in filters.items()) if filters else ""

    return f'''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#060b16; color:#e2e8f0;
    font-family: -apple-system, "Segoe UI", "Microsoft YaHei", "PingFang SC", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased; }}
  .wrap {{ max-width: 920px; margin: 0 auto; padding: 28px 22px 60px; }}
  h1 {{ font-size: 24px; margin: 0; color: #f1f5f9; }}
  a {{ color:#60a5fa; }}
  @media print {{ body {{ background:#fff; }} .sect {{ break-inside: avoid; }} }}
</style></head>
<body><div class="wrap">
  <div style="display:flex;justify-content:space-between;align-items:flex-end;border-bottom:2px solid #1e293b;padding-bottom:16px;margin-bottom:8px;">
    <div>
      <div style="font-size:13px;letter-spacing:2px;color:#3b82f6;font-weight:700;">SENTINEL</div>
      <h1 style="margin-top:6px;">{_esc(title)}</h1>
    </div>
    <div style="text-align:right;font-size:11px;color:#64748b;line-height:1.6;">
      <div>Application Security Platform</div>
      <div>{_esc(gen_at)}</div>
      {f'<div>筛选: {_esc(filter_str)}</div>' if filter_str else ""}
    </div>
  </div>
  {''.join(sections)}
  <div style="margin-top:24px;padding-top:14px;border-top:1px solid #1e293b;font-size:11px;color:#475569;text-align:center;">
    Sentinel AppSec Platform · 本报告由系统自动生成 · Report ID 见导出元数据
  </div>
</div></body></html>'''
