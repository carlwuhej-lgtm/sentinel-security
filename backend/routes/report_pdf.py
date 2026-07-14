# ─── 升级版可视化 PDF 安全报告渲染器 ───
"""
render_pdf_report(content, meta, row) -> BytesIO(PDF)

在原有 fpdf2 基础上做可视化升级（替代 reports.py 的平铺 pdf_report）：
  - 封面 KPI 概览
  - 严重度 / 状态 / 修复率：彩色横向条形
  - 趋势：彩色柱状图
  - TOP 漏洞：按严重度配色列表
  - 合规：评级圆环 + 分类卡片 + 检查项带状态色点
  - 风险等级色带

复用 reports.py 的中文字体加载逻辑（SimHei / NotoSansSC / msyh）。
"""

import os
import io

from fpdf import FPDF, XPos, YPos

# 配色（与前端 / HTML 报告保持一致）
SEV_RGB = {
    "critical": (239, 68, 68), "high": (249, 115, 22), "medium": (234, 179, 8),
    "low": (59, 130, 246), "info": (100, 116, 139), "unknown": (100, 116, 139),
}
STATUS_RGB = {
    "open": (245, 158, 11), "fixed": (34, 197, 94), "ignored": (100, 116, 139),
    "breached": (239, 68, 68), "urgent": (249, 115, 22), "on_track": (34, 197, 94),
    "pass": (34, 197, 94), "warning": (234, 179, 8), "fail": (239, 68, 68),
}
RISK_RGB = {"严重": (239, 68, 68), "高": (249, 115, 22), "中": (234, 179, 8), "低": (34, 197, 94)}
SEV_LABELS = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息", "unknown": "未知"}


def _hex2rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _sev_rgb(key):
    return SEV_RGB.get(str(key).lower(), (100, 116, 139))


class ReportPDF(FPDF):
    def __init__(self, font_name="Helvetica"):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=16)
        self.font_name = font_name
        self.set_margins(15, 15, 15)

    # ── 基础工具 ──
    def safe(self, text):
        if text is None:
            return ""
        if isinstance(text, (int, float)):
            return str(text)
        if self.font_name == "Helvetica":
            try:
                return str(text).encode("latin-1", "replace").decode("latin-1")
            except Exception:
                return str(text)[:50]
        return str(text)

    def ensure(self, need):
        if self.get_y() + need > 280:
            self.add_page()

    def rrect(self, x, y, w, h, style="DF", r=2):
        # fpdf2 >= 2.7 移除了 rounded_rect；为稳定性用普通矩形（方角），视觉仍清晰
        self.rect(x, y, w, h, style=style)

    def section_title(self, label):
        self.ensure(20)
        self.set_fill_color(241, 245, 249)
        self.set_text_color(30, 64, 175)
        self.set_font(self.font_name, "B", 12)
        self.cell(0, 9, self.safe(f"  {label}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        self.ln(3)
        self.set_text_color(30, 41, 59)

    # ── KPI 卡片行 ──
    def kpi_row(self, cards, max_cols=4):
        """cards: list[(label, value, (r,g,b))]"""
        if not cards:
            return
        self.ensure(24)
        n = min(len(cards), max_cols)
        gap = 4
        total_w = 180
        cw = (total_w - gap * (n - 1)) / n
        x0 = self.l_margin
        y0 = self.get_y()
        for i, (label, value, color) in enumerate(cards[:max_cols]):
            x = x0 + i * (cw + gap)
            self.set_fill_color(15, 23, 42)
            self.set_draw_color(30, 41, 59)
            self.rrect(x, y0, cw, 20, "DF", 2)
            self.set_xy(x, y0 + 3)
            self.set_text_color(*color)
            self.set_font(self.font_name, "B", 13)
            self.cell(cw, 8, self.safe(str(value)), align="C")
            self.set_xy(x, y0 + 12)
            self.set_text_color(100, 116, 139)
            self.set_font(self.font_name, "", 7.5)
            self.cell(cw, 6, self.safe(str(label)), align="C")
        self.set_xy(self.l_margin, y0 + 22)
        self.set_text_color(30, 41, 59)

    # ── 横向条形 ──
    def hbars(self, data, color_of, unit=""):
        items = [(k, v) for k, v in data.items() if isinstance(v, (int, float))]
        if not items:
            return
        self.ensure(8 + 9 * len(items))
        mx = max(v for _, v in items) or 1
        x0 = self.l_margin
        w = 180
        for k, v in items:
            self.ensure(9)
            self.set_font(self.font_name, "", 8.5)
            self.set_text_color(71, 85, 105)
            self.cell(34, 7, self.safe(SEV_LABELS.get(str(k).lower(), str(k))))
            bar_x = x0 + 36
            bar_w = w - 36 - 22
            self.set_fill_color(30, 41, 59)
            self.rect(bar_x, self.get_y() + 1, bar_w, 5, "F")
            pct = (v / mx) * bar_w
            col = color_of(k)
            self.set_fill_color(*col)
            self.rect(bar_x, self.get_y() + 1, max(pct, 1), 5, "F")
            self.set_xy(bar_x + bar_w + 1, self.get_y())
            self.set_text_color(30, 41, 59)
            self.set_font(self.font_name, "B", 8.5)
            self.cell(20, 7, self.safe(f"{v}{unit}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

    # ── 风险色带 ──
    def risk_banner(self, level, critical_open=0, high_open=0, recommendation=""):
        col = RISK_RGB.get(level, (100, 116, 139))
        self.ensure(26)
        y0 = self.get_y()
        self.set_fill_color(*col)
        self.set_draw_color(*col)
        self.rrect(self.l_margin, y0, 180, 22, "DF", 2)
        self.set_xy(self.l_margin + 4, y0 + 3)
        self.set_text_color(255, 255, 255)
        self.set_font(self.font_name, "B", 12)
        txt = f"风险等级：{level}"
        if critical_open:
            txt += f"   严重开放 {critical_open}"
        if high_open:
            txt += f"   高危开放 {high_open}"
        self.cell(0, 7, self.safe(txt), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if recommendation:
            self.set_x(self.l_margin + 4)
            self.set_font(self.font_name, "", 8)
            self.set_text_color(241, 245, 249)
            self.multi_cell(172, 5, self.safe(recommendation))
        self.set_xy(self.l_margin, y0 + 24)
        self.set_text_color(30, 41, 59)

    # ── TOP 漏洞列表 ──
    def top_vulns(self, items):
        if not items:
            return
        for v in items[:15]:
            self.ensure(12)
            sev = str(v.get("severity", "")).lower()
            col = _sev_rgb(sev)
            y0 = self.get_y()
            self.set_fill_color(15, 23, 42)
            self.set_draw_color(30, 41, 59)
            self.rrect(self.l_margin, y0, 180, 10, "DF", 1.5)
            self.set_xy(self.l_margin + 2, y0 + 2)
            self.set_text_color(*col)
            self.set_font(self.font_name, "B", 8)
            self.cell(16, 6, self.safe(f"[{SEV_LABELS.get(sev, sev).upper()}]"))
            self.set_text_color(226, 232, 240)
            self.set_font(self.font_name, "", 8)
            title = str(v.get("title", ""))[:42]
            extra = ""
            if v.get("cve_id"):
                extra += f"  {v['cve_id']}"
            if v.get("sla_breached"):
                extra += "  SLA超时"
            self.cell(120, 6, self.safe(title + extra))
            self.set_text_color(100, 116, 139)
            self.set_xy(self.l_margin + 140, y0 + 2)
            self.cell(38, 6, self.safe(str(v.get("file_path", "")).split("/")[-1][:22]), align="R")
            self.set_xy(self.l_margin, y0 + 11)
        self.ln(1)

    # ── 表格 ──
    def table(self, headers, rows, row_color_fn=None, max_rows=25):
        if not rows:
            return
        self.ensure(14)
        widths = [180 / len(headers)] * len(headers)
        # 表头
        self.set_fill_color(30, 64, 175)
        self.set_text_color(255, 255, 255)
        self.set_font(self.font_name, "B", 7.5)
        for h, w in zip(headers, widths):
            self.cell(w, 7, self.safe(str(h))[:16], border=0, fill=True, align="C")
        self.ln()
        self.set_text_color(30, 41, 59)
        for r in rows[:max_rows]:
            self.ensure(8)
            c = row_color_fn(r) if row_color_fn else None
            if c:
                self.set_fill_color(c[0], c[1], c[2])
                fill = True
            else:
                self.set_fill_color(248, 250, 252)
                fill = True
            self.set_font(self.font_name, "", 7.5)
            for val, w in zip(r, widths):
                self.cell(w, 6.5, self.safe(str(val))[:20], border=0, fill=fill, align="C")
            self.ln()
        self.ln(2)

    # ── 柱状图（趋势）──
    def vbars(self, items, value_key, label_key, color=(59, 130, 246), h=46):
        if not items:
            return
        self.ensure(h + 14)
        nums = [float(it.get(value_key, 0) or 0) for it in items]
        mx = max(nums) or 1
        x0 = self.l_margin
        n = len(items)
        slot = 180 / n
        bw = min(slot * 0.6, 22)
        base_y = self.get_y() + h
        for i, (it, num) in enumerate(zip(items, nums)):
            bh = (num / mx) * (h - 10)
            cx = x0 + i * slot + (slot - bw) / 2
            self.set_fill_color(*color)
            self.rect(cx, base_y - bh, bw, bh, "F")
            self.set_text_color(71, 85, 105)
            self.set_font(self.font_name, "", 6.5)
            self.set_xy(cx - 4, base_y - bh - 6)
            self.cell(bw + 8, 4, self.safe(str(int(num))), align="C")
            self.set_xy(cx - 4, base_y + 1)
            self.cell(bw + 8, 4, self.safe(str(it.get(label_key, ""))[-5:]), align="C")
        self.set_xy(self.l_margin, base_y + 8)
        self.set_text_color(30, 41, 59)

    # ── 合规评分卡 ──
    def compliance(self, content):
        s = content.get("summary") or {}
        if "weighted_score" in s:
            self.ensure(40)
            y0 = self.get_y()
            score = float(s.get("weighted_score", 0))
            gc = _hex2rgb(_grade_hex(score))
            cx, cy, r = self.l_margin + 22, y0 + 20, 18
            self.set_fill_color(*gc)
            self.circle(cx, cy, r, "F")
            self.set_fill_color(11, 18, 32)
            self.circle(cx, cy, r - 5, "F")
            self.set_text_color(*gc)
            self.set_font(self.font_name, "B", 14)
            self.set_xy(cx - 16, cy - 7)
            self.cell(32, 8, self.safe(str(score)), align="C")
            self.set_xy(cx - 16, cy + 1)
            self.set_font(self.font_name, "", 6.5)
            self.cell(32, 5, self.safe(f"评级 {s.get('grade','')}"), align="C")
            # KPI
            self.set_xy(self.l_margin + 50, y0)
            self.kpi_row([
                ("检查项", s.get("total_checks", 0), (226, 232, 240)),
                ("已通过", s.get("passed", 0), (34, 197, 94)),
                ("需关注", s.get("warning", 0), (234, 179, 8)),
                ("未通过", s.get("failed", 0), (239, 68, 68)),
            ], max_cols=4)
            self.set_text_color(30, 41, 59)
        if content.get("categories"):
            self.ensure(10)
            cards = content["categories"][:4]
            gap = 4
            cw = (180 - gap * (len(cards) - 1)) / len(cards)
            x0 = self.l_margin
            y0 = self.get_y()
            for i, c in enumerate(cards):
                x = x0 + i * (cw + gap)
                sc = float(c.get("score", 0))
                self.set_fill_color(15, 23, 42)
                self.set_draw_color(30, 41, 59)
                self.rrect(x, y0, cw, 24, "DF", 2)
                self.set_xy(x, y0 + 2)
                self.set_text_color(226, 232, 240)
                self.set_font(self.font_name, "B", 8)
                self.cell(cw, 6, self.safe(str(c.get("name", ""))[:10]), align="C")
                self.set_xy(x, y0 + 14)
                self.set_text_color(*_hex2rgb(_grade_hex(sc)))
                self.set_font(self.font_name, "B", 12)
                self.cell(cw, 8, self.safe(f"{int(sc)}分"), align="C")
            self.set_xy(self.l_margin, y0 + 26)
            self.set_text_color(30, 41, 59)
        if content.get("checks"):
            self.ensure(8)
            for c in content["checks"]:
                self.ensure(9)
                y0 = self.get_y()
                col = STATUS_RGB.get(c.get("status"), (100, 116, 139))
                self.set_fill_color(*col)
                self.circle(self.l_margin + 3, y0 + 3, 1.6, "F")
                self.set_xy(self.l_margin + 7, y0)
                self.set_text_color(71, 85, 105)
                self.set_font(self.font_name, "", 7.5)
                self.cell(24, 6, self.safe(str(c.get("id", ""))))
                self.set_text_color(30, 41, 59)
                self.cell(0, 6, self.safe(str(c.get("name", ""))[:40]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)


def _grade_hex(score):
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


def _load_font(pdf: ReportPDF):
    font_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fonts")
    for font_file, label in [("SimHei.ttf", "SimHei"), ("NotoSansSC-Regular.ttf", "NotoSansSC"),
                             ("msyh.ttf", "MicrosoftYaHei")]:
        path = os.path.join(font_dir, font_file)
        if os.path.isfile(path):
            try:
                pdf.add_font(label, "", path)
                pdf.add_font(label, "B", path)
                pdf.font_name = label
                return True
            except Exception:
                continue
    return False


def render_pdf_report(content: dict, meta: dict, row: dict) -> io.BytesIO:
    """返回 PDF 字节流（BytesIO）。"""
    pdf = ReportPDF()
    _load_font(pdf)
    fn = pdf.font_name

    rtype = (meta or {}).get("report_type") or (row or {}).get("report_type") or "security_summary"
    gen_at = (meta or {}).get("generated_at") or str((row or {}).get("created_at", ""))
    filters = (meta or {}).get("filters") or {}
    title = (row or {}).get("title") or (meta or {}).get("title") or {
        "security_summary": "安全总览报告", "vuln_detail": "漏洞明细报告",
        "sla_report": "SLA 合规报告", "trend": "趋势分析报告", "compliance": "合规检查清单",
    }.get(rtype, rtype)

    # ══ 封面 ══
    pdf.add_page()
    pdf.set_font(fn, "B", 22)
    pdf.set_text_color(30, 64, 175)
    pdf.cell(0, 14, "SENTINEL", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.set_text_color(100, 116, 139)
    pdf.set_font(fn, "", 10)
    pdf.cell(0, 8, "Application Security Platform", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(8)
    pdf.set_draw_color(30, 64, 175)
    pdf.set_line_width(0.5)
    y = pdf.get_y()
    pdf.line(40, y, 170, y)
    pdf.ln(8)
    pdf.set_text_color(30, 41, 59)
    pdf.set_font(fn, "B", 17)
    pdf.multi_cell(0, 10, pdf.safe(title), align="C")
    pdf.ln(3)
    pdf.set_font(fn, "", 9)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 5, pdf.safe(f"Sentinel AppSec Platform  |  {gen_at}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    if filters:
        fs = ", ".join(f"{k}={v}" for k, v in filters.items())
        pdf.cell(0, 5, pdf.safe(f"筛选条件: {fs}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(10)

    # ══ 内容 ══
    if "summary" in content and isinstance(content["summary"], dict) and rtype != "compliance":
        s = content["summary"]
        labelmap = {
            "total_projects": ("项目数", (226, 232, 240)), "total_vulnerabilities": ("漏洞总数", (226, 232, 240)),
            "open_vulnerabilities": ("未修复", (245, 158, 11)), "fixed_vulnerabilities": ("已修复", (34, 197, 94)),
            "critical_count": ("严重", (239, 68, 68)), "high_count": ("高危", (249, 115, 22)),
            "medium_count": ("中危", (234, 179, 8)), "low_count": ("低危", (59, 130, 246)),
            "overall_fix_rate": ("整体修复率", (96, 165, 250)), "total_tracked": ("跟踪中", (226, 232, 240)),
            "compliance_rate": ("SLA合规率", (96, 165, 250)),
        }
        cards = []
        for k, (lab, col) in labelmap.items():
            if k in s:
                val = f'{s[k]}%' if "rate" in k else s[k]
                cards.append((lab, val, col))
        if cards:
            pdf.section_title("总览")
            pdf.kpi_row(cards, max_cols=4)

    if "risk_assessment" in content and isinstance(content["risk_assessment"], dict):
        ra = content["risk_assessment"]
        pdf.section_title("风险评估")
        pdf.risk_banner(ra.get("level", ""), ra.get("critical_open", 0), ra.get("high_open", 0), ra.get("recommendation", ""))

    if rtype == "security_summary":
        if "severity_distribution" in content:
            pdf.section_title("严重度分布")
            pdf.hbars(content["severity_distribution"], _sev_rgb)
        if "status_distribution" in content:
            pdf.section_title("漏洞状态分布")
            pdf.hbars(content["status_distribution"], lambda k: STATUS_RGB.get(str(k).lower(), (100, 116, 139)))
        if "fix_rate" in content and isinstance(content["fix_rate"], dict):
            cards = [(SEV_LABELS.get(str(k).lower(), k), f"{v}%", _sev_rgb(k)) for k, v in content["fix_rate"].items()]
            pdf.section_title("修复率分析")
            pdf.kpi_row(cards, max_cols=4)
        if "tool_coverage" in content and isinstance(content["tool_coverage"], dict):
            tc = content["tool_coverage"]
            pdf.section_title("工具覆盖情况")
            pdf.kpi_row([(str(k).replace("_", " "), v, (96, 165, 250)) for k, v in tc.items()], max_cols=5)
        if "knowledge_base_stats" in content and isinstance(content["knowledge_base_stats"], dict):
            kb = content["knowledge_base_stats"]
            pdf.section_title("知识库统计")
            pdf.kpi_row([("总文章数", kb.get("total_articles", 0), (34, 197, 94)),
                         ("分类数", kb.get("categories", 0), (34, 197, 94))], max_cols=4)
        if "top_vulnerabilities" in content:
            pdf.section_title("TOP 高危漏洞")
            pdf.top_vulns(content["top_vulnerabilities"])

    if rtype == "vuln_detail":
        if "totals" in content:
            pdf.section_title("按严重度统计")
            pdf.hbars(content["totals"], _sev_rgb)
        if "cwe_distribution" in content:
            pdf.section_title("Top CWE 类型分布")
            pdf.hbars(content["cwe_distribution"], lambda k: (139, 92, 246))
        if "cvss_distribution" in content:
            pdf.section_title("CVSS 分档统计")
            pdf.hbars(content["cvss_distribution"], lambda k: (168, 85, 247))
        if "items" in content and isinstance(content["items"], list):
            rows = [[str(v.get("severity", "")).upper(), str(v.get("title", ""))[:24],
                     str(v.get("cve_id", "")), str(v.get("file_path", "")).split("/")[-1][:18]]
                    for v in content["items"][:30]]
            pdf.section_title(f"漏洞明细（{content.get('total', len(content['items']))} 条，预览前 {len(rows)}）")
            pdf.table(["严重度", "标题", "CVE", "文件"], rows,
                      row_color_fn=lambda it: _sev_rgb(it[0]))

    if rtype == "sla_report":
        for key, lab, col in [("breached", "已超时 SLA", (239, 68, 68)), ("urgent", "即将到期 <24h", (249, 115, 22)),
                              ("on_track", "正常跟踪", (34, 197, 94)), ("closed_or_fixed", "已关闭/修复", (96, 165, 250))]:
            if key in content and isinstance(content[key], dict) and "count" in content[key]:
                pdf.section_title(lab)
                pdf.kpi_row([(lab, content[key]["count"], col)], max_cols=4)
        if "assignee_performance" in content and isinstance(content["assignee_performance"], list):
            rows = [[a.get("assignee", ""), a.get("total", 0), a.get("breached", 0),
                     a.get("fixed", 0), f'{a.get("sla_rate", 0)}%'] for a in content["assignee_performance"]]
            pdf.section_title("处理人 SLA 表现")
            pdf.table(["处理人", "总数", "超时", "已修", "SLA率"], rows)
        if "avg_time_to_fix" in content and isinstance(content["avg_time_to_fix"], dict):
            t = content["avg_time_to_fix"]
            pdf.section_title("平均修复时间")
            pdf.kpi_row([("平均(小时)", t.get("hours", 0), (96, 165, 250)),
                         ("平均(天)", t.get("days", 0), (96, 165, 250)),
                         ("样本数", t.get("samples", 0), (100, 116, 139))], max_cols=4)

    if rtype == "trend":
        if "monthly_scans" in content:
            pdf.section_title("月度扫描趋势")
            pdf.vbars(content["monthly_scans"], "scan_count", "month", color=(59, 130, 246))
        if "fix_rate_trend" in content:
            pdf.section_title("修复率趋势")
            pdf.vbars(content["fix_rate_trend"], "fix_rate", "month", color=(34, 197, 94))

    if rtype == "compliance":
        pdf.section_title("合规评估")
        pdf.compliance(content)

    # 页脚
    pdf.ln(4)
    pdf.set_draw_color(203, 213, 225)
    pdf.set_line_width(0.3)
    y = pdf.get_y()
    pdf.line(30, y, 180, y)
    pdf.ln(3)
    pdf.set_font(fn, "", 7)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 4, pdf.safe(f"Sentinel AppSec Platform  |  Page {{nb}}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.alias_nb_pages()

    out = io.BytesIO()
    pdf.output(out)
    out.seek(0)
    return out
