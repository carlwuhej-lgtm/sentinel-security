"""哨兵安全管理平台 — MCP Server (stdio 传输)

让 AI 客户端（Claude Desktop / Cursor / WorkBuddy 等支持 MCP 的客户端）通过标准
MCP 协议调用 Sentinel 的安全能力：只读漏洞查询、知识库检索、列出/运行「已审批」技能。

## 安全边界（符合项目需求，必须守住）
- 最小权限：仅暴露「只读查询」+「运行已审批技能」。不暴露认证/加密/用户管理/写管理。
- 审批闸门复用：run_skill 仅允许 approval=approved 的技能（第三方技能默认 pending，
  不可经 MCP 运行）——与前端技能中心同一套闸门。
- 审计：每次工具调用写 backend/mcp_audit.log（stdio 模式 stdout 已被 MCP 协议占用，
  故审计只能写文件，禁止 print 到 stdout）。
- 部署约束：仅在受信本地/内网运行；公网暴露需套反向代理 + Bearer 认证
  （预留 SENTINEL_MCP_TOKEN 环境变量用于将来 HTTP 传输校验）。

## 与 routes/skills.py 的关系
本文件自包含「技能清单加载 + script 运行 + CVSS 定级」逻辑，避免 import Flask app
（MCP 是独立进程，无 flask.g 上下文）。如 routes/skills.py 改动以下逻辑，请同步此处：
  - SKILLS 内置列表 / load_manifest_skills / _cvss_to_severity / script runner
"""
import os
import re
import sys
import json
import glob
import sqlite3
import logging

# 让 import 能找到 config（仅依赖 config.DATABASE_PATH，不依赖 Flask）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import DATABASE_PATH  # noqa: E402

# ── 审计日志（写文件，不碰 stdout） ──────────────────────────────────────
AUDIT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_audit.log")
audit = logging.getLogger("sentinel_mcp")
audit.setLevel(logging.INFO)
_ah = logging.FileHandler(AUDIT_LOG, encoding="utf-8")
_ah.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
audit.addHandler(_ah)
audit.propagate = False

from mcp.server.fastmcp import FastMCP, Context  # noqa: E402

mcp = FastMCP("sentinel-security")

# ── 自包含技能清单逻辑（与 routes/skills.py 同步） ─────────────────────────
SKILLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills")
SAFE_ENV_KEYS = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP",
                 "LANG", "LC_ALL", "COMSPEC", "PATHEXT", "HOME", "USERNAME")

SKILLS = [
    {
        "id": "vuln-triage",
        "name": "漏洞智能分诊",
        "description": "依据 CVSS 评分对全部漏洞重新定级，修正 severity 与评分不一致的项。",
        "risk": "low", "module": "vulnerabilities", "writes": True,
        "source": "builtin", "approval": "approved",
    },
    {
        "id": "code-audit",
        "name": "安全知识审查清单生成",
        "description": "基于知识库生成指定语言的安全代码审查清单。只读。",
        "risk": "low", "module": "knowledge_base", "writes": False,
        "source": "builtin", "approval": "approved",
    },
]


def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def load_manifest_skills() -> list:
    out = []
    if not os.path.isdir(SKILLS_DIR):
        return out
    for f in sorted(glob.glob(os.path.join(SKILLS_DIR, "*.json"))):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                m = json.load(fh)
        except Exception:
            continue
        if not isinstance(m, dict) or not m.get("id"):
            continue
        m.setdefault("source", "user")
        m.setdefault("approval", "approved")
        m.setdefault("risk", "low")
        out.append(m)
    return out


def load_all_skills() -> list:
    out = [dict(s) for s in SKILLS]
    out.extend(load_manifest_skills())
    return out


def _safe_join_skills_dir(filename: str) -> str:
    base = os.path.realpath(SKILLS_DIR)
    target = os.path.realpath(os.path.join(base, filename))
    if target != base and not target.startswith(base + os.sep):
        raise ValueError("非法路径（疑似路径穿越）")
    return target


# ── DB 直连（不依赖 Flask） ──────────────────────────────────────────────
def get_db():
    db = sqlite3.connect(os.environ.get("SENTINEL_DB_PATH", DATABASE_PATH))
    db.row_factory = sqlite3.Row
    return db


def _strip_internal(skill: dict) -> dict:
    return {k: v for k, v in skill.items() if not k.startswith("_") and k != "writes"}


def _audit(tool: str, args: dict) -> None:
    audit.info("TOOL=%s ARGS=%s", tool, json.dumps(args, ensure_ascii=False)[:500])


# ── Tools ─────────────────────────────────────────────────────────────────
@mcp.tool()
def list_vulnerabilities(severity: str = "", limit: int = 50) -> dict:
    """列出漏洞。severity 可填 critical/high/medium/low（留空返回全部）；limit 默认 50。"""
    _audit("list_vulnerabilities", {"severity": severity, "limit": limit})
    db = get_db()
    sql = "SELECT * FROM vulnerabilities"
    where, params = [], []
    if severity:
        where.append("severity=?")
        params.append(severity)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY (cvss_score IS NULL), cvss_score DESC LIMIT ?"
    params.append(min(int(limit), 200))
    rows = db.execute(sql, params).fetchall()
    return {"count": len(rows), "items": [dict(r) for r in rows]}


@mcp.tool()
def get_vulnerability_stats() -> dict:
    """统计各严重度漏洞数量与总体情况，用于安全运营概览。"""
    _audit("get_vulnerability_stats", {})
    db = get_db()
    rows = db.execute(
        "SELECT COALESCE(severity,'unknown') AS severity, COUNT(*) AS c FROM vulnerabilities GROUP BY severity"
    ).fetchall()
    by_sev = {r["severity"]: r["c"] for r in rows}
    total = sum(by_sev.values())
    return {"total": total, "by_severity": by_sev}


@mcp.tool()
def search_knowledge(query: str = "", cwe: str = "") -> dict:
    """检索安全知识库（仅已发布文章）。query 为关键词；cwe 如 CWE-79。两者可组合。"""
    _audit("search_knowledge", {"query": query, "cwe": cwe})
    db = get_db()
    sql = "SELECT id, title, category, summary, tags FROM knowledge_articles"
    where, params = ["is_published=1"], []
    if cwe:
        where.append("(content LIKE ? OR tags LIKE ?)")
        params += [f"%{cwe}%", f"%{cwe}%"]
    if query:
        where.append("(title LIKE ? OR summary LIKE ? OR content LIKE ?)")
        params += [f"%{query}%", f"%{query}%", f"%{query}%"]
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id LIMIT 50"
    rows = db.execute(sql, params).fetchall()
    return {"count": len(rows), "items": [dict(r) for r in rows]}


@mcp.tool()
def list_skills() -> dict:
    """列出当前已上架（approved）的技能。MCP 仅能运行这些已审批技能。"""
    _audit("list_skills", {})
    approved = [s for s in load_all_skills() if s.get("approval") == "approved"]
    visible = [_strip_internal(s) for s in approved]
    return {"count": len(visible), "skills": visible}


@mcp.tool()
def run_skill(skill_id: str, params: str = "{}") -> dict:
    """运行一个已审批技能。skill_id 取自 list_skills；params 为 JSON 字符串（可选，如 '{\"language\":\"java\"}'）。

    安全：仅允许 approval=approved 的技能；第三方（pending）技能会被拒绝。
    """
    _audit("run_skill", {"skill_id": skill_id})
    skill = next((s for s in load_all_skills() if s["id"] == skill_id), None)
    if not skill:
        return {"error": "skill not found", "id": skill_id}
    if skill.get("approval") != "approved":
        return {"error": "skill not approved（MCP 仅允许运行已审批技能）", "id": skill_id}
    try:
        if skill.get("source") == "builtin":
            return _run_builtin(skill, params)
        runner = skill.get("runner") or {}
        rtype = runner.get("type")
        if rtype == "script":
            return _run_script_runner(skill)
        if rtype == "http":
            return _run_http_runner(skill, params)
        return {"error": "unsupported runner", "id": skill_id}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "id": skill_id}


# ── 内置技能 / runner 实现（sqlite 直连，无 Flask 依赖） ───────────────────
def _run_builtin(skill: dict, params: str) -> dict:
    sid = skill["id"]
    db = get_db()
    if sid == "vuln-triage":
        rows = db.execute("SELECT id, cvss_score, severity FROM vulnerabilities").fetchall()
        changed = 0
        for r in rows:
            cvss = r["cvss_score"] or 0.0
            target = _cvss_to_severity(cvss) if cvss > 0 else (r["severity"] or "low")
            if target != r["severity"]:
                db.execute("UPDATE vulnerabilities SET severity=? WHERE id=?", (target, r["id"]))
                changed += 1
        db.commit()
        return {"skill": "vuln-triage", "updated": changed, "total": len(rows),
                "message": f"已重新定级 {changed}/{len(rows)} 个漏洞"}
    if sid == "code-audit":
        cwe_re = re.compile(r"CWE-(\d+)", re.IGNORECASE)
        try:
            payload = json.loads(params) if params else {}
        except Exception:
            payload = {}
        language = (payload.get("language") or "general").strip().lower()
        arts = db.execute(
            "SELECT title, category, summary, content, tags FROM knowledge_articles WHERE is_published=1"
        ).fetchall()
        items = []
        for a in arts:
            hit = cwe_re.search(a["content"] or "")
            items.append({
                "title": a["title"],
                "cwe": f"CWE-{hit.group(1)}" if hit else "",
                "category": a["category"],
                "summary": a["summary"] or "",
            })
        label = {"general": "通用", "java": "Java", "python": "Python",
                 "go": "Go", "javascript": "JavaScript/TypeScript", "js": "JavaScript/TypeScript"}.get(language, language)
        return {"skill": "code-audit", "language": language, "language_label": label,
                "items": items, "count": len(items)}
    return {"error": "unknown builtin", "id": sid}


def _run_script_runner(skill: dict) -> dict:
    import subprocess
    runner = skill["runner"]
    fname = runner.get("file") or ""
    if "/" in fname or "\\" in fname or ".." in fname or not fname.endswith(".py"):
        raise ValueError("script runner 文件名非法")
    path = _safe_join_skills_dir(fname)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"skill 脚本不存在: {fname}")
    timeout = int(runner.get("timeout", 15))
    safe_env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    # 强制子进程 UTF-8 输出（Windows 默认 GBK 会导致中文解码失败/卡死）
    safe_env.setdefault("PYTHONUTF8", "1")
    safe_env.setdefault("PYTHONIOENCODING", "utf-8")
    proc = subprocess.run([sys.executable, path], capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=timeout, env=safe_env)
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", errors="replace")
        raise RuntimeError(f"脚本执行失败: {err[:2000]}")
    raw = proc.stdout or b""
    try:
        out = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        out = {"raw": raw.decode("utf-8", errors="replace")[:4000]}
    return {"skill": skill["id"], "result": out}


def _run_http_runner(skill: dict, params: str) -> dict:
    import urllib.request
    runner = skill["runner"]
    endpoint = runner.get("endpoint")
    if not endpoint or not endpoint.startswith("https://"):
        raise ValueError("http runner 需要 https endpoint")
    method = (runner.get("method") or "POST").upper()
    timeout = int(runner.get("timeout", 10))
    try:
        body = json.loads(params) if params else {}
    except Exception:
        body = {}
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(endpoint, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        out = resp.read().decode("utf-8")
    return {"skill": skill["id"], "external": True,
            "result": json.loads(out) if out else None}


# ── Resource（示例）：漏洞总览 ────────────────────────────────────────────
@mcp.resource("sentinel://vulnerability-summary")
def vulnerability_summary() -> str:
    """返回当前漏洞统计的纯文本摘要，供 AI 客户端作为上下文资源读取。"""
    db = get_db()
    rows = db.execute(
        "SELECT COALESCE(severity,'unknown') AS severity, COUNT(*) AS c FROM vulnerabilities GROUP BY severity"
    ).fetchall()
    lines = ["哨兵平台漏洞总览："]
    for r in rows:
        lines.append(f"  - {r['severity']}: {r['c']}")
    return "\n".join(lines)


# ── Prompt（示例）：安全运营日报 ──────────────────────────────────────────
@mcp.prompt()
def daily_security_report() -> str:
    """生成安全运营日报的提示词模板，供 AI 客户端基于平台数据撰写日报。"""
    return (
        "你是哨兵安全管理平台的安全运营助手。请基于以下平台数据生成今日安全运营日报：\n"
        "1) 调用 get_vulnerability_stats 获取漏洞统计；\n"
        "2) 调用 list_vulnerabilities 查看高危(critical/high)项；\n"
        "3) 必要时用 search_knowledge 引用处置建议。\n"
        "日报需包含：总体态势、高危项清单、处置建议、明日重点。"
    )


if __name__ == "__main__":
    # stdio 传输：stdout 专供 MCP 协议，审计已改为写文件
    mcp.run()
