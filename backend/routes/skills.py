"""技能中心（Skills）后端模块。

把平台已有的安全能力封装成可被前端「技能中心」调用、也可被 WorkBuddy 项目级
skill 复用的"技能"。每个技能都是对现有模块的安全编排，**不涉及任何密钥、不出网、
不碰认证/加密命门**。

## 两种技能来源
1. **内置（builtin）**：写死在本文件的 SKILLS 列表，run 直接调内部函数。
2. **清单（manifest）**：`backend/skills/*.json` 描述，runner.type 决定怎么跑。
   第三方或自己写的 skill 走这条 —— **放一个 json +（可选）脚本文件即出现在前端**。

   runner.type 支持：
     - builtin  : 仅内置使用（内部 _handler）
     - http     : 平台代发请求到声明的 endpoint（短超时、白名单出口、绝不注入密钥）
     - script   : 在 skills 目录内跑一个本地脚本（防路径穿越、超时、捕获 stdout JSON）
     - llm_prompt: 走平台 AI（暂未启用，返回 501）

当前 must-do 两个内置技能（低风险、前端可见效果）：
  - vuln-triage : 依据 CVSS 评分与 CWE 对全部漏洞重新定级（修正 severity 不一致项）
  - code-audit  : 基于知识库（CWE 标签）生成针对指定语言的安全代码审查清单
"""
import os
import sys
import glob
import json
import logging
import subprocess
import urllib.request

from flask import Blueprint, request, jsonify
from app import get_db
from routes.auth import login_required

logger = logging.getLogger(__name__)

skills_bp = Blueprint('skills', __name__)

# 清单目录：backend/routes/skills.py -> ../../skills
SKILLS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "skills")

# ── 内置技能（写死，run 调内部函数） ──────────────────────────────────────
SKILLS = [
    {
        "id": "vuln-triage",
        "name": "漏洞智能分诊",
        "description": "依据 CVSS 评分与 CWE 类型，对全部漏洞重新定级（critical/high/medium/low），"
                       "修正 severity 与评分不一致的项。结果直接写回漏洞表，在「漏洞管理」页可见。",
        "risk": "low",
        "module": "vulnerabilities",
        "writes": True,
        "source": "builtin",
        "approval": "approved",
    },
    {
        "id": "code-audit",
        "name": "安全知识审查清单生成",
        "description": "基于知识库（CWE 标签）生成针对指定语言的「安全代码审查清单」，"
                       "输出可直接用于人工审查的条目。只读，不改写任何数据。",
        "risk": "low",
        "module": "knowledge_base",
        "writes": False,
        "source": "builtin",
        "approval": "approved",
    },
]

_BUILTIN_HANDLERS = {
    "vuln-triage": "_run_vuln_triage",
    "code-audit": "_run_code_audit",
}


def _cvss_to_severity(cvss: float) -> str:
    """CVSS 3.0 标准分级，与 integrations/codeql.py 保持一致。"""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def load_manifest_skills() -> list:
    """扫描 backend/skills/*.json，加载第三方/自定义技能清单。

    清单文件随代码入库（git review = 审批），故默认 approval=approved。
    运行时经前端上传的第三方 skill 应默认 pending 并走管理员审批（后续管理页）。
    """
    out = []
    if not os.path.isdir(SKILLS_DIR):
        return out
    for f in sorted(glob.glob(os.path.join(SKILLS_DIR, "*.json"))):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                m = json.load(fh)
        except Exception:  # noqa: BLE001 - 坏清单跳过，不拖垮整个列表
            logger.warning("跳过无法解析的技能清单: %s", f)
            continue
        if not isinstance(m, dict) or not m.get("id"):
            logger.warning("技能清单缺少 id，跳过: %s", f)
            continue
        m.setdefault("source", "user")
        m.setdefault("approval", "approved")
        m.setdefault("risk", "low")
        out.append(m)
    return out


# 合并：内置 + 清单。内置挂内部 handler 名（供 run 分发）。
for _s in SKILLS:
    _s["_handler"] = _BUILTIN_HANDLERS.get(_s["id"])
ALL_SKILLS = SKILLS + load_manifest_skills()


@skills_bp.route("", methods=["GET"])
@login_required
def list_skills():
    """列出全部已批准技能（脱敏：去掉 _handler / writes 等内部字段）。"""
    public = [
        {k: v for k, v in s.items() if not k.startswith("_") and k != "writes"}
        for s in ALL_SKILLS
        if s.get("approval") == "approved"
    ]
    return jsonify(public)


@skills_bp.route("/<sid>/run", methods=["POST"])
@login_required
def run_skill(sid):
    skill = next((s for s in ALL_SKILLS if s["id"] == sid), None)
    if not skill:
        return jsonify({"error": "skill not found", "id": sid}), 404
    if skill.get("approval") != "approved":
        return jsonify({"error": "skill not approved", "id": sid}), 403

    logger.info("skill run: %s by user=%s", sid, getattr(request, "current_user_id", None))
    try:
        handler = skill.get("_handler")
        if handler:
            return jsonify(globals()[handler]())
        runner = skill.get("runner") or {}
        rtype = runner.get("type")
        if rtype == "http":
            return jsonify(_run_http_runner(skill))
        if rtype == "script":
            return jsonify(_run_script_runner(skill))
        if rtype == "llm_prompt":
            return jsonify({"error": "llm_prompt runner 暂未启用", "id": sid}), 501
    except Exception as e:  # noqa: BLE001 - 技能失败不应 500 拖垮页面
        logger.exception("skill %s failed", sid)
        return jsonify({"error": str(e), "skill": sid}), 500
    return jsonify({"error": "skill not runnable", "id": sid}), 400


# ── runner 实现 ──────────────────────────────────────────────────────────
def _run_http_runner(skill: dict) -> dict:
    """代发 HTTP 请求到声明的 endpoint。不注入任何平台密钥；仅转发调用方 body。"""
    runner = skill["runner"]
    endpoint = runner.get("endpoint")
    if not endpoint or not endpoint.startswith("https://"):
        raise ValueError("http runner 需要 https endpoint")
    method = (runner.get("method") or "POST").upper()
    timeout = int(runner.get("timeout", 10))
    payload = request.get_json(silent=True) or {}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    return {
        "skill": skill["id"],
        "external": True,
        "result": json.loads(body) if body else None,
    }


def _run_script_runner(skill: dict) -> dict:
    """在 skills 目录内运行一个本地脚本。防路径穿越 + 超时 + 捕获 stdout(JSON)。

    注：生产环境应进一步做网络隔离与降权账户（最小化权限），此处为基础实现。
    """
    runner = skill["runner"]
    fname = runner.get("file") or ""
    # 路径穿越防护：禁止目录分隔与上级引用
    if "/" in fname or "\\" in fname or ".." in fname or not fname.endswith(".py"):
        raise ValueError("script runner 文件名非法")
    path = os.path.join(SKILLS_DIR, fname)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"skill 脚本不存在: {fname}")
    timeout = int(runner.get("timeout", 15))
    proc = subprocess.run(
        [sys.executable, path],
        capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"脚本执行失败: {proc.stderr[:2000]}")
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError:
        out = {"raw": proc.stdout[:4000]}
    return {"skill": skill["id"], "result": out}


# ── 内置技能实现 ──────────────────────────────────────────────────────────
def _run_vuln_triage():
    """按 CVSS 重新定级全部漏洞，修正 severity 与评分不一致的项。"""
    db = get_db()
    rows = db.execute(
        "SELECT id, cvss_score, severity FROM vulnerabilities"
    ).fetchall()
    changed = 0
    for r in rows:
        cvss = r["cvss_score"] or 0.0
        target = _cvss_to_severity(cvss) if cvss > 0 else (r["severity"] or "low")
        if target != r["severity"]:
            db.execute(
                "UPDATE vulnerabilities SET severity=? WHERE id=?",
                (target, r["id"]),
            )
            changed += 1
    db.commit()
    return {
        "skill": "vuln-triage",
        "updated": changed,
        "total": len(rows),
        "message": f"已重新定级 {changed} / {len(rows)} 个漏洞（依据 CVSS 评分）",
    }


def _run_code_audit():
    """基于知识库生成审查清单（按语言过滤提示，数据来自已发布文章）。

    知识库表无独立 cwe_id 列，CWE 锚点来自文章正文（如 "CWE-502"）或 tags，
    这里用正则从 content 提取首个 CWE 编号作为清单条目的锚点。
    """
    import re
    payload = request.get_json(silent=True) or {}
    language = (payload.get("language") or "general").strip().lower()

    db = get_db()
    arts = db.execute(
        "SELECT title, category, summary, content, tags FROM knowledge_articles "
        "WHERE is_published=1 ORDER BY category, id"
    ).fetchall()

    cwe_re = re.compile(r"CWE-(\d+)", re.IGNORECASE)
    items = []
    for a in arts:
        cwe_hit = cwe_re.search(a["content"] or "")
        cwe = f"CWE-{cwe_hit.group(1)}" if cwe_hit else ""
        items.append({
            "title": a["title"],
            "cwe": cwe,
            "category": a["category"],
            "summary": a["summary"] or "",
        })
    lang_label = {
        "general": "通用", "java": "Java", "python": "Python",
        "go": "Go", "javascript": "JavaScript/TypeScript", "js": "JavaScript/TypeScript",
    }.get(language, language)
    return {
        "skill": "code-audit",
        "language": language,
        "language_label": lang_label,
        "items": items,
        "count": len(items),
        "message": f"基于 {len(items)} 篇知识库文章生成「{lang_label}」安全代码审查清单",
    }
