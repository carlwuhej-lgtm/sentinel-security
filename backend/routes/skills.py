"""技能中心（Skills）后端模块。

把平台已有的安全能力封装成可被前端「技能中心」调用、也可被 WorkBuddy 项目级
skill 复用的"技能"。每个技能都是对现有模块的安全编排，**不涉及任何密钥、不出网、
不碰认证/加密命门**。

当前实现两个 must-do 技能（低风险、前端可见效果）：
  - vuln-triage : 依据 CVSS 评分与 CWE 对全部漏洞重新定级（修正 severity 不一致项）
  - code-audit  : 基于知识库（CWE 标签）生成针对指定语言的安全代码审查清单
"""
from flask import Blueprint, request, jsonify
from app import get_db
from routes.auth import login_required
import json
import logging

logger = logging.getLogger(__name__)

skills_bp = Blueprint('skills', __name__)

# 技能注册表：单一事实来源，前端「技能中心」与 WorkBuddy 项目级 skill 共用此定义。
SKILLS = [
    {
        "id": "vuln-triage",
        "name": "漏洞智能分诊",
        "description": "依据 CVSS 评分与 CWE 类型，对全部漏洞重新定级（critical/high/medium/low），"
                       "修正 severity 与评分不一致的项。结果直接写回漏洞表，在「漏洞管理」页可见。",
        "risk": "low",
        "module": "vulnerabilities",
        "writes": True,
    },
    {
        "id": "code-audit",
        "name": "安全知识审查清单生成",
        "description": "基于知识库（CWE 标签）生成针对指定语言的「安全代码审查清单」，"
                       "输出可直接用于人工审查的条目。只读，不改写任何数据。",
        "risk": "low",
        "module": "knowledge_base",
        "writes": False,
    },
]


def _cvss_to_severity(cvss: float) -> str:
    """CVSS 3.0 标准分级，与 integrations/codeql.py 保持一致。"""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


@skills_bp.route("", methods=["GET"])
@login_required
def list_skills():
    """列出全部技能（脱敏：不返回 writes 内部字段）。"""
    public = [
        {k: v for k, v in s.items() if k != "writes"}
        for s in SKILLS
    ]
    return jsonify(public)


@skills_bp.route("/<sid>/run", methods=["POST"])
@login_required
def run_skill(sid):
    skill = next((s for s in SKILLS if s["id"] == sid), None)
    if not skill:
        return jsonify({"error": "skill not found", "id": sid}), 404

    logger.info("skill run: %s by user=%s", sid, getattr(request, "current_user_id", None))
    try:
        if sid == "vuln-triage":
            return jsonify(_run_vuln_triage())
        if sid == "code-audit":
            return jsonify(_run_code_audit())
    except Exception as e:  # noqa: BLE001 - 技能失败不应 500 拖垮页面
        logger.exception("skill %s failed", sid)
        return jsonify({"error": str(e), "skill": sid}), 500
    return jsonify({"error": "skill not runnable", "id": sid}), 400


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
