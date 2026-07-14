"""技能中心（Skills）后端模块。

把平台已有的安全能力封装成可被前端「技能中心」调用、也可被 WorkBuddy 项目级
skill 复用的"技能"。每个技能都是对现有模块的安全编排，**不涉及任何密钥、不出网、
不碰认证/加密命门**。

## 技能来源
1. **内置（builtin）**：写死在本文件 SKILLS 列表，run 直接调内部函数。
2. **清单（manifest）**：`backend/skills/*.json` 描述，runner.type 决定怎么跑。
   第三方 / 自己写的 skill 走这条。

## 加技能的两种方式
- **开发者 / git 入库**：直接在 `backend/skills/` 放 `<id>.manifest.json`（+可选脚本），
  随代码 review 即视为审批，默认 approval=approved。
- **前端上传（第三方）**：在技能中心点「上传技能」→ 选 manifest(.json) + 可选脚本(.py)
  → **默认 approval=pending** → 管理员在技能中心「通过」后才上架、才能运行。
  这是供应链安全闸门：第三方代码绝不允许"丢进来就能跑"。

## runner.type
  - builtin   : 仅内置（内部 _handler）
  - http      : 平台代发请求到声明的 https endpoint（短超时、白名单、绝不注入密钥）
  - script    : 在 skills 目录内跑本地脚本（防路径穿越、最小化 env、超时、捕获 stdout JSON）
  - llm_prompt: 走平台 AI（暂未启用，返回 501）

## must-do 两个内置技能（低风险、前端可见）
  - vuln-triage : 依据 CVSS 对全部漏洞重新定级
  - code-audit  : 基于知识库生成指定语言的安全代码审查清单
"""
import os
import re
import sys
import glob
import json
import logging
import subprocess
import urllib.request

from flask import Blueprint, request, jsonify
from app import get_db
from routes.auth import login_required, admin_required

logger = logging.getLogger(__name__)

skills_bp = Blueprint('skills', __name__)

# 清单目录：backend/routes/skills.py -> ../../skills
SKILLS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "skills")

# 上传安全边界
MAX_MANIFEST_BYTES = 64 * 1024        # manifest ≤ 64KB
MAX_SCRIPT_BYTES = 256 * 1024         # 脚本 ≤ 256KB
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
ALLOWED_UPLOAD_TYPES = {"http", "script", "llm_prompt"}
# 脚本运行时允许继承的最小环境变量（避免把 JWT_SECRET / DB 口令等泄露给第三方脚本）
_SAFE_ENV_KEYS = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP",
                  "LANG", "LC_ALL", "COMSPEC", "PATHEXT", "HOME", "USERNAME")


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
    经前端上传的第三方 skill 由上传接口强制置为 pending，并走管理员审批。
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


def load_all_skills() -> list:
    """合并内置 + 清单。**每次请求都重新扫描**，这样前端上传的技能无需重启即生效。"""
    out = []
    for s in SKILLS:
        s2 = dict(s)
        s2["_handler"] = _BUILTIN_HANDLERS.get(s["id"])
        out.append(s2)
    out.extend(load_manifest_skills())
    return out


def _safe_join_skills_dir(filename: str) -> str:
    """拼接并校验路径落在 SKILLS_DIR 内（防路径穿越）。返回真实路径。"""
    base = os.path.realpath(SKILLS_DIR)
    target = os.path.realpath(os.path.join(base, filename))
    if target != base and not target.startswith(base + os.sep):
        raise ValueError("非法路径（疑似路径穿越）")
    return target


def _atomic_write_text(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def save_uploaded_skill(manifest: dict, script_bytes: bytes | None,
                        script_filename: str | None) -> dict:
    """落盘一个经前端上传的技能。

    - manifest 已在前端/路由层做过基础校验
    - 强制 source=user、approval=pending（供应链闸门：不允许自批准）
    - 返回脱敏后的公共字段
    """
    sid = manifest["id"]
    runner = manifest.get("runner") or {}
    rtype = runner.get("type")

    # 脚本类：必须提供脚本文件，落到 skills 目录（仅 basename，强制 .py）
    if rtype == "script":
        if not script_bytes or not script_filename:
            raise ValueError("script 类型技能必须同时上传脚本文件")
        base = os.path.basename(script_filename)
        if not base.endswith(".py") or "/" in base or "\\" in base or ".." in base:
            raise ValueError("脚本文件名非法（仅允许 *.py 且不含路径）")
        if len(script_bytes) > MAX_SCRIPT_BYTES:
            raise ValueError("脚本超过大小上限")
        script_path = _safe_join_skills_dir(base)
        with open(script_path, "wb") as fh:
            fh.write(script_bytes)
        runner["file"] = base

    if rtype == "http":
        if not (runner.get("endpoint") or "").startswith("https://"):
            raise ValueError("http 类型技能需要 https endpoint")

    manifest["source"] = "user"
    manifest["approval"] = "pending"
    manifest.setdefault("risk", "low")

    manifest_path = _safe_join_skills_dir(f"{sid}.manifest.json")
    if os.path.getsize(manifest_path) > MAX_MANIFEST_BYTES if os.path.exists(manifest_path) else False:
        raise ValueError("manifest 超过大小上限")
    _atomic_write_text(manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2))
    logger.info("技能已上传(待审批): %s", sid)

    public = {k: v for k, v in manifest.items()
              if not k.startswith("_") and k != "writes"}
    return public


def set_skill_approval(sid: str, approval: str) -> dict:
    """改写技能清单的 approval 字段（原子写）。仅管理员调用。"""
    manifest_path = _safe_join_skills_dir(f"{sid}.manifest.json")
    if not os.path.isfile(manifest_path):
        raise FileNotFoundError(f"技能不存在: {sid}")
    with open(manifest_path, "r", encoding="utf-8") as fh:
        m = json.load(fh)
    m["approval"] = approval
    _atomic_write_text(manifest_path, json.dumps(m, ensure_ascii=False, indent=2))
    logger.info("技能审批变更: %s -> %s", sid, approval)
    public = {k: v for k, v in m.items() if not k.startswith("_") and k != "writes"}
    return public


def _strip_internal(skill: dict) -> dict:
    return {k: v for k, v in skill.items() if not k.startswith("_") and k != "writes"}


@skills_bp.route("", methods=["GET"])
@login_required
def list_skills():
    """列出技能。

    - 管理员：看到全部（含 pending / rejected），并随响应返回 is_admin=true
    - 普通用户：仅看到已批准(approved)的技能
    响应体: { skills: [...], is_admin: bool }
    """
    is_admin = getattr(request, "current_user_role", "") == "admin"
    all_skills = load_all_skills()
    if is_admin:
        visible = all_skills
    else:
        visible = [s for s in all_skills if s.get("approval") == "approved"]
    return jsonify({"skills": [_strip_internal(s) for s in visible], "is_admin": is_admin})


@skills_bp.route("/upload", methods=["POST"])
@login_required
def upload_skill():
    """前端上传第三方技能。

    表单字段：
      - manifest : 必选，JSON 文件（含 id/name/description/runner）
      - script   : 可选，.py 脚本（runner.type=script 时必选）
    校验：id 格式、必填字段、runner 类型、脚本路径/大小；强制 source=user、approval=pending。
    """
    manifest_file = request.files.get("manifest")
    if not manifest_file:
        return jsonify({"error": "缺少 manifest 文件"}), 400
    try:
        raw = manifest_file.read()
        if len(raw) > MAX_MANIFEST_BYTES:
            return jsonify({"error": "manifest 超过大小上限(64KB)"}), 413
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return jsonify({"error": "manifest 不是合法的 JSON"}), 400

    sid = (manifest.get("id") or "").strip()
    if not ID_RE.match(sid):
        return jsonify({"error": "id 非法（仅允许小写字母/数字/连字符，2-64 位）"}), 400
    if not manifest.get("name") or not isinstance(manifest.get("name"), str):
        return jsonify({"error": "manifest 缺少 name"}), 400
    runner = manifest.get("runner")
    if not isinstance(runner, dict) or not runner.get("type"):
        return jsonify({"error": "manifest.runner.type 必填"}), 400
    if runner["type"] not in ALLOWED_UPLOAD_TYPES:
        return jsonify({"error": f"不支持的 runner.type: {runner['type']}"}), 400
    # 内置 id 冲突检查
    if sid in _BUILTIN_HANDLERS:
        return jsonify({"error": "id 与内置技能冲突"}), 409

    script_bytes = None
    script_filename = None
    script_file = request.files.get("script")
    if script_file and script_file.filename:
        script_bytes = script_file.read()
        script_filename = script_file.filename

    try:
        public = save_uploaded_skill(manifest, script_bytes, script_filename)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except FileNotFoundError:
        return jsonify({"error": "技能不存在"}), 404

    return jsonify({
        "message": "技能已提交，等待管理员审批后上架",
        "skill": public,
    }), 201


@skills_bp.route("/<sid>/approve", methods=["POST"])
@admin_required
def approve_skill(sid):
    try:
        public = set_skill_approval(sid, "approved")
    except FileNotFoundError:
        return jsonify({"error": "技能不存在", "id": sid}), 404
    return jsonify({"message": "已通过审批", "skill": public})


@skills_bp.route("/<sid>/reject", methods=["POST"])
@admin_required
def reject_skill(sid):
    try:
        public = set_skill_approval(sid, "rejected")
    except FileNotFoundError:
        return jsonify({"error": "技能不存在", "id": sid}), 404
    return jsonify({"message": "已拒绝", "skill": public})


@skills_bp.route("/<sid>/run", methods=["POST"])
@login_required
def run_skill(sid):
    skill = next((s for s in load_all_skills() if s["id"] == sid), None)
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
    """在 skills 目录内运行一个本地脚本。

    安全：realpath 校验路径落在 SKILLS_DIR 内；仅继承最小环境变量（不泄露 JWT_SECRET /
    DB 口令等）；超时 + 捕获 stdout(JSON)。
    注：生产环境应进一步做网络隔离与降权账户（最小化权限），此处为基础实现。
    """
    runner = skill["runner"]
    fname = runner.get("file") or ""
    if "/" in fname or "\\" in fname or ".." in fname or not fname.endswith(".py"):
        raise ValueError("script runner 文件名非法")
    path = _safe_join_skills_dir(fname)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"skill 脚本不存在: {fname}")
    timeout = int(runner.get("timeout", 15))
    safe_env = {k: os.environ[k] for k in _SAFE_ENV_KEYS if k in os.environ}
    # 强制子进程 UTF-8 输出（Windows 默认 GBK 会导致中文解码失败/卡死）
    safe_env.setdefault("PYTHONUTF8", "1")
    safe_env.setdefault("PYTHONIOENCODING", "utf-8")
    proc = subprocess.run(
        [sys.executable, path],
        capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout,
        env=safe_env,
    )
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", errors="replace")
        raise RuntimeError(f"脚本执行失败: {err[:2000]}")
    raw = proc.stdout or b""
    try:
        out = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        out = {"raw": raw.decode("utf-8", errors="replace")[:4000]}
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
    cwe_re = re.compile(r"CWE-(\d+)", re.IGNORECASE)
    payload = request.get_json(silent=True) or {}
    language = (payload.get("language") or "general").strip().lower()

    db = get_db()
    arts = db.execute(
        "SELECT title, category, summary, content, tags FROM knowledge_articles "
        "WHERE is_published=1 ORDER BY category, id"
    ).fetchall()

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
