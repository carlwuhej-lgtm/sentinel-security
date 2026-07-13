import logging
logger = logging.getLogger(__name__)
"""
哨兵安全平台 — 扫描编排服务

将扫描执行逻辑从 HTTP 路由层解耦为独立服务，支持：
- HTTP 路由触发（原有 API）
- 定时调度触发（Scheduler 调用）
- Webhook 触发

核心流程：
  create_scan_task → run_scanner → save_vulnerabilities → update_scan_status → send_alerts
"""

import sqlite3
import os
import threading
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict, Any

# 工具集成框架
from integrations import REGISTRY as SCANNER_REGISTRY
from integrations import BaseScanner
from config import SCANNER_MODE, DATABASE_PATH

# 服务层
from services.notification_service import NotificationService

# 工具名→scanner key 映射（同时包含简称和DB中存储的全名）
_NAME_TO_KEY = {
    "Semgrep": "semgrep",
    "Semgrep SAST": "semgrep",
    "Trivy": "trivy",
    "Trivy SCA": "trivy",
    "OWASP ZAP": "zap",
    "OWASP ZAP DAST": "zap",
    "Gitleaks": "gitleaks",
    "Gitleaks SECRET": "gitleaks",
    "Dependency-Check": "dependency-check",
    "CodeQL": "codeql",
}


def _get_db() -> sqlite3.Connection:
    """获取数据库连接，优先用环境变量 SENTINEL_DB_PATH。"""
    db_path = os.environ.get("SENTINEL_DB_PATH", DATABASE_PATH)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=DELETE")
    except sqlite3.OperationalError:
        pass
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def _db_execute_retry(db: sqlite3.Connection, sql: str, params=(), max_retries: int = 5) -> sqlite3.Cursor:
    """执行 SQL 语句，遇到锁时自动重试。"""
    import time as _time
    for attempt in range(max_retries):
        try:
            return db.execute(sql, params)
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and attempt < max_retries - 1:
                _time.sleep(0.5 * (attempt + 1))
                continue
            raise


# AI 健康状态缓存（避免每条漏洞都重复检查 AI 连接）
_ai_health_cache: Dict[str, Any] = {"healthy": None, "checked_at": 0}
_ai_health_cache_ttl: float = 30.0  # 30 秒内复用缓存


def _is_ai_healthy() -> bool:
    """检查 AI 服务是否可用，结果缓存 30 秒避免重复 HTTP 请求。"""
    import time as _time
    now = _time.time()
    if _ai_health_cache["healthy"] is not None and (now - _ai_health_cache["checked_at"]) < _ai_health_cache_ttl:
        return _ai_health_cache["healthy"]
    try:
        from routes.ai_routes import check_ai_health, AI_ENABLED
        if not AI_ENABLED:
            _ai_health_cache["healthy"] = False
        else:
            _ai_health_cache["healthy"] = check_ai_health()
    except Exception:
        _ai_health_cache["healthy"] = False
    _ai_health_cache["checked_at"] = now
    return _ai_health_cache["healthy"]


def _pregenerate_ai_fix(vuln: dict, timeout: int = 3) -> str:
    """
    扫描落库阶段为单条漏洞预生成 AI 修复建议（存入 vulnerabilities.ai_analysis）。

    - 先通过 _is_ai_healthy() 快速检查 AI 是否可达（结果缓存 30s）。
    - AI 未启用 / 不健康 / 调用失败 / 超时 → 返回空串，绝不抛异常、绝不阻塞入库。
    - 生成成功的建议后续发邮件、漏洞详情、工单、报告均可直接复用，无需再调 AI。
    """
    # 快速跳过：AI 不健康则所有漏洞都跳过，不浪费 3s×N 条 = N×3s 的等待
    if not _is_ai_healthy():
        return ""

    try:
        from routes.ai_routes import call_ai
    except Exception:
        return ""

    try:
        vuln_summary = (
            f"漏洞标题: {vuln.get('title', 'N/A')}\n"
            f"严重性: {vuln.get('severity', 'N/A')}\n"
            f"CWE ID: {vuln.get('cwe_id', 'N/A')}\n"
            f"描述: {vuln.get('description', 'N/A')}\n"
            f"文件路径: {vuln.get('file_path', 'N/A')}\n"
            f"行号: {vuln.get('line', 'N/A')}\n"
        )
        system_prompt = (
            "你是「哨兵」应用安全平台的安全修复专家。请对以下漏洞给出简明、可落地的修复建议，使用中文。\n"
            "包含三部分：1) 根因分析（1-2句）；2) 修复方案（1-2种，附关键代码或配置示例）；3) 验证方法（1-2句）。\n"
            "控制在 400 字以内，直接给要点，不要寒暄。"
        )
        user_prompt = f"请为以下漏洞提供修复建议：\n\n{vuln_summary}"
        resp = call_ai(system_prompt, user_prompt, timeout=timeout)
        if not resp or resp.startswith("[AI Error]"):
            return ""
        return resp.strip()
    except Exception as e:
        logger.error(f"[ScannerService] _pregenerate_ai_fix failed (non-blocking): {e}")
        return ""


def _normalize_url(url: str) -> str:
    """规范化单个 URL：补全缺失的 //（如 https:x.com → https://x.com）。"""
    u = (url or "").strip()
    if not u:
        return u
    if u.startswith("http:") and not u.startswith("http://"):
        u = u.replace("http:", "http://", 1)
    elif u.startswith("https:") and not u.startswith("https://"):
        u = u.replace("https:", "https://", 1)
    return u


def _parse_targets(raw: str) -> List[str]:
    """
    把 target_url 字段拆成多个目标 URL 列表。

    支持分隔符：换行、逗号、分号、空白。向后兼容单 URL（返回单元素列表）。
    去重、去空、保序，并对每个 URL 做规范化。
    """
    if not raw:
        return []
    import re as _re
    parts = _re.split(r"[\n\r,;\s]+", str(raw))
    seen = set()
    out = []
    for p in parts:
        u = _normalize_url(p)
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _run_multi_target_scan(scanner, project_config: dict, targets: List[str],
                           db: sqlite3.Connection, scan_id: int):
    """
    DAST 多目标扫描：对每个目标 URL 各跑一遍，合并所有漏洞为一个 ScanResult。

    - 单个目标扫描失败不影响其他目标（记录到 raw_output）。
    - 只要有一个目标成功产出结果，整体即视为 completed。
    """
    from integrations.base import ScanResult

    all_vulns = []
    raw_parts = []
    total_duration = 0
    ok_targets = 0
    n = len(targets)

    for idx, tgt in enumerate(targets, 1):
        cfg = dict(project_config)
        cfg["target_url"] = tgt
        # 进度：15 → 70 之间按目标数均匀推进
        prog = 15 + int(55 * (idx - 1) / max(n, 1))
        try:
            db.execute(
                "UPDATE scan_tasks SET progress=?, progress_message=? WHERE id=?",
                (prog, f"正在扫描目标 {idx}/{n}: {tgt[:60]}", scan_id),
            )
            db.commit()
        except Exception:
            pass

        try:
            r = scanner.run(cfg)
            total_duration += getattr(r, "duration_ms", 0) or 0
            vulns = getattr(r, "vulnerabilities", []) or []
            # 给每条漏洞的描述标注来源目标，便于区分是哪个 URL 的问题
            for v in vulns:
                if tgt not in (getattr(v, "file_path", "") or ""):
                    v.description = f"[目标: {tgt}] {v.description}"
                all_vulns.append(v)
            status = getattr(r, "status", "completed")
            if status in ("completed", "completed_no_findings"):
                ok_targets += 1
            raw_parts.append(f"=== 目标 {idx}/{n}: {tgt} (status={status}, vulns={len(vulns)}) ===")
            raw_parts.append((getattr(r, "raw_output", "") or "")[:500])
        except Exception as e:
            raw_parts.append(f"=== 目标 {idx}/{n}: {tgt} 扫描异常: {str(e)[:150]} ===")

    # 汇总严重性统计
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in all_vulns:
        sev = getattr(v, "severity", "low")
        if sev in sev_counts:
            sev_counts[sev] += 1

    overall_status = "completed" if ok_targets > 0 else "failed"

    import uuid as _uuid
    return ScanResult(
        scan_id=_uuid.uuid4().hex[:12],
        tool_key=getattr(scanner, "tool_key", "zap"),
        project_name="",
        status=overall_status,
        vulnerabilities=all_vulns,
        duration_ms=total_duration,
        summary={
            "total": len(all_vulns),
            "critical": sev_counts["critical"],
            "high": sev_counts["high"],
            "medium": sev_counts["medium"],
            "low": sev_counts["low"],
            "targets_scanned": n,
            "targets_ok": ok_targets,
        },
        raw_output=f"[多目标 DAST] 共 {n} 个目标，{ok_targets} 个成功\n" + "\n".join(raw_parts),
    )


def _get_scanner(tool_name: str, tool_type: str, endpoint: str = "", api_key: str = "") -> Optional[BaseScanner]:
    """根据工具名获取对应的扫描器实例。"""
    # 1) 精确名称匹配
    key = _NAME_TO_KEY.get(tool_name)
    # 2) 模糊名称匹配：DB 中 "Semgrep SAST" 匹配到 "Semgrep"
    if not key:
        for map_name, map_key in _NAME_TO_KEY.items():
            if map_name in tool_name or tool_name in map_name:
                key = map_key
                break
    # 3) 按 tool_type 回退（大小写不敏感）
    if not key or key not in SCANNER_REGISTRY:
        for k, cls in SCANNER_REGISTRY.items():
            if cls.tool_type.upper() == tool_type.upper():
                key = k
                break
    if not key:
        return None
    cls = SCANNER_REGISTRY[key]
    import sys
    sys.stderr.write(f"\n[DEBUG] _get_scanner() instantiating {cls.__name__} with mode={SCANNER_MODE}\n")
    sys.stderr.flush()
    return cls(mode=SCANNER_MODE, api_endpoint=endpoint, api_key=api_key)


def execute_scan(
    project_id: int,
    tool_type: str,
    trigger_type: str = "manual",
    user_id: Optional[int] = None,
    db: Optional[sqlite3.Connection] = None,
) -> Tuple[bool, Dict[str, Any], str]:
    """
    执行一次完整的安全扫描。

    参数:
        project_id:   项目 ID
        tool_type:    扫描类型 (SAST/SCA/DAST/SECRET)
        trigger_type: 触发来源 (manual/scheduled/webhook)
        user_id:      触发用户 ID（用于审计）
        db:           外部数据库连接（为 None 时自动创建）

    返回:
        (success, scan_dict, error_message)
    """
    own_db = db is None
    if own_db:
        db = _get_db()

    try:
        # 1. 校验项目
        project = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if not project:
            return False, {}, "项目不存在"

        # 2. 取启用的工具（大小写不敏感匹配）
        tool = db.execute(
            "SELECT * FROM tools WHERE LOWER(tool_type)=LOWER(?) AND enabled=1 LIMIT 1", (tool_type,)
        ).fetchone()
        if not tool:
            return False, {}, f"没有启用的 {tool_type} 工具"

        # 3. 创建扫描任务
        cur = db.execute(
            """INSERT INTO scan_tasks (project_id, tool_id, tool_type, status, started_at, trigger_type, progress, progress_message)
               VALUES (?,?,?,'running',datetime('now','localtime'),?,5,'正在启动扫描引擎...')""",
            (project_id, tool["id"], tool_type, trigger_type),
        )
        scan_id = cur.lastrowid
        db.commit()

        # 4. 调用扫描器
        endpoint = tool["endpoint"] if "endpoint" in tool.keys() else ""
        api_key = tool["api_key"] if "api_key" in tool.keys() else ""
        scanner = _get_scanner(tool["name"], tool_type, endpoint=endpoint, api_key=api_key)
        if scanner is None:
            db.execute(
                "UPDATE scan_tasks SET status='failed', finished_at=datetime('now','localtime') WHERE id=?",
                (scan_id,),
            )
            db.commit()
            return False, {}, f"不支持的扫描类型: {tool_type}"

        try:
            project_config = dict(project)
            project_config["lang"] = (
                project["language"] if "language" in project.keys() and project["language"] else "python"
            )
            # 进度：开始扫描
            db.execute(
                "UPDATE scan_tasks SET progress=15, progress_message='正在执行代码扫描...' WHERE id=?",
                (scan_id,),
            )
            db.commit()
            logger.info(f"[ScannerService] scanner instance={scanner!r}, class={scanner.__class__}, module={scanner.__class__.__module__}")
            logger.info(f"[ScannerService] project_config local_path={project_config.get('local_path')}")

            # ── DAST 多目标：target_url 可含多个 URL（换行/逗号/分号分隔），逐个扫描并合并 ──
            targets = _parse_targets(project_config.get("target_url", ""))
            if str(tool_type).upper() == "DAST" and len(targets) > 1:
                scan_result = _run_multi_target_scan(
                    scanner, project_config, targets, db, scan_id
                )
            else:
                # 单目标（含非 DAST 工具）：规范化后直接扫描
                if targets:
                    project_config["target_url"] = _normalize_url(targets[0])
                scan_result = scanner.run(project_config)

            # 进度：扫描完成，开始入库
            db.execute(
                "UPDATE scan_tasks SET progress=75, progress_message='正在分析扫描结果...' WHERE id=?",
                (scan_id,),
            )
            db.commit()
            logger.info(f"[ScannerService] scan_result status={getattr(scan_result, 'status', None)}, vulns={len(getattr(scan_result, 'vulnerabilities', []) or [])}, raw={getattr(scan_result, 'raw_output', '')[:200]}")
        except Exception as e:
            db.execute(
                "UPDATE scan_tasks SET status='failed', finished_at=datetime('now','localtime') WHERE id=?",
                (scan_id,),
            )
            db.commit()
            return False, {}, f"扫描执行失败: {str(e)}"

        # 5. 如果扫描器明确失败，任务必须失败，不能标记 completed
        if getattr(scan_result, "status", "completed") != "completed":
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            db.execute(
                "UPDATE scan_tasks SET status='failed', vuln_count=0, finished_at=?, result_json=? WHERE id=?",
                (now, getattr(scan_result, "raw_output", ""), scan_id),
            )
            db.commit()
            scan = db.execute(
                """SELECT s.*, p.name as project_name
                   FROM scan_tasks s LEFT JOIN projects p ON s.project_id = p.id
                   WHERE s.id=?""",
                (scan_id,),
            ).fetchone()
            result = dict(scan)
            result["vulnerabilities"] = []
            return False, result, getattr(scan_result, "raw_output", "扫描失败")

        # 6. 漏洞入库（入库时预生成 AI 修复建议，存入 ai_analysis 字段供发邮件/展示复用）
        vuln_dicts = []
        for v in scan_result.vulnerabilities:
            vd = v.to_dict()
            # 预生成 AI 修复建议：AI 未启用/失败/超时则为空串，不阻塞入库
            ai_fix = _pregenerate_ai_fix({
                "title": vd["title"],
                "severity": vd["severity"],
                "cwe_id": vd["cwe_id"],
                "description": vd["description"],
                "file_path": vd["file_path"],
                "line": vd["line"],
            })
            db.execute(
                """INSERT INTO vulnerabilities
                   (scan_id, cve_id, title, severity, file_path, line, source_tool,
                    description, fix_suggestion, cvss_score, cwe_id, ai_analysis)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan_id, vd["cve_id"], vd["title"], vd["severity"],
                    vd["file_path"], vd["line"], tool["name"],
                    vd["description"], vd["recommendation"], vd["cvss_score"],
                    vd["cwe_id"], ai_fix,
                ),
            )
            vuln_dicts.append({
                "cve_id": vd["cve_id"],
                "title": vd["title"],
                "severity": vd["severity"],
                "file_path": vd["file_path"],
                "line": vd["line"],
                "description": vd["description"],
                "cvss_score": vd["cvss_score"],
                "cwe_id": vd["cwe_id"],
                "fix_suggestion": vd["recommendation"],
                "ai_analysis": ai_fix,
                "source_tool": tool["name"],
            })

        # 6. 更新扫描状态
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        db.execute(
            "UPDATE scan_tasks SET status='completed', vuln_count=?, finished_at=?, progress=100, progress_message='扫描完成' WHERE id=?",
            (len(vuln_dicts), now, scan_id),
        )

        # 6b. 更新工具使用统计
        db.execute(
            """UPDATE tools SET
               scan_count = scan_count + 1,
               last_scan_at = ?,
               vuln_found_total = vuln_found_total + ?
               WHERE id = ?""",
            (now, len(vuln_dicts), tool["id"]),
        )
        db.commit()

        # 7. 邮件告警
        try:
            notifier = NotificationService(
                os.environ.get("SENTINEL_DB_PATH", DATABASE_PATH)
            )
            notifier.send_scan_alert(
                project["name"], tool["name"],
                vuln_dicts,
                {"duration_ms": scan_result.duration_ms, "summary": scan_result.summary},
            )
        except Exception as e:
            logger.error(f"[ScannerService] Alert failed (non-blocking): {e}")

        # 7b. 生成告警记录 + IM 通知
        try:
            critical_count = sum(1 for v in vuln_dicts if v.get("severity", "").lower() == "critical")
            high_count = sum(1 for v in vuln_dicts if v.get("severity", "").lower() == "high")
            if critical_count > 0 or high_count > 0:
                from routes.alerts import generate_scan_alert
                alert_id = generate_scan_alert(
                    db, scan_id, project["id"], project["name"],
                    len(vuln_dicts), critical_count, high_count
                )
                if alert_id:
                    # 发送 IM 通知
                    send_im_alert(
                        os.environ.get("SENTINEL_DB_PATH", DATABASE_PATH),
                        alert_id, project["name"], tool["name"],
                        len(vuln_dicts), critical_count, high_count
                    )
        except Exception as e:
            logger.error(f"[ScannerService] Alert generation failed (non-blocking): {e}")

        # 8. 返回结果
        scan = db.execute(
            """SELECT s.*, p.name as project_name
               FROM scan_tasks s LEFT JOIN projects p ON s.project_id = p.id
               WHERE s.id=?""",
            (scan_id,),
        ).fetchone()
        result = dict(scan)
        result["vulnerabilities"] = vuln_dicts

        return True, result, ""

    finally:
        if own_db:
            db.close()


# ─── 便捷函数（供调度器使用） ───

def _execute_scan_in_thread(scan_id: int, project_id: int, tool_type: str, trigger_type: str, user_id: Optional[int]):
    """在后台线程中执行扫描，更新扫描任务状态。"""
    db = _get_db()
    try:
        # 更新状态为 running
        _db_execute_retry(db, "UPDATE scan_tasks SET status='running', progress=5, progress_message='正在启动扫描引擎...' WHERE id=?", (scan_id,))
        db.commit()

        # 1. 校验项目
        project = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if not project:
            _db_execute_retry(db, "UPDATE scan_tasks SET status='failed', finished_at=datetime('now','localtime') WHERE id=?", (scan_id,))
            db.commit()
            return

        # 2. 取启用的工具（大小写不敏感匹配）
        tool = db.execute(
            "SELECT * FROM tools WHERE LOWER(tool_type)=LOWER(?) AND enabled=1 LIMIT 1", (tool_type,)
        ).fetchone()
        if not tool:
            _db_execute_retry(db, "UPDATE scan_tasks SET status='failed', finished_at=datetime('now','localtime') WHERE id=?", (scan_id,))
            db.commit()
            return

        # 3. 调用扫描器
        endpoint = tool["endpoint"] if "endpoint" in tool.keys() else ""
        api_key = tool["api_key"] if "api_key" in tool.keys() else ""
        scanner = _get_scanner(tool["name"], tool_type, endpoint=endpoint, api_key=api_key)
        if scanner is None:
            _db_execute_retry(db, "UPDATE scan_tasks SET status='failed', finished_at=datetime('now','localtime') WHERE id=?", (scan_id,))
            db.commit()
            return

        try:
            project_config = dict(project)
            project_config["lang"] = (
                project["language"] if "language" in project.keys() and project["language"] else "python"
            )
            _target = project_config.get("target_url", "")
            if _target and _target.startswith("http:") and not _target.startswith("http://"):
                _target = _target.replace("http:", "http://", 1)
                project_config["target_url"] = _target
            elif _target and _target.startswith("https:") and not _target.startswith("https://"):
                _target = _target.replace("https:", "https://", 1)
                project_config["target_url"] = _target
            # 进度：开始扫描
            _db_execute_retry(db, "UPDATE scan_tasks SET progress=15, progress_message='正在执行代码扫描...' WHERE id=?", (scan_id,))
            db.commit()
            logger.info(f"[ScannerService] bg_scanner instance={scanner!r}, class={scanner.__class__}")
            scan_result = scanner.run(project_config)
            # 进度：扫描完成
            _db_execute_retry(db, "UPDATE scan_tasks SET progress=75, progress_message='正在分析扫描结果...' WHERE id=?", (scan_id,))
            db.commit()
            logger.info(f"[ScannerService] bg_scan #{scan_id}: scanner.run() returned, status={scan_result.status}, vulns={len(scan_result.vulnerabilities)}")
        except Exception as e:
            _db_execute_retry(db,
                "UPDATE scan_tasks SET status='failed', finished_at=datetime('now','localtime'), error=?, progress_message='扫描执行异常' WHERE id=?",
                (str(e)[:500], scan_id))
            db.commit()
            logger.info(f"[ScannerService] Background scan #{scan_id} exception: {e}")
            import traceback
            traceback.print_exc()
            return

        # 4. 检查扫描状态
        if getattr(scan_result, "status", "completed") != "completed":
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            _db_execute_retry(db,
                "UPDATE scan_tasks SET status='failed', vuln_count=0, finished_at=?, result_json=? WHERE id=?",
                (now, getattr(scan_result, "raw_output", ""), scan_id),
            )
            db.commit()
            logger.error(f"[ScannerService] bg_scan #{scan_id}: scan failed, status={scan_result.status}")
            return

        logger.info(f"[ScannerService] bg_scan #{scan_id}: saving {len(scan_result.vulnerabilities)} vulns...")

        # 进度：入库中
        _db_execute_retry(db, "UPDATE scan_tasks SET progress=85, progress_message='正在保存漏洞数据...' WHERE id=?", (scan_id,))
        db.commit()

        # 5. 漏洞入库
        vuln_dicts = []
        for v in scan_result.vulnerabilities:
            vd = v.to_dict()
            logger.info(f"[ScannerService] bg_scan #{scan_id}: pre AI fix for {vd['title'][:40]}...")
            ai_fix = _pregenerate_ai_fix({
                "title": vd["title"],
                "severity": vd["severity"],
                "cwe_id": vd["cwe_id"],
                "description": vd["description"],
                "file_path": vd["file_path"],
                "line": vd["line"],
            })
            logger.info(f"[ScannerService] bg_scan #{scan_id}: inserting vuln {vd['title'][:40]}...")
            _db_execute_retry(db,
                """INSERT INTO vulnerabilities
                   (scan_id, cve_id, title, severity, file_path, line, source_tool,
                    description, fix_suggestion, cvss_score, cwe_id, ai_analysis)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan_id, vd["cve_id"], vd["title"], vd["severity"],
                    vd["file_path"], vd["line"], tool["name"],
                    vd["description"], vd["recommendation"], vd["cvss_score"],
                    vd["cwe_id"], ai_fix,
                ),
            )
            vuln_dicts.append({
                "cve_id": vd["cve_id"],
                "title": vd["title"],
                "severity": vd["severity"],
                "file_path": vd["file_path"],
                "line": vd["line"],
                "description": vd["description"],
                "cvss_score": vd["cvss_score"],
                "cwe_id": vd["cwe_id"],
                "fix_suggestion": vd["recommendation"],
                "ai_analysis": ai_fix,
                "source_tool": tool["name"],
            })

        # 6. 更新扫描状态
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        _db_execute_retry(db,
            "UPDATE scan_tasks SET status='completed', vuln_count=?, finished_at=?, progress=100, progress_message='扫描完成' WHERE id=?",
            (len(vuln_dicts), now, scan_id),
        )

        # 7. 更新工具统计
        _db_execute_retry(db,
            """UPDATE tools SET
               scan_count = scan_count + 1,
               last_scan_at = ?,
               vuln_found_total = vuln_found_total + ?
               WHERE id = ?""",
            (now, len(vuln_dicts), tool["id"]),
        )
        db.commit()

        # 8. 告警通知
        try:
            notifier = NotificationService(
                os.environ.get("SENTINEL_DB_PATH", DATABASE_PATH)
            )
            notifier.send_scan_alert(
                project["name"], tool["name"],
                vuln_dicts,
                {"duration_ms": getattr(scan_result, "duration_ms", 0), "summary": getattr(scan_result, "summary", "")},
            )
        except Exception as e:
            logger.error(f"[ScannerService] Alert failed (non-blocking): {e}")

        try:
            critical_count = sum(1 for v in vuln_dicts if v.get("severity", "").lower() == "critical")
            high_count = sum(1 for v in vuln_dicts if v.get("severity", "").lower() == "high")
            if critical_count > 0 or high_count > 0:
                from routes.alerts import generate_scan_alert
                alert_id = generate_scan_alert(
                    db, scan_id, project["id"], project["name"],
                    len(vuln_dicts), critical_count, high_count
                )
        except Exception as e:
            logger.error(f"[ScannerService] Alert generation failed (non-blocking): {e}")

        logger.info(f"[ScannerService] Background scan #{scan_id} completed: {len(vuln_dicts)} vulns found")

    except Exception as e:
        logger.info(f"[ScannerService] Background scan #{scan_id} fatal exception: {e}")
        import traceback
        traceback.print_exc()
        try:
            _db_execute_retry(db,
                "UPDATE scan_tasks SET status='failed', finished_at=datetime('now','localtime'), error=?, progress_message='扫描线程异常退出' WHERE id=?",
                (str(e)[:500], scan_id))
            db.commit()
        except Exception:
            pass
    finally:
        # 终级保护：如果到这一步 status 还是 running，强制标记失败
        try:
            row = db.execute("SELECT status FROM scan_tasks WHERE id=?", (scan_id,)).fetchone()
            if row and row["status"] == "running":
                _db_execute_retry(db,
                    "UPDATE scan_tasks SET status='failed', finished_at=datetime('now','localtime'), error='扫描线程异常退出（未捕获异常）' WHERE id=?",
                    (scan_id,))
                db.commit()
        except Exception:
            pass
        db.close()


def execute_scan_async(
    project_id: int,
    tool_type: str,
    trigger_type: str = "manual",
    user_id: Optional[int] = None,
) -> Tuple[bool, Dict[str, Any], str]:
    """
    异步执行安全扫描 — 立即返回扫描任务，在后台线程执行。

    返回:
        (success, scan_dict, error_message)
    """
    db = _get_db()
    try:
        # 1. 校验项目
        project = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if not project:
            return False, {}, "项目不存在"

        # 2. 取启用的工具（大小写不敏感匹配）
        tool = db.execute(
            "SELECT * FROM tools WHERE LOWER(tool_type)=LOWER(?) AND enabled=1 LIMIT 1", (tool_type,)
        ).fetchone()
        if not tool:
            return False, {}, f"没有启用的 {tool_type} 工具"

        # 3. 创建扫描任务（pending）
        cur = db.execute(
            """INSERT INTO scan_tasks (project_id, tool_id, tool_type, status, started_at, trigger_type, progress, progress_message)
               VALUES (?,?,?,'pending',datetime('now','localtime'),?,0,'等待调度...')""",
            (project_id, tool["id"], tool_type, trigger_type),
        )
        scan_id = cur.lastrowid
        db.commit()

        # 4. 启动后台线程执行
        thread = threading.Thread(
            target=_execute_scan_in_thread,
            args=(scan_id, project_id, tool_type, trigger_type, user_id),
            daemon=True,
        )
        thread.start()

        # 5. 立即返回
        scan = db.execute(
            """SELECT s.*, p.name as project_name
               FROM scan_tasks s LEFT JOIN projects p ON s.project_id = p.id
               WHERE s.id=?""",
            (scan_id,),
        ).fetchone()
        result = dict(scan)
        result["vulnerabilities"] = []
        result["status_note"] = "扫描已提交，正在后台执行"

        return True, result, ""

    finally:
        db.close()


def scan_for_schedule(project_id: int, tool_type: str, schedule_id: int) -> Tuple[bool, str, str]:
    """
    供调度器调用的扫描入口。
    返回: (success, status_message, error_detail)
    """
    success, result, error = execute_scan_async(
        project_id=project_id,
        tool_type=tool_type,
        trigger_type="scheduled",
    )
    if success:
        msg = f"定时扫描已提交: project={project_id}, tool={tool_type}, scan_id={result.get('id')}"
        logger.info(f"[ScannerService] {msg}")
        return True, msg, ""
    else:
        logger.error(f"[ScannerService] 定时扫描失败: {error}")
        return False, error, error
