import logging
logger = logging.getLogger(__name__)
"""
哨兵安全平台 — 定时扫描调度服务

基于 APScheduler 实现的轻量级定时扫描调度器。
支持 cron 表达式和简单间隔两种模式。

架构：
  APScheduler (BackgroundScheduler)
    ├── 启动时从 scan_schedules 表加载所有活跃调度
    ├── 每个调度对应一个 cron/interval 任务
    └── 任务执行时调用 scanner_service.scan_for_schedule()

API 端点（由 routes/schedules.py 提供）：
  GET    /api/schedules          — 列出所有调度
  POST   /api/schedules          — 创建调度
  PUT    /api/schedules/<id>     — 更新调度
  DELETE /api/schedules/<id>     — 删除调度
  POST   /api/schedules/<id>/run — 手动触发一次
"""

import os
import sqlite3
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from config import DATABASE_PATH

# ═══════════════════════════════════════════════════════
# 全局调度器实例
# ═══════════════════════════════════════════════════════

_scheduler: Optional[BackgroundScheduler] = None


def _get_db_path() -> str:
    return os.environ.get("SENTINEL_DB_PATH", DATABASE_PATH)


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(_get_db_path(), timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=DELETE")
    except sqlite3.OperationalError:
        pass
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ═══════════════════════════════════════════════════════
# 数据库迁移
# ═══════════════════════════════════════════════════════

def migrate_scheduler(conn: sqlite3.Connection):
    """
    Phase 4 迁移: 添加定时扫描支持。
    - scan_tasks 表增加 trigger_type 列
    - 创建 scan_schedules 表
    """
    cur = conn.cursor()

    # 1. trigger_type 列
    try:
        cur.execute("ALTER TABLE scan_tasks ADD COLUMN trigger_type TEXT DEFAULT 'manual'")
    except sqlite3.OperationalError:
        pass

    # 2. scan_schedules 表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_schedules (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id      INTEGER NOT NULL,
            tool_type       TEXT    NOT NULL DEFAULT 'SAST',
            schedule_type   TEXT    NOT NULL DEFAULT 'cron',
            cron_expression TEXT    NOT NULL DEFAULT '0 2 * * *',
            interval_hours  INTEGER DEFAULT 24,
            enabled         INTEGER NOT NULL DEFAULT 1,
            last_run_at     TEXT    DEFAULT '',
            last_run_status TEXT    DEFAULT '',
            next_run_at     TEXT    DEFAULT '',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            updated_at      TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    logger.info("[Scheduler] Migration Phase 4 completed")


# ═══════════════════════════════════════════════════════
# 调度器管理
# ═══════════════════════════════════════════════════════

def init_scheduler() -> BackgroundScheduler:
    """
    初始化并启动调度器。
    从数据库加载所有活跃调度并注册为 APScheduler 任务。
    """
    global _scheduler

    db_path = _get_db_path()

    # 使用 SQLite 内存存储（轻量方案，不依赖 SQLAlchemy 持久化）
    _scheduler = BackgroundScheduler(
        job_defaults={
            "coalesce": True,
            "max_instances": 1,
            "misfire_grace_time": 300,  # 5 分钟容错
        },
        timezone="Asia/Shanghai",
    )

    # 迁移数据表
    conn = _get_db()
    try:
        migrate_scheduler(conn)
    finally:
        conn.close()

    # 加载所有活跃调度
    _load_all_schedules()

    _scheduler.start()
    logger.info(f"[Scheduler] Started with {len(_scheduler.get_jobs())} schedules")

    return _scheduler


def _load_all_schedules():
    """从数据库加载所有启用的调度并注册任务。"""
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM scan_schedules WHERE enabled = 1"
        ).fetchall()

        for row in rows:
            _add_schedule_job(dict(row))
    finally:
        conn.close()


def _add_schedule_job(schedule: dict):
    """将单个调度注册为 APScheduler 任务。"""
    if _scheduler is None:
        return

    trigger = _build_trigger(schedule)
    if trigger is None:
        logger.info(f"[Scheduler] Invalid trigger for schedule #{schedule['id']}")
        return

    job_id = f"scan_schedule_{schedule['id']}"

    # 先移除已有的同名任务
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)

    _scheduler.add_job(
        _run_scheduled_scan,
        trigger=trigger,
        id=job_id,
        args=[schedule["id"], schedule["project_id"], schedule["tool_type"]],
        replace_existing=True,
    )

    # 更新下次执行时间
    job = _scheduler.get_job(job_id)
    if job and job.next_run_time:
        next_run = job.next_run_time.strftime("%Y-%m-%d %H:%M:%S")
        conn = _get_db()
        try:
            conn.execute(
                "UPDATE scan_schedules SET next_run_at=? WHERE id=?",
                (next_run, schedule["id"]),
            )
            conn.commit()
        finally:
            conn.close()


def _remove_schedule_job(schedule_id: int):
    """移除 APScheduler 任务。"""
    if _scheduler is None:
        return
    job_id = f"scan_schedule_{schedule_id}"
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)


def _build_trigger(schedule: dict):
    """根据调度配置构建 APScheduler 触发器。"""
    schedule_type = schedule.get("schedule_type", "cron")

    if schedule_type == "cron":
        cron_expr = schedule.get("cron_expression", "0 2 * * *").strip()
        parts = cron_expr.split()
        if len(parts) != 5:
            # 尝试解析带秒字段的表达式
            if len(parts) == 6:
                parts = parts[1:]  # 去掉秒字段
            else:
                return None
        try:
            return CronTrigger(
                minute=parts[0],
                hour=parts[1],
                day=parts[2],
                month=parts[3],
                day_of_week=parts[4],
                timezone="Asia/Shanghai",
            )
        except Exception:
            return None

    elif schedule_type == "interval":
        hours = int(schedule.get("interval_hours", 24))
        return IntervalTrigger(hours=hours, timezone="Asia/Shanghai")

    return None


def _run_scheduled_scan(schedule_id: int, project_id: int, tool_type: str):
    """
    执行定时扫描（由 APScheduler 触发）。
    更新执行状态到数据库。
    """
    from services.scanner_service import scan_for_schedule

    start_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    success, msg, error = scan_for_schedule(project_id, tool_type, schedule_id)

    conn = _get_db()
    try:
        conn.execute(
            """UPDATE scan_schedules
               SET last_run_at = ?, last_run_status = ?,
                   updated_at = datetime('now','localtime')
               WHERE id = ?""",
            (start_time, "completed" if success else "failed", schedule_id),
        )
        conn.commit()
    finally:
        conn.close()


def reload_schedule(schedule_id: int):
    """单个调度变更后重新加载。"""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM scan_schedules WHERE id=?", (schedule_id,)
        ).fetchone()
        if row is None:
            _remove_schedule_job(schedule_id)
            return

        sched = dict(row)
        if sched["enabled"]:
            _add_schedule_job(sched)
        else:
            _remove_schedule_job(schedule_id)
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════
# CRUD 操作（供 API 路由调用）
# ═══════════════════════════════════════════════════════

def list_schedules() -> List[Dict]:
    """列出所有调度（含项目名）。"""
    conn = _get_db()
    try:
        rows = conn.execute("""
            SELECT ss.*, p.name as project_name
            FROM scan_schedules ss
            LEFT JOIN projects p ON ss.project_id = p.id
            ORDER BY ss.created_at DESC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_schedule(schedule_id: int) -> Optional[Dict]:
    """获取单个调度详情。"""
    conn = _get_db()
    try:
        row = conn.execute("""
            SELECT ss.*, p.name as project_name
            FROM scan_schedules ss
            LEFT JOIN projects p ON ss.project_id = p.id
            WHERE ss.id=?
        """, (schedule_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def create_schedule(data: dict) -> Tuple[bool, Dict, str]:
    """
    创建新的扫描调度。
    必填: project_id, tool_type
    可选: schedule_type, cron_expression, interval_hours, enabled
    """
    project_id = data.get("project_id")
    tool_type = data.get("tool_type", "SAST").strip()
    schedule_type = data.get("schedule_type", "cron")
    cron_expression = data.get("cron_expression", "0 2 * * *")
    interval_hours = data.get("interval_hours", 24)
    enabled = data.get("enabled", 1)

    if not project_id:
        return False, {}, "project_id 为必填项"

    conn = _get_db()
    try:
        # 校验项目存在
        proj = conn.execute("SELECT id FROM projects WHERE id=?", (project_id,)).fetchone()
        if not proj:
            return False, {}, "项目不存在"

        cur = conn.execute(
            """INSERT INTO scan_schedules
               (project_id, tool_type, schedule_type, cron_expression,
                interval_hours, enabled)
               VALUES (?,?,?,?,?,?)""",
            (project_id, tool_type, schedule_type, cron_expression, interval_hours, enabled),
        )
        schedule_id = cur.lastrowid
        conn.commit()

        row = conn.execute(
            "SELECT * FROM scan_schedules WHERE id=?", (schedule_id,)
        ).fetchone()
        result = dict(row)

        # 如果启用，立即注册任务
        if enabled:
            reload_schedule(schedule_id)

        return True, result, ""
    finally:
        conn.close()


def update_schedule(schedule_id: int, data: dict) -> Tuple[bool, Dict, str]:
    """更新调度配置。"""
    conn = _get_db()
    try:
        existing = conn.execute(
            "SELECT * FROM scan_schedules WHERE id=?", (schedule_id,)
        ).fetchone()
        if not existing:
            return False, {}, "调度不存在"

        updates = []
        params = []

        for field in ["schedule_type", "cron_expression", "interval_hours", "tool_type"]:
            if field in data:
                updates.append(f"{field}=?")
                params.append(data[field])

        if "enabled" in data:
            updates.append("enabled=?")
            params.append(data["enabled"])

        if "project_id" in data and data["project_id"]:
            updates.append("project_id=?")
            params.append(data["project_id"])

        if updates:
            updates.append("updated_at=datetime('now','localtime')")
            params.append(schedule_id)
            conn.execute(
                f"UPDATE scan_schedules SET {', '.join(updates)} WHERE id=?",
                params,
            )
            conn.commit()

        row = conn.execute(
            "SELECT * FROM scan_schedules WHERE id=?", (schedule_id,)
        ).fetchone()
        result = dict(row)

        # 重新加载调度任务
        reload_schedule(schedule_id)

        return True, result, ""
    finally:
        conn.close()


def delete_schedule(schedule_id: int) -> Tuple[bool, str]:
    """删除调度。"""
    conn = _get_db()
    try:
        existing = conn.execute(
            "SELECT id FROM scan_schedules WHERE id=?", (schedule_id,)
        ).fetchone()
        if not existing:
            return False, "调度不存在"

        _remove_schedule_job(schedule_id)
        conn.execute("DELETE FROM scan_schedules WHERE id=?", (schedule_id,))
        conn.commit()
        return True, ""
    finally:
        conn.close()


def trigger_schedule_now(schedule_id: int) -> Tuple[bool, str]:
    """手动触发一次调度扫描。"""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM scan_schedules WHERE id=?", (schedule_id,)
        ).fetchone()
        if not row:
            return False, "调度不存在"

        sched = dict(row)
        _run_scheduled_scan(schedule_id, sched["project_id"], sched["tool_type"])
        return True, "扫描已触发"
    finally:
        conn.close()


def get_scheduler_stats() -> Dict:
    """获取调度器运行统计。"""
    job_count = len(_scheduler.get_jobs()) if _scheduler else 0

    conn = _get_db()
    try:
        total = conn.execute("SELECT COUNT(*) as cnt FROM scan_schedules").fetchone()["cnt"]
        active = conn.execute(
            "SELECT COUNT(*) as cnt FROM scan_schedules WHERE enabled=1"
        ).fetchone()["cnt"]
        last_runs = conn.execute(
            "SELECT * FROM scan_schedules WHERE last_run_at != '' ORDER BY last_run_at DESC LIMIT 5"
        ).fetchall()
        return {
            "total_schedules": total,
            "active_schedules": active,
            "running_jobs": job_count,
            "recent_executions": [dict(r) for r in last_runs],
        }
    finally:
        conn.close()
