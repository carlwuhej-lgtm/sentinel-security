"""
哨兵安全平台 — 定时扫描调度 API

端点:
  GET    /api/schedules           — 列出所有调度
  GET    /api/schedules/stats     — 调度器统计
  POST   /api/schedules           — 创建调度
  GET    /api/schedules/<id>      — 获取调度详情
  PUT    /api/schedules/<id>      — 更新调度
  DELETE /api/schedules/<id>      — 删除调度
  POST   /api/schedules/<id>/run  — 手动触发一次
"""

from flask import Blueprint, request, jsonify
from routes.auth import login_required, admin_required
from services.scheduler_service import (
    list_schedules, get_schedule, create_schedule,
    update_schedule, delete_schedule, trigger_schedule_now,
    get_scheduler_stats,
)

schedules_bp = Blueprint("schedules", __name__)


# ─── CRUD 端点 ───

@schedules_bp.route("", methods=["GET"])
@login_required
def api_list_schedules():
    return jsonify(list_schedules())


@schedules_bp.route("/stats", methods=["GET"])
@login_required
def api_scheduler_stats():
    return jsonify(get_scheduler_stats())


@schedules_bp.route("", methods=["POST"])
@login_required
@admin_required
def api_create_schedule():
    data = request.get_json(silent=True) or {}
    success, result, error = create_schedule(data)
    if not success:
        return jsonify({"error": error}), 400
    return jsonify(result), 201


@schedules_bp.route("/<int:sid>", methods=["GET"])
@login_required
def api_get_schedule(sid: int):
    result = get_schedule(sid)
    if result is None:
        return jsonify({"error": "调度不存在"}), 404
    return jsonify(result)


@schedules_bp.route("/<int:sid>", methods=["PUT"])
@login_required
@admin_required
def api_update_schedule(sid: int):
    data = request.get_json(silent=True) or {}
    success, result, error = update_schedule(sid, data)
    if not success:
        return jsonify({"error": error}), 404
    return jsonify(result)


@schedules_bp.route("/<int:sid>", methods=["DELETE"])
@login_required
@admin_required
def api_delete_schedule(sid: int):
    success, error = delete_schedule(sid)
    if not success:
        return jsonify({"error": error}), 404
    return jsonify({"ok": True, "message": "调度已删除"})


@schedules_bp.route("/<int:sid>/run", methods=["POST"])
@login_required
@admin_required
def api_trigger_schedule(sid: int):
    success, msg = trigger_schedule_now(sid)
    if not success:
        return jsonify({"error": msg}), 404
    return jsonify({"ok": True, "message": msg})
