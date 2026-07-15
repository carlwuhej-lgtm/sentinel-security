#!/usr/bin/env bash
# Sentinel 后端一键重启：先杀掉占用 5000 端口的旧实例，再干净启动。
# 用法: bash backend/restart.sh
set -u

PORT="${SENTINEL_PORT:-5000}"
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR" || exit 1

echo ">> 查找占用端口 $PORT 的进程..."
# 跨平台: lsof / fuser / ss
PIDS=""
if command -v lsof >/dev/null 2>&1; then
  PIDS="$(lsof -ti tcp:$PORT 2>/dev/null)"
elif command -v fuser >/dev/null 2>&1; then
  PIDS="$(fuser "$PORT/tcp" 2>/dev/null | tr -d ' ')"
elif command -v ss >/dev/null 2>&1; then
  PIDS="$(ss -ltnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | tr '\n' ' ')"
fi

if [ -n "$PIDS" ]; then
  echo ">> 终止旧实例: $PIDS"
  # shellcheck disable=SC2086
  kill $PIDS 2>/dev/null || true
  sleep 2
  # 兜底强杀
  # shellcheck disable=SC2086
  kill -9 $PIDS 2>/dev/null || true
else
  echo ">> 未发现占用进程"
fi

# 激活 venv（若存在）
if [ -f venv/bin/activate ]; then
  # shellcheck disable=SC1091
  . venv/bin/activate
fi

echo ">> 启动后端 (python run.py) ..."
nohup python run.py > backend.log 2>&1 &
echo ">> 已后台启动，日志见 backend/backend.log"
sleep 3
curl -s -o /dev/null -w ">> 健康检查 HTTP %{http_code}\n" "http://localhost:$PORT/api/health" || true
