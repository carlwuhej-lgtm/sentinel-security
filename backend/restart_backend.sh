#!/usr/bin/env bash
# 哨兵后端一键重启脚本
# 用法（在 Git Bash 中）：  bash restart_backend.sh
# 作用：找到占用 5000 的进程 -> 杀掉 -> 用 Anaconda python 后台启动 run.py -> 轮询验证监听
# 说明：仅杀死 5000 端口监听进程，不动其他进程；日志写入 backend/backend.log
set -e

PORT=5000
PY="D:/service/Anaconda/python.exe"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[restart] 查找占用 :$PORT 的监听进程..."
PID=$(netstat -ano 2>/dev/null | grep -E ":$PORT +" | grep LISTENING | awk '{print $5}' | head -1)
if [ -n "$PID" ]; then
  echo "[restart] 杀掉旧进程 PID=$PID"
  kill -f "$PID" 2>/dev/null || taskkill //PID "$PID" //F 2>/dev/null || true
  sleep 2
else
  echo "[restart] 未发现 :$PORT 监听，直接启动"
fi

echo "[restart] 用 $PY 后台启动 run.py ..."
nohup "$PY" run.py > backend.log 2>&1 &
NEW_PID=$!
echo "[restart] 新进程 PID=$NEW_PID，日志 -> backend/backend.log"

for i in $(seq 1 20); do
  if netstat -ano 2>/dev/null | grep -E ":$PORT +" | grep -q LISTENING; then
    echo "[restart] :$PORT 已监听，启动成功 (PID=$NEW_PID) ✅"
    exit 0
  fi
  sleep 1
done
echo "[restart] 警告：20s 内未监听到 :$PORT，请查看 backend/backend.log" >&2
exit 1
