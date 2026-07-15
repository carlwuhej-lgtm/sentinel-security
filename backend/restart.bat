@echo off
REM Sentinel 后端一键重启：先杀掉占用 5000 端口的旧实例，再干净启动。
REM 用法: backend\restart.bat
setlocal
set PORT=5000
cd /d "%~dp0"

echo ^>> 查找占用端口 %PORT% 的进程...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT% " ^| findstr "LISTENING"') do (
  echo ^>> 终止旧实例 PID %%a
  taskkill /F /PID %%a >nul 2>&1
)
timeout /t 2 >nul

if exist venv\Scripts\activate.bat (
  call venv\Scripts\activate.bat
)

echo ^>> 启动后端 (python run.py) ...
start "Sentinel-Backend" /min python run.py
timeout /t 3 >nul
powershell -Command "try { (Invoke-WebRequest -Uri 'http://localhost:%PORT%/api/health' -UseBasicParsing -TimeoutSec 3).StatusCode } catch { 'health check failed' }"
echo ^>> 已启动，日志见 backend\backend.log
endlocal
