"""Entry point – run: python run.py"""
import os
import sys
import socket
from dotenv import load_dotenv
from werkzeug.serving import WSGIRequestHandler

# Load .env relative to this file's directory
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
load_dotenv(_env_path)

from app import create_app
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG

app = create_app()


class _SilentWSGIRequestHandler(WSGIRequestHandler):
    """抑制 Werkzeug 在传输层注入的 Server 响应头（版本信息泄露），
    与 security_headers 中 response.headers['Server']='' 形成双重保险。"""
    def version_string(self) -> str:
        return ""


def _port_in_use(port: int) -> bool:
    """探测端口是否已有进程在监听（防止重复启动多个后端实例）。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


if __name__ == "__main__":
    if _port_in_use(FLASK_PORT):
        print(f"ERROR: 端口 {FLASK_PORT} 已被占用，可能已有 Sentinel 后端在运行。")
        print("       请先停止旧实例，或执行 backend/restart.(sh|bat) 一键重启。")
        sys.exit(1)
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG,
            use_reloader=FLASK_DEBUG, request_handler=_SilentWSGIRequestHandler)
