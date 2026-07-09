# Sentinel Security v4.0 — Linux 部署指南

> 适用：将哨兵应用安全平台从 Windows 开发环境部署到 Linux 服务器。
> 配套部署包：`sentinel-security-linux.tar.gz`

---

## 一、部署包说明

| 项目 | 内容 |
|------|------|
| 文件名 | `sentinel-security-linux.tar.gz`（约 9.4 MB） |
| **包含** | 后端源码 `backend/`（不含 venv）、前端源码与构建产物 `frontend/`（含 `dist/`）、Docker 编排 `docker-compose.yml` / `Dockerfile.backend` / `Dockerfile.frontend` / `nginx.conf`、CI 配置 `.github/`、文档 `docs/` |
| **不含**（部署时自动生成/安装） | `venv`、`node_modules`、`__pycache__`、`*.pyc`、数据库 `sentinel.db`（全新初始化） |

> 部署包**不含任何业务数据**，Linux 上将以**全新空库**启动；首次启动自动创建默认管理员账号，无需手动初始化。

---

## 二、方式一：Docker Compose 部署（推荐）

### 1. 上传并解压

```bash
# 在 Windows / 本地执行
scp sentinel-security-linux.tar.gz user@<linux-ip>:/opt/

# 登录 Linux
ssh user@<linux-ip>
cd /opt
tar -xzf sentinel-security-linux.tar.gz
cd sentinel-security
```

### 2. 配置环境变量（可选，但生产必做）

项目根目录创建 `.env` 文件（docker-compose.yml 会读取）：

```bash
# .env
# ⚠️ 生产环境务必替换为强随机值，否则使用默认弱密钥
SENTINEL_JWT_SECRET=<请生成一段至少 32 位的随机字符串>

BACKEND_PORT=5000
FRONTEND_PORT=80

# 可选：AI 智能分析（默认 ollama，不配置则 AI 功能不可用，不影响其余功能）
SENTINEL_AI_PROVIDER=ollama
SENTINEL_AI_BASE=http://host.docker.internal:11434/v1
SENTINEL_AI_MODEL=qwen3:0.6b

# 可选：SMTP 邮件通知
SENTINEL_SMTP_ENABLED=false
SENTINEL_SMTP_HOST=
SENTINEL_SMTP_PORT=587
SENTINEL_SMTP_USER=
SENTINEL_SMTP_PASS=
SENTINEL_SMTP_FROM=
```

> 生成随机密钥示例：`openssl rand -hex 32`

### 3. 启动

```bash
docker compose up -d

# 查看运行状态
docker compose ps

# 查看后端日志（首次启动会看到建表与默认管理员创建）
docker compose logs -f backend
```

### 4. 访问与初始化

- **前端界面**：`http://<服务器IP>:80`（或 `FRONTEND_PORT` 指定端口）
- **后端 API**：`http://<服务器IP>:5000`
- **首次登录账号**：`admin@sentinel.io` / `admin123`
- 首次登录会被**强制要求修改密码**，改密后即可正常使用。
- 数据库通过 Docker 卷 `sentinel_data` 持久化（容器内路径 `/data/sentinel.db`），升级/重启数据不丢失。

---

## 三、方式二：裸机部署（无 Docker）

### 3.1 后端

```bash
cd sentinel-security/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn            # 生产推荐使用 gunicorn

# 必须指定数据库路径（指向真实库文件，全新库会自动建表+默认管理员）
export SENTINEL_DB_PATH="$(pwd)/sentinel.db"

# 生产启动（4 工作进程）
gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 "app:create_app()"

# 或开发模式
# python run.py
```

### 3.2 前端（Nginx 托管 `dist/`）

部署包已包含构建产物 `frontend/dist`，直接用 Nginx 托管即可（无需 Node 环境）：

```nginx
server {
    listen 80;
    server_name _;
    root /opt/sentinel-security/frontend/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # 反向代理后端 API
    location /api {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

> 如需重新构建前端（自定义 API 地址等）：
> ```bash
> cd sentinel-security/frontend
> npm ci --legacy-peer-deps
> npm run build        # 产物输出到 frontend/dist
> ```

---

## 四、关键配置说明

| 配置项 | 说明 |
|--------|------|
| `SENTINEL_DB_PATH` | SQLite 数据库文件路径。**务必正确指向**；全新库启动会自动建表并创建默认管理员。 |
| `SENTINEL_JWT_SECRET` | JWT 签名密钥。**生产环境必须设为强随机值**（Docker 通过 `.env` 的 `SENTINEL_JWT_SECRET` 注入）。 |
| `SENTINEL_SCANNER_MODE` | 扫描模式，默认 `real`（真实扫描）。真实扫描需在 backend 环境安装 `semgrep` 等工具（Docker 可在 `Dockerfile.backend` 取消 `pip install semgrep` 注释行；裸机用 `pip install semgrep`）。 |
| AI 配置 | `SENTINEL_AI_PROVIDER` / `SENTINEL_AI_BASE` / `SENTINEL_AI_MODEL`，可选；不配置时 AI 分析不可用，其余功能正常。 |
| 邮件/通知 | `SENTINEL_SMTP_*` 与飞书机器人（在平台「设置」中配置），可选。 |

---

## 五、运维与升级

### 数据备份
- **Docker**：数据库在卷 `sentinel_data` 中。定位并拷贝：
  ```bash
  docker volume inspect sentinel_data   # 找到 Mountpoint
  cp <Mountpoint>/sentinel.db /backup/sentinel-$(date +%F).db
  ```
- **裸机**：直接拷贝 `SENTINEL_DB_PATH` 指向的 `sentinel.db` 文件。
- 也可在平台内「设置 → 数据备份」一键生成快照并下载。

### 升级
重新上传新版部署包并解压，然后：

```bash
cd sentinel-security
docker compose up -d --build     # 数据卷 sentinel_data 保留，业务数据不丢
```

### 安全建议
- 部署后立即修改默认管理员密码（首次登录强制改密）。
- 将 `SENTINEL_JWT_SECRET` 设为强随机值。
- 公开注册默认关闭（邀请模式），如需开放请在「设置 → 外观 → 注册策略」中开启。
- 生产建议在前端 Nginx 前再加一层 HTTPS 反向代理（如 Caddy / 云厂商 LB）。

### 故障排查
- 后端无法启动：检查 `SENTINEL_DB_PATH` 路径是否可写；SQLite 建议使用 DELETE 日志模式（默认已配置），避免残留 `-wal`/`-shm` 锁文件。
- 前端白屏/API 报错：确认 Nginx 反向代理 `/api` 指向后端 `5000` 端口；Docker 方式确认 `VITE_API_URL` 是否正确。
- 查看健康：后端 `GET /api/auth/register/status` 应返回 `200`。

---

> 本指南基于 Sentinel Security v4.0 的 Docker 编排与源码编写。完整产品功能见《Sentinel-Security-使用手册.md》。
