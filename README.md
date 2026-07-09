# Sentinel Security Platform（哨兵应用安全平台）

企业级 DevSecOps 应用安全编排平台（v4.0）。将资产盘点、漏洞扫描、风险管理、工单流转、AI 辅助分析与安全知识库整合到统一工作流中，帮助安全团队在软件开发生命周期（SDLC）全程内嵌安全。

## 核心能力

- **资产与项目管理**：按业务项目组织资产，统一视图追踪安全状况
- **多引擎漏洞扫描**：SAST（Semgrep / CodeQL）、DAST（OWASP ZAP）、依赖扫描（Dependency-Check / Trivy）、密钥扫描（Gitleaks）
- **漏洞生命周期管理**：发现 → 定级（CVSS / CWE）→ 修复 → 验证 → 闭环
- **告警与工单**：可配置告警规则与通知渠道，漏洞一键转工单流转
- **AI 辅助分析**：针对漏洞与风险给出修复建议和影响分析
- **安全知识库**：沉淀检测规则、修复模板与典型案例
- **审计与合规**：完整操作审计日志，满足合规追溯要求
- **RBAC 权限模型**：`admin` / `security_analyst` / `developer` / `viewer` 四角色
- **CI/CD 集成**：流水线安全门禁、定时调度、邮件 / 飞书通知

## 技术栈

| 层 | 技术 |
|----|------|
| 后端 | Flask 3（Python 3.11+）+ SQLite + JWT 认证 |
| 前端 | React 18 + TypeScript + Vite + Tailwind CSS |
| 部署 | Docker / Docker Compose + Nginx |
| 编排 | 原生 scheduler 守护线程 + 扫描服务守护线程 |

## 快速开始

### 方式一：Docker Compose（推荐）

```bash
git clone https://github.com/carlwuhej-lgtm/sentinel-security.git
cd sentinel-security
docker compose up -d
```

- 前端访问：http://localhost
- 后端 API：http://localhost:5000/api

### 方式二：本地开发

```bash
# 后端
cd backend
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
export SENTINEL_DB_PATH="$(pwd)/sentinel.db"
python run.py

# 前端（另开一个终端）
cd frontend
npm install
npm run dev
```

## 默认管理员

| 账号 | 密码 | 说明 |
|------|------|------|
| `admin@sentinel.io` | `admin123` | **首次登录强制改密** |

> 注册默认关闭（邀请模式）。管理员可在「用户管理」中创建账号，或在「设置 → 注册策略」中开放公开注册。

## 目录结构

```
sentinel-security/
├── backend/              # Flask 后端
│   ├── routes/           # 业务蓝图（漏洞、扫描、工单、告警、资产、知识库、用户等）
│   ├── services/         # 调度、扫描、通知等后台服务
│   ├── integrations/     # Semgrep / CodeQL / ZAP / Trivy 等扫描器集成
│   ├── app.py            # 应用入口与初始化
│   └── config.py         # 配置
├── frontend/             # React 前端（src/pages、src/components）
├── docs/                 # 文档
├── docker-compose.yml    # 服务编排
├── Dockerfile.backend     # 后端镜像
├── Dockerfile.frontend    # 前端镜像（源码构建）
├── nginx.conf            # 反向代理配置
└── .env.example          # 配置示例
```

## 文档

- `docs/ci-cd-integration.md` — CI/CD 安全门禁与流水线集成指南
- 完整使用手册（产品功能、角色权限、运维 FAQ）与 Linux 部署指南随项目交付物提供

## 安全说明

- 认证采用 PBKDF2（约 26 万轮）+ JWT（HS256，`token_version` 支持吊销）
- 所有数据库访问参数化，无 SQL 注入；子进程调用均使用参数列表，无命令注入
- CORS 仅允许白名单来源
- 生产环境请务必设置强随机的 `SENTINEL_JWT_SECRET`，并修改默认管理员口令
- 本项目为公开仓库，**请勿在源码中硬编码任何密钥或凭证**，所有敏感配置请通过环境变量提供

## 许可证

本项目许可证以仓库内 `LICENSE` 文件为准（如未提供，默认保留所有权利）。
