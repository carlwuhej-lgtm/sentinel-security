# 哨兵安全管理平台 — MCP Server 接入指南

让支持 MCP 的 AI 客户端（Claude Desktop / Cursor / WorkBuddy 等）通过标准 MCP 协议
直接调用哨兵平台的安全能力：用自然语言查漏洞、查知识库、跑已审批技能。

> MCP Server 是独立 stdio 进程，**不依赖 Flask Web 服务**，也不提供前端页面——
> 它是给 AI 客户端用的「插头」，让 AI 能「拧」进哨兵。

## 暴露的能力（最小权限）

| 类型 | 名称 | 说明 |
|---|---|---|
| tool | `list_vulnerabilities(severity?, limit?)` | 列出漏洞，可按严重度过滤 |
| tool | `get_vulnerability_stats()` | 各严重度漏洞数量统计 |
| tool | `search_knowledge(query?, cwe?)` | 检索已发布知识库（关键词 / CWE） |
| tool | `list_skills()` | 列出当前已上架（approved）的技能 |
| tool | `run_skill(skill_id, params?)` | 运行一个已审批技能（受审批闸门约束） |
| resource | `sentinel://vulnerability-summary` | 漏洞总览文本摘要 |
| prompt | `daily_security_report` | 安全运营日报提示词模板 |

## 本地启动（stdio 传输）

```bash
cd backend
venv/Scripts/python.exe mcp_server.py
```

- stdio 模式下 **stdout 专供 MCP 协议**，切勿 `print` 到 stdout；
  运行审计写入 `backend/mcp_audit.log`。
- 依赖见 `backend/requirements-mcp.txt`（已安装于 `backend/venv`）。

## 客户端配置

### Claude Desktop — `claude_desktop_config.json`

```json
{
  "mcpServers": {
    "sentinel-security": {
      "command": "C:/Users/Jy/WorkBuddy/2026-06-30-15-39-50/sentinel-security/backend/venv/Scripts/python.exe",
      "args": ["C:/Users/Jy/WorkBuddy/2026-06-30-15-39-50/sentinel-security/backend/mcp_server.py"]
    }
  }
}
```

### Cursor — `.cursor/mcp.json`（或 Settings → MCP）

```json
{
  "mcpServers": {
    "sentinel-security": {
      "command": "C:/Users/Jy/WorkBuddy/2026-06-30-15-39-50/sentinel-security/backend/venv/Scripts/python.exe",
      "args": ["C:/Users/Jy/WorkBuddy/2026-06-30-15-39-50/sentinel-security/backend/mcp_server.py"]
    }
  }
}
```

配置后重启客户端，即可用自然语言驱动，例如：
- “本周 critical / high 漏洞有哪些？”
- “把 CWE-79 的处置建议调出来”
- “运行 code-audit 技能，生成 Java 审查清单”

## 安全约束（必须守住）

1. **最小权限**：仅暴露只读查询 + 运行已审批技能；**不暴露**认证 / 加密 / 用户管理 / 写管理。
2. **审批闸门复用**：`run_skill` 仅允许 `approval=approved` 的技能；第三方技能需先在
   前端「技能中心」由管理员「通过」后才能经 MCP 运行。
3. **审计**：每次调用记录在 `backend/mcp_audit.log`（工具名 + 参数）。
4. **部署边界**：仅在受信本地 / 内网运行；**不要直接公网暴露** stdio 进程。
   远程接入需套反向代理 + Bearer 认证（预留环境变量 `SENTINEL_MCP_TOKEN` 用于将来
   HTTP 传输校验）。

## 与技能中心的关系

`backend/mcp_server.py` 自包含「技能清单加载 + script 运行 + CVSS 定级」逻辑，
避免 import Flask app（MCP 是独立进程，无 `flask.g` 上下文）。若修改
`backend/routes/skills.py` 的以下逻辑，请同步 `mcp_server.py`：
`SKILLS 内置列表 / load_manifest_skills / _cvss_to_severity / script runner`。

---

## 平台接入外部 MCP（Client 模式）

除「对外暴露」(Server) 外，哨兵也可作为 **MCP Client** 接入**别人写好的 MCP Server**，
把外部能力变成技能中心里的一张可运行卡片。这让你 / 第三方写好的 MCP「拿来就能用」，
且与内置 skill 走同一套上传 → 审批 → 运行框架（`runner.type = "mcp"`）。

### 前端操作
1. 打开「技能中心」(`/skills`) → 点 **「+ 接入 MCP」**
2. 填写：
   - **传输方式**：`stdio`（本地进程，如 `npx @vendor/mcp`）或 `sse`（远程 http/https）
   - **stdio**：启动命令 `command`（如 `npx`）+ 参数 `args`（逗号分隔）
   - **sse**：连接地址 `url`（如 `http://localhost:8000/sse`）
   - **要调用的 tool 名**（外部 MCP 暴露的 tool）
3. 提交 → 进入「待审批」→ 管理员「通过」后上架，点「运行技能」即由平台作为 client 连接并调用。

### manifest 示例（前端自动拼装）
```json
{
  "id": "vendor-cve-mcp",
  "name": "某厂商 CVE 情报 MCP",
  "description": "连外部 MCP 拉取 CVE 情报",
  "risk": "medium",
  "runner": {
    "type": "mcp",
    "transport": "stdio",
    "command": "npx",
    "args": ["-y", "@vendor/cve-mcp"],
    "tool": "get_cve",
    "timeout": 20
  }
}
```

### 实现要点（backend/routes/skills.py）
- `runner.type = "mcp"` 触发 `_run_mcp_runner`；`transport` 决定用 `stdio_client` 或 `sse_client`
- 运行时再 `list_tools()` 校验声明的 tool 确实存在，仅调用该 tool
- 超时隔离（`asyncio.wait_for`），外部 MCP 崩溃 / 超时不影响平台
- 审计写入 `backend/mcp_client_audit.log`（工具 / transport / 成败）

### 安全约束（供应链闸门，不可退让）
1. **必须管理员审批**：第三方 MCP 默认 `pending`，绝不允许「丢进来就能跑」
2. **不注入密钥**：平台只传 command/args/url/tool，**绝不**把 `JWT_SECRET` / 数据库口令等
   内部密钥传给外部 MCP Server
3. **最小权限**：仅调用声明的单个 tool，不暴露平台内部能力
4. **网络约束**：`sse` 类需显式声明 https 地址；不明来源的外部 MCP 接入须谨慎评估
