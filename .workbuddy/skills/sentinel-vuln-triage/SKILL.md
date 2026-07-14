---
name: sentinel-vuln-triage
description: >-
  调用 Sentinel 安全平台的「漏洞智能分诊」技能：依据 CVSS 3.0 评分对全部漏洞
  重新定级（critical/high/medium/low），修正 severity 与评分不一致的项并写回漏洞表。
  当用户需要统一漏洞定级标准、清理历史定级错配、或在提交报告前做一次定级体检时使用。
  纯平台内编排，低风险、不涉及密钥、不出网、不触碰认证与加密模块。
---

# 漏洞智能分诊（sentinel-vuln-triage）

把 Sentinel 平台里「漏洞管理」已有的数据做一次基于 CVSS 的客观定级体检。
本 skill 是后端 `backend/routes/skills.py` 中 `vuln-triage` 的薄封装，
前端「技能中心」(Skills.tsx) 也调用同一个端点，行为完全一致。

## 何时使用

- 用户说「帮我统一一下漏洞定级」「漏洞的 severity 和 CVSS 对不上」「跑一下分诊」
- 提交安全报告 / 周报前，确认定级口径一致
- 导入了第三方扫描器数据，想用统一标准重新定级

## 安全边界（务必遵守）

- **低风险**：只读后按 CVSS 写回 `severity` 字段，不删数据、不触密码、不出网。
- **不碰认证/加密**：禁止读取 `users` 口令、`JWT_SECRET` 或任何密钥材料。
- 若平台未运行或用户未授权，不要自行启动服务或猜测凭据。

## 调用流程

所有请求走 Sentinel 后端（默认 `http://127.0.0.1:5000`）。
技能端点受 `login_required` 保护，需先取 JWT。

### 1. 登录取 token

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"<USER_EMAIL>","password":"<USER_PASSWORD>"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
echo "$TOKEN"   # 仅本会话内使用，不要写入文件或回显到日志外
```

> 凭据由用户提供，绝不硬编码、不写记忆、不回显到交付物。

### 2. 运行分诊

```bash
curl -s -X POST http://127.0.0.1:5000/api/skills/vuln-triage/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

### 3. 预期返回（示例）

```json
{
  "skill": "vuln-triage",
  "updated": 3,
  "total": 1122,
  "message": "已重新定级 3 / 1122 个漏洞（依据 CVSS 评分）"
}
```

- `updated`：本次被纠正定级数量的漏洞数（一致则为 0）。
- `total`：漏洞表总条数。
- 定级规则（与 `integrations/codeql.py` 一致，CVSS 3.0）：
  `>=9.0→critical`，`>=7.0→high`，`>=4.0→medium`，其余 `low`；
  CVSS 为 0 时保留原 severity。

## 结果呈现给用户

- 用一句话总结：`「本次修正 N 个定级不一致的漏洞（共 M 个），已在漏洞管理页生效」`。
- 若 `updated=0`：说明「定级已与 CVSS 一致，无需改动」——这是正常健康状态，不是失败。
- 提醒用户可前往前端「漏洞管理」页查看更新后的 severity 标记。

## 维护参考

- 后端实现：`backend/routes/skills.py` → `_run_vuln_triage()` / `_cvss_to_severity()`
- 蓝图注册：`backend/app.py` 中 `register_blueprint(skills_bp, url_prefix="/api/skills")`
- 如需调整分级阈值，改 `_cvss_to_severity()` 并在本文件同步说明。
