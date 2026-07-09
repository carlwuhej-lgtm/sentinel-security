# Sentinel Security — CI/CD 集成指南

平台提供两种把安全扫描接入研发流水线的方式，任选其一。

---

## 方式 A：原生 Git Push 自动触发（推荐，零 CI 改动）

平台已内置 GitHub / GitLab 的 push 事件接收端点，**配置一次即可，代码 push 自动扫描**。

### GitHub
仓库 `Settings → Webhooks`：
- **Payload URL**：`https://<你的域名>/api/webhooks/github`
- **Content type**：`application/json`
- **Secret**：平台 Webhook Token（在 设置 → 安全门禁 中生成/查看）
- **Events**：仅勾选 `Push`

### GitLab
项目 `Settings → Webhooks`：
- **URL**：`https://<你的域名>/api/webhooks/gitlab`
- **Secret Token**：平台 Webhook Token
- **Trigger**：勾选 `Push events`

> 平台按仓库 URL（自动归一化 https/ssh 形式）或仓库名匹配到已配置的项目，
> 自动以 `SAST` 工具触发扫描并跑安全门禁。

---

## 方式 B：CI 流水线主动调用（适用于任意 CI）

在流水线 build/test 之后加一步，调用通用触发端点 `POST /api/webhooks/scan`。

### GitHub Actions（见 .github/workflows/security-scan.yml）
在仓库 `Settings → Secrets` 配置：
- `SENTINEL_URL`：平台地址，如 `https://sentinel.yourcompany.com`
- `SENTINEL_TOKEN`：平台 Webhook Token

### GitLab CI（.gitlab-ci.example.yml）
在 `Settings → CI/CD → Variables` 配置同名变量后，在 `.gitlab-ci.yml` 引入该示例。

### 安全门禁
响应中的 `gate.decision`：
- `block` → 存在 Critical/High，建议 `exit 1` 阻断构建
- `warn`  → 存在高危，放行但告警
- `pass`  → 通过

门禁规则可在 `GET/PUT /api/webhooks/config` 调整（如把 High 也设为 block）。
