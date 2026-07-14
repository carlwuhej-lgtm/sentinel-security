---
name: sentinel-code-audit
description: >-
  调用 Sentinel 安全平台的「安全知识审查清单生成」技能：基于知识库（已发布文章，
  从正文提取 CWE 锚点）生成针对指定语言（general/java/python/go/javascript）的
  「安全代码审查清单」，可直接用于人工 code review。当用户需要一份按语言裁剪的、
  带有 CWE 参考点的安全审查 checklist 时使用。只读，不改写任何数据。
  低风险、不涉及密钥、不出网、不触碰认证与加密模块。
---

# 安全知识审查清单生成（sentinel-code-audit）

把 Sentinel「知识库」里已发布的安全文章，编成一张可按编程语言裁剪的审查清单。
本 skill 是后端 `backend/routes/skills.py` 中 `code-audit` 的薄封装，
前端「技能中心」(Skills.tsx) 也调用同一个端点，行为完全一致。

## 何时使用

- 用户说「给我一份 Java 安全审查清单」「code review 要看哪些 CWE」「按语言出个审计清单」
- 进入一个新语言栈的 review 前，想快速拿到带 CWE 参考点的检查项
- 安全培训 / 自查时，需要平台知识库沉淀的要点清单

## 安全边界（务必遵守）

- **只读**：仅查询 `knowledge_articles`（`is_published=1`），不 INSERT/UPDATE/DELETE。
- **低风险**：不出网、不碰密钥与认证；CWE 锚点从文章正文正则提取，不依赖外部数据源。
- 知识库表无独立 `cwe_id` 列，CWE 取自正文中的 `CWE-<数字>` 字样（如 `CWE-502`）；
  无命中时该条目 `cwe` 为空字符串，属正常。

## 调用流程

### 1. 登录取 token

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"<USER_EMAIL>","password":"<USER_PASSWORD>"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
```

> 凭据由用户提供，绝不硬编码、不写记忆、不回显到交付物。

### 2. 运行（按语言）

`language` 取值：`general`（默认）| `java` | `python` | `go` | `javascript`

```bash
curl -s -X POST http://127.0.0.1:5000/api/skills/code-audit/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"language":"java"}'
```

### 3. 预期返回（示例）

```json
{
  "skill": "code-audit",
  "language": "java",
  "language_label": "Java",
  "items": [
    {"title":"反序列化安全实践","cwe":"CWE-502","category":"代码安全","summary":"避免不可信数据进入 readObject"},
    {"title":"对称加密使用规范","cwe":"CWE-327","category":"密码学","summary":"禁用 DES/ECB，推荐 AES-GCM"}
  ],
  "count": 20,
  "message": "基于 20 篇知识库文章生成「Java」安全代码审查清单"
}
```

- `items[].cwe`：从正文提取的 CWE 锚点（可能为空）。
- `count`：命中的知识库文章数（即清单条数）。
- `language_label`：前端展示用的语言中文名。

## 结果呈现给用户

- 输出清单时，建议按 `cwe` / `title` / `category` 三列呈现，空 CWE 用 `—` 占位。
- 说明来源：`「以上清单由平台知识库 N 篇已发布文章生成，CWE 锚点取自正文」`。
- 提醒：本清单是**人工审查的辅助起点**，不能替代 SAST/DAST 工具扫描。

## 维护参考

- 后端实现：`backend/routes/skills.py` → `_run_code_audit()`
- CWE 提取：`re.compile(r"CWE-(\d+)", re.IGNORECASE)` 取正文首个命中
- 语言映射表见 `_run_code_audit()` 中 `lang_label`
- 新增/修订清单内容 → 在「知识库」发布对应文章即可，无需改代码。
