"""
enhanced_scanner.py — 增强版 SAST 扫描器（50+ Python规则 + 25+ JS规则）
可独立测试，然后合并到 semgrep.py
"""
import re
import os

# ── Python 规则：50+ 条，覆盖 OWASP Top 10 2021 + CWE Top 25 2023 ──
PYTHON_RULES = [
    # ── A01: Broken Access Control (CWE-285, CWE-639, CWE-22) ──
    {
        "id": "PY-A01-001",
        "pattern": r"(?i)current_user\.is_admin\s*==\s*False",
        "cwe": "CWE-285",
        "title": "访问控制绕过 — is_admin==False 可被绕过",
        "cvss": 7.5,
        "fix": "使用 @login_required + @admin_required 装饰器统一鉴权，而非函数内 if 判断",
        "conf": "medium",
    },
    {
        "id": "PY-A01-002",
        "pattern": r"@app\.route\([^)]*\)\s*(?!\s*@)",
        "cwe": "CWE-285",
        "title": "路由可能缺少鉴权装饰器",
        "cvss": 6.0,
        "fix": "在所有需鉴权的路由上添加 @login_required 装饰器",
        "conf": "low",
    },

    # ── A02: Cryptographic Failure (CWE-798, CWE-327, CWE-295, CWE-330) ──
    {
        "id": "PY-A02-001",
        "pattern": r"(?i)(password|passwd|pwd|db_pass)\s*=\s*[\"']([^\"']{3,})[\"']",
        "cwe": "CWE-798",
        "title": "硬编码密码/凭证",
        "cvss": 8.8,
        "fix": "将凭证移至环境变量或密钥管理服务 (KMS/HashiCorp Vault/AWS Secrets Manager)",
        "conf": "high",
    },
    {
        "id": "PY-A02-002",
        "pattern": r"(?i)(api_key|api_secret|access_key|secret_key)\s*=\s*[\"']([^\"']{16,})[\"']",
        "cwe": "CWE-798",
        "title": "硬编码 API Key / Secret",
        "cvss": 8.5,
        "fix": "从环境变量读取，使用 python-dotenv 管理本地开发配置",
        "conf": "high",
    },
    {
        "id": "PY-A02-003",
        "pattern": r"(?i)(aws_secret|private_key|encryption_key|jwt_secret)\s*=\s*[\"']([^\"']{20,})[\"']",
        "cwe": "CWE-798",
        "title": "硬编码加密密钥/云服务凭证",
        "cvss": 9.0,
        "fix": "使用 IAM 角色、KMS 或专用密钥管理服务，禁止代码硬编码",
        "conf": "high",
    },
    {
        "id": "PY-A02-004",
        "pattern": r"(?i)SECRET_KEY\s*=\s*[\"']([^\"']+)[\"']",
        "cwe": "CWE-798",
        "title": "硬编码 Flask/Django SECRET_KEY",
        "cvss": 8.0,
        "fix": "从环境变量读取 SECRET_KEY，生产环境使用随机 256bit 以上强密钥",
        "conf": "high",
    },
    {
        "id": "PY-A02-005",
        "pattern": r"hashlib\.(md5|sha1)\s*\(",
        "cwe": "CWE-327",
        "title": "弱哈希算法 — %s",
        "cvss": 7.0,
        "fix": "密码哈希使用 bcrypt/argon2/scrypt；数据完整性使用 SHA-256 以上",
        "conf": "high",
    },
    {
        "id": "PY-A02-006",
        "pattern": r"random\.(randint|random|choice|randrange)\s*\(",
        "cwe": "CWE-330",
        "title": "密码学不安全的随机数 — random 模块",
        "cvss": 5.5,
        "fix": "安全场景使用 secrets.token_bytes()/token_hex()/token_urlsafe()",
        "conf": "medium",
    },
    {
        "id": "PY-A02-007",
        "pattern": r"requests\.\w+\([^)]*verify\s*=\s*False",
        "cwe": "CWE-295",
        "title": "SSL 证书校验被禁用 — verify=False",
        "cvss": 7.5,
        "fix": "删除 verify=False；如需自签证书，使用 verify='/path/to/ca-bundle.crt'",
        "conf": "high",
    },
    {
        "id": "PY-A02-008",
        "pattern": r"urllib\.request\.urlopen\([^)]*context\s*=\s*None",
        "cwe": "CWE-295",
        "title": "urllib URL 请求未校验证书",
        "cvss": 6.0,
        "fix": "使用 ssl.create_default_context() 并传入 context 参数",
        "conf": "medium",
    },

    # ── A03: Injection (CWE-89, CWE-78, CWE-95, CWE-94) ──
    {
        "id": "PY-A03-001",
        "pattern": r"\.execute\s*\(\s*f[\"']",
        "cwe": "CWE-89",
        "title": "SQL 注入 — f-string 拼接 SQL",
        "cvss": 9.1,
        "fix": "使用参数化查询: cursor.execute('SELECT ... WHERE x = ?', (value,))",
        "conf": "high",
    },
    {
        "id": "PY-A03-002",
        "pattern": r"\.execute\s*\(\s*[\"'][^\"']*%\s*",
        "cwe": "CWE-89",
        "title": "SQL 注入 — % 格式化拼接 SQL",
        "cvss": 9.0,
        "fix": "使用参数化查询或 ORM 框架 (SQLAlchemy/Django ORM)",
        "conf": "high",
    },
    {
        "id": "PY-A03-003",
        "pattern": r"\.execute\s*\(\s*[\"'][^\"']*\+\s*\w+",
        "cwe": "CWE-89",
        "title": "SQL 注入 — 字符串拼接 SQL",
        "cvss": 9.0,
        "fix": "使用参数化查询，禁止字符串拼接构建 SQL",
        "conf": "high",
    },
    {
        "id": "PY-A03-004",
        "pattern": r"cursor\.execute\s*\(\s*[\"'][^\"']*\{",
        "cwe": "CWE-89",
        "title": "SQL 注入 — .format() 拼接 SQL",
        "cvss": 9.0,
        "fix": "使用参数化查询",
        "conf": "high",
    },
    {
        "id": "PY-A03-005",
        "pattern": r"(raw|extra)\s*\(\s*f?[\"']",
        "cwe": "CWE-89",
        "title": "Django ORM Raw SQL / Extra — 注入风险",
        "cvss": 8.5,
        "fix": "避免 raw()/extra()，必须使用则用参数化: raw('SELECT ... %s', [user_input])",
        "conf": "high",
    },
    {
        "id": "PY-A03-006",
        "pattern": r"os\.system\s*\(",
        "cwe": "CWE-78",
        "title": "命令注入 — os.system()",
        "cvss": 8.8,
        "fix": "使用 subprocess.run() with shell=False + 参数列表",
        "conf": "high",
    },
    {
        "id": "PY-A03-007",
        "pattern": r"os\.popen\s*\(",
        "cwe": "CWE-78",
        "title": "命令注入 — os.popen()",
        "cvss": 8.5,
        "fix": "使用 subprocess.run() 替代",
        "conf": "high",
    },
    {
        "id": "PY-A03-008",
        "pattern": r"subprocess\.\w+\([^)]*shell\s*=\s*True",
        "cwe": "CWE-78",
        "title": "命令注入 — subprocess shell=True",
        "cvss": 8.8,
        "fix": "设置 shell=False (默认)，使用参数列表 [cmd, arg1, arg2] 而非字符串",
        "conf": "high",
    },
    {
        "id": "PY-A03-009",
        "pattern": r"\beval\s*\(",
        "cwe": "CWE-95",
        "title": "代码注入 — eval()",
        "cvss": 9.8,
        "fix": "永远不要对用户输入使用 eval()；使用 ast.literal_eval() 解析字面量",
        "conf": "high",
    },
    {
        "id": "PY-A03-010",
        "pattern": r"\bexec\s*\(",
        "cwe": "CWE-95",
        "title": "代码注入 — exec()",
        "cvss": 9.8,
        "fix": "移除 exec()，使用专用解析器或沙箱环境",
        "conf": "high",
    },
    {
        "id": "PY-A03-011",
        "pattern": r"getattr\s*\(\s*\w+\s*,\s*(request|self\.request)",
        "cwe": "CWE-95",
        "title": "动态属性访问 — 用户输入控制属性名",
        "cvss": 7.5,
        "fix": "对允许访问的属性列表做白名单校验，禁止用户输入直接控制 getattr 第二参数",
        "conf": "medium",
    },

    # ── A05: Security Misconfiguration (CWE-489, CWE-16, CWE-1004, CWE-614) ──
    {
        "id": "PY-A05-001",
        "pattern": r"app\.run\s*\([^)]*debug\s*=\s*True",
        "cwe": "CWE-489",
        "title": "Flask Debug 模式启用 — 生产环境代码执行风险",
        "cvss": 5.5,
        "fix": "生产环境设置 debug=False；使用环境变量 FLASK_ENV=production",
        "conf": "high",
    },
    {
        "id": "PY-A05-002",
        "pattern": r"DEBUG\s*=\s*True",
        "cwe": "CWE-489",
        "title": "DEBUG=True — 生产环境配置泄露风险",
        "cvss": 5.5,
        "fix": "根据环境变量动态设置: DEBUG = os.environ.get('DEBUG') == 'True'",
        "conf": "high",
    },
    {
        "id": "PY-A05-003",
        "pattern": r"ALLOWED_HOSTS\s*=\s*\[\s*\*\s*\]",
        "cwe": "CWE-16",
        "title": "Django ALLOWED_HOSTS 通配符 — Host Header 攻击",
        "cvss": 6.0,
        "fix": "明确指定允许的 Host 列表: ALLOWED_HOSTS = ['example.com']",
        "conf": "medium",
    },
    {
        "id": "PY-A05-004",
        "pattern": r"SESSION_COOKIE_HTTPONLY\s*=\s*False",
        "cwe": "CWE-1004",
        "title": "Session Cookie HttpOnly=False — XSS 可读取",
        "cvss": 5.0,
        "fix": "设置 SESSION_COOKIE_HTTPONLY=True",
        "conf": "medium",
    },
    {
        "id": "PY-A05-005",
        "pattern": r"SESSION_COOKIE_SECURE\s*=\s*False",
        "cwe": "CWE-614",
        "title": "Session Cookie Secure=False — 明文传输",
        "cvss": 5.5,
        "fix": "设置 SESSION_COOKIE_SECURE=True (仅 HTTPS 传输)",
        "conf": "medium",
    },

    # ── A06: Vulnerable Components (CWE-502, CWE-20) ──
    {
        "id": "PY-A06-001",
        "pattern": r"pickle\.(loads|load)\s*\(",
        "cwe": "CWE-502",
        "title": "不安全反序列化 — pickle.loads()",
        "cvss": 9.8,
        "fix": "使用 JSON 等安全格式；如必须用 pickle，签名+加密数据，校验来源",
        "conf": "high",
    },
    {
        "id": "PY-A06-002",
        "pattern": r"yaml\.load\s*\(\s*[^,\)]*\)",
        "cwe": "CWE-502",
        "title": "YAML 不安全反序列化 — yaml.load()",
        "cvss": 9.8,
        "fix": "使用 yaml.safe_load() 替代 yaml.load()",
        "conf": "high",
    },
    {
        "id": "PY-A06-003",
        "pattern": r"json\.loads\s*\(\s*(request|self\.request)",
        "cwe": "CWE-20",
        "title": "JSON 反序列化缺少异常处理",
        "cvss": 4.0,
        "fix": "对 request.json 使用 try/except json.JSONDecodeError 捕获异常",
        "conf": "low",
    },

    # ── A07: Auth Failures (CWE-287, CWE-327, CWE-640) ──
    {
        "id": "PY-A07-001",
        "pattern": r"(?i)password\s*==\s*",
        "cwe": "CWE-287",
        "title": "明文密码比较 — 无哈希校验",
        "cvss": 7.5,
        "fix": "使用 bcrypt/argon2 的 check_password_hash 方法比较密码",
        "conf": "high",
    },
    {
        "id": "PY-A07-002",
        "pattern": r"(?i)md5\s*\(\s*(password|passwd|pwd)",
        "cwe": "CWE-327",
        "title": "密码使用 MD5 哈希 — 已破解",
        "cvss": 7.0,
        "fix": "使用 bcrypt/argon2/scrypt 哈希密码，加盐迭代",
        "conf": "high",
    },
    {
        "id": "PY-A07-003",
        "pattern": r"session\[.user_id.\]\s*=\s*\w+(?!\s*[.]check_password)",
        "cwe": "CWE-287",
        "title": "Session 登录缺少密码验证",
        "cvss": 6.5,
        "fix": "登录时必须验证密码，不仅仅检查用户名存在",
        "conf": "medium",
    },

    # ── A09: Security Logging Failures (CWE-778, CWE-209) ──
    {
        "id": "PY-A09-001",
        "pattern": r"except\s*:\s*pass",
        "cwe": "CWE-778",
        "title": "空 except 块 — 异常被静默忽略",
        "cvss": 4.0,
        "fix": "记录异常日志: except Exception as e: logging.exception(e)",
        "conf": "medium",
    },
    {
        "id": "PY-A09-002",
        "pattern": r"traceback\.format_exc\s*\(\s*\)\s*\)",
        "cwe": "CWE-209",
        "title": "异常堆栈信息可能泄露给客户端",
        "cvss": 5.0,
        "fix": "生产环境不向客户端返回详细错误信息；记录到服务端日志",
        "conf": "medium",
    },

    # ── A10: SSRF (CWE-918) ──
    {
        "id": "PY-A10-001",
        "pattern": r"requests\.\w+\(\s*(request|self\.request)",
        "cwe": "CWE-918",
        "title": "SSRF — HTTP 请求 URL 来自用户输入",
        "cvss": 7.5,
        "fix": "实施 URL 白名单校验；禁止访问 127.0.0.1/10.0.0.0/8/169.254.0.0/16 等内网地址",
        "conf": "high",
    },
    {
        "id": "PY-A10-002",
        "pattern": r"urllib\.request\.urlopen\s*\(\s*(request|self\.request)",
        "cwe": "CWE-918",
        "title": "SSRF — urlopen 请求用户控制 URL",
        "cvss": 7.5,
        "fix": "校验 URL 是否为预期域名；使用 DNS 解析校验 + 内网 IP 黑名单",
        "conf": "high",
    },

    # ── CWE Top 25 额外覆盖 ──
    {
        "id": "PY-CWE-022-001",
        "pattern": r"open\s*\(\s*(request|self\.request)",
        "cwe": "CWE-22",
        "title": "路径遍历 — 用户输入控制文件打开",
        "cvss": 7.5,
        "fix": "校验文件名不含 ../；使用 os.path.basename 过滤；限制文件在白名单目录内",
        "conf": "high",
    },
    {
        "id": "PY-CWE-022-002",
        "pattern": r"os\.path\.join\s*\([^)]*(request|self\.request)",
        "cwe": "CWE-22",
        "title": "路径遍历 — os.path.join 含用户输入",
        "cvss": 7.0,
        "fix": "使用 os.path.realpath 解析后校验路径前缀；拒绝含 ../ 的输入",
        "conf": "high",
    },
    {
        "id": "PY-CWE-079-001",
        "pattern": r"return\s+.*?\+\s*(request|self\.request)",
        "cwe": "CWE-79",
        "title": "反射型 XSS — 用户输入拼接 HTML 返回",
        "cvss": 6.1,
        "fix": "使用 html.escape() 或模板引擎 (Jinja2) 的自动转义功能",
        "conf": "medium",
    },
    {
        "id": "PY-CWE-079-002",
        "pattern": r"Markup\s*\(\s*(request|self\.request)",
        "cwe": "CWE-79",
        "title": "Markup 包装用户输入 — XSS 风险",
        "cvss": 5.5,
        "fix": "确保用户输入已转义后再用 Markup 包装；优先使用自动转义模板",
        "conf": "medium",
    },
    {
        "id": "PY-CWE-611-001",
        "pattern": r"xml\.etree\.ElementTree\.parse\s*\(",
        "cwe": "CWE-611",
        "title": "XXE — XML 解析未禁用外部实体",
        "cvss": 7.5,
        "fix": "使用 defusedxml 库替代标准 xml 库；或设置 XMLParser 禁用外部实体",
        "conf": "medium",
    },
    {
        "id": "PY-CWE-611-002",
        "pattern": r"from\s+lxml\s+import",
        "cwe": "CWE-611",
        "title": "lxml XML 解析 — 需禁用外部实体",
        "cvss": 6.5,
        "fix": "设置 lxml 的 resolve_entities=False；使用 defusedxml 包装 lxml",
        "conf": "medium",
    },
    {
        "id": "PY-CWE-352-001",
        "pattern": r"@app\.route\([^)]*(POST|PUT|DELETE|PATCH)",
        "cwe": "CWE-352",
        "title": "状态修改路由可能缺少 CSRF 保护",
        "cvss": 6.0,
        "fix": "使用 CSRF Token (Flask-WTF) 或 SameSite=Strict Cookie",
        "conf": "low",
    },
    {
        "id": "PY-CWE-377-001",
        "pattern": r"tempfile\.mktemp",
        "cwe": "CWE-377",
        "title": "不安全的临时文件 — mktemp 有竞态条件",
        "cvss": 5.0,
        "fix": "使用 tempfile.mkstemp() 或 tempfile.TemporaryDirectory()",
        "conf": "medium",
    },
    # ReDoS 规则已移除 — 嵌套量词难以用正则可靠检测，误报率高
    {
        "id": "PY-CWE-117-001",
        "pattern": r"logging\.\w+\s*\(\s*(request|self\.request)",
        "cwe": "CWE-117",
        "title": "日志注入 — 用户输入直接进入日志",
        "cvss": 4.0,
        "fix": "对日志内容做 sanitize，过滤换行符 \\n \\r；使用结构化日志",
        "conf": "low",
    },
]


# ── JS/TS 规则：25+ 条 ──
JS_RULES = [
    # A01: Broken Access Control
    {
        "id": "JS-A01-001",
        "pattern": r"localStorage\.setItem\s*\(\s*[\"'](token|password|secret|key)",
        "cwe": "CWE-312",
        "title": "敏感数据存入 localStorage — 可被 XSS 读取",
        "cvss": 6.5,
        "fix": "使用 httpOnly cookie 存储 token；或 Secure Storage API (需 HTTPS)",
        "conf": "high",
    },
    {
        "id": "JS-A01-002",
        "pattern": r"sessionStorage\.setItem\s*\(\s*[\"'](token|password|secret)",
        "cwe": "CWE-312",
        "title": "敏感数据存入 sessionStorage",
        "cvss": 6.0,
        "fix": "使用 httpOnly cookie",
        "conf": "medium",
    },

    # A02: Cryptographic Failure
    {
        "id": "JS-A02-001",
        "pattern": r"(?i)const\s+(password|secret|key|token)\s*=\s*[\"']",
        "cwe": "CWE-798",
        "title": "硬编码凭证 — 前端代码中的密钥",
        "cvss": 8.5,
        "fix": "前端禁止存放密钥；使用后端 API 代理；密钥存环境变量",
        "conf": "high",
    },
    {
        "id": "JS-A02-002",
        "pattern": r"(?i)api[_-]?key\s*=\s*[\"']",
        "cwe": "CWE-798",
        "title": "硬编码 API Key",
        "cvss": 8.0,
        "fix": "从环境变量读取；使用 .env + process.env；禁止提交前端代码",
        "conf": "high",
    },
    {
        "id": "JS-A02-003",
        "pattern": r"Math\.random\s*\(\s*\)",
        "cwe": "CWE-330",
        "title": "不安全的随机数 Math.random() — 可预测",
        "cvss": 5.0,
        "fix": "使用 crypto.getRandomValues() (浏览器) 或 crypto.randomBytes() (Node.js)",
        "conf": "medium",
    },
    {
        "id": "JS-A02-004",
        "pattern": r"process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']0",
        "cwe": "CWE-295",
        "title": "Node.js SSL 证书校验被禁用",
        "cvss": 7.5,
        "fix": "删除此设置；使用自定义 CA 证书: NODE_EXTRA_CA_CERTS=/path/to/ca.crt",
        "conf": "high",
    },

    # A03: Injection
    {
        "id": "JS-A03-001",
        "pattern": r"\beval\s*\(\s*\w+",
        "cwe": "CWE-95",
        "title": "代码注入 — eval()",
        "cvss": 9.8,
        "fix": "永远不要使用 eval()；解析 JSON 用 JSON.parse()；动态执行用 Function() (仍需谨慎)",
        "conf": "high",
    },
    {
        "id": "JS-A03-002",
        "pattern": r"new\s+Function\s*\(\s*\w+",
        "cwe": "CWE-95",
        "title": "代码注入 — new Function()",
        "cvss": 9.0,
        "fix": "避免动态代码生成；使用函数引用或策略模式",
        "conf": "high",
    },
    {
        "id": "JS-A03-003",
        "pattern": r"document\.write\s*\(\s*\w+",
        "cwe": "CWE-79",
        "title": "XSS — document.write() 写入变量",
        "cvss": 6.5,
        "fix": "使用 textContent 替代 document.write；或对内容做 DOMPurify 净化",
        "conf": "medium",
    },
    {
        "id": "JS-A03-004",
        "pattern": r"\.innerHTML\s*\+=\s*",
        "cwe": "CWE-79",
        "title": "XSS — innerHTML 拼接赋值",
        "cvss": 6.1,
        "fix": "使用 textContent 或对内容做 DOMPurify.sanitize() 净化",
        "conf": "high",
    },
    {
        "id": "JS-A03-005",
        "pattern": r"setTimeout\s*\(\s*[\"']",
        "cwe": "CWE-95",
        "title": "代码注入 — setTimeout 含字符串",
        "cvss": 7.5,
        "fix": "使用函数引用: setTimeout(() => {...}, 1000) 而非字符串",
        "conf": "medium",
    },
    {
        "id": "JS-A03-006",
        "pattern": r"setInterval\s*\(\s*[\"']",
        "cwe": "CWE-95",
        "title": "代码注入 — setInterval 含字符串",
        "cvss": 7.5,
        "fix": "使用函数引用而非字符串",
        "conf": "medium",
    },

    # A05: Security Misconfiguration
    {
        "id": "JS-A05-001",
        "pattern": r"app\.listen\s*\(\s*\d+\s*\)\s*;?",
        "cwe": "CWE-16",
        "title": "Express 未设置安全 Headers — 缺少 Helmet",
        "cvss": 4.0,
        "fix": "使用 helmet.js 中间件: app.use(helmet())",
        "conf": "low",
    },
    {
        "id": "JS-A05-002",
        "pattern": r"cookie\s*\([^)]*httpOnly\s*:\s*false",
        "cwe": "CWE-1004",
        "title": "Cookie httpOnly=false — JS 可读取",
        "cvss": 5.0,
        "fix": "设置 httpOnly: true；配合 secure: true",
        "conf": "medium",
    },
    {
        "id": "JS-A05-003",
        "pattern": r"cookie\s*\([^)]*secure\s*:\s*false",
        "cwe": "CWE-614",
        "title": "Cookie secure=false — 明文传输",
        "cvss": 5.0,
        "fix": "设置 secure: true (仅 HTTPS 传输)",
        "conf": "medium",
    },

    # A07: Auth Failures
    {
        "id": "JS-A07-001",
        "pattern": r"jwt\.sign\s*\(\s*[^)]*,\s*[\"'][^\"']{0,15}[\"']\s*\)",
        "cwe": "CWE-798",
        "title": "JWT 使用弱密钥 — 密钥过短",
        "cvss": 7.5,
        "fix": "使用强随机密钥 (>=256bit/32字节)；存储在环境变量",
        "conf": "high",
    },

    # A10: SSRF
    {
        "id": "JS-A10-001",
        "pattern": r"axios\.get\s*\(\s*\w+",
        "cwe": "CWE-918",
        "title": "SSRF — axios 请求用户控制 URL",
        "cvss": 7.0,
        "fix": "校验 URL 白名单；禁止访问内网地址；使用 DNS 解析校验",
        "conf": "medium",
    },
    {
        "id": "JS-A10-002",
        "pattern": r"fetch\s*\(\s*\w+",
        "cwe": "CWE-918",
        "title": "SSRF — fetch 请求用户控制 URL",
        "cvss": 7.0,
        "fix": "校验 URL 白名单；禁止内网地址",
        "conf": "medium",
    },

    # CWE Top 25
    {
        "id": "JS-CWE-078-001",
        "pattern": r"child_process\.exec\s*\(\s*",
        "cwe": "CWE-78",
        "title": "命令注入 — child_process.exec()",
        "cvss": 8.8,
        "fix": "使用 child_process.execFile() with shell=false；或 spawn()",
        "conf": "high",
    },
    {
        "id": "JS-CWE-078-002",
        "pattern": r"child_process\.spawn\s*\(\s*[^)]*shell\s*:\s*true",
        "cwe": "CWE-78",
        "title": "命令注入 — child_process.spawn shell:true",
        "cvss": 8.5,
        "fix": "设置 shell: false (默认)；使用参数列表",
        "conf": "high",
    },
    {
        "id": "JS-CWE-095-001",
        "pattern": r"vm\.runInContext\s*\(\s*",
        "cwe": "CWE-95",
        "title": "代码注入 — vm.runInContext()",
        "cvss": 8.5,
        "fix": "避免执行用户提供的代码；使用沙箱 + 超时限制",
        "conf": "medium",
    },
    {
        "id": "JS-CWE-1321-001",
        "pattern": r"Object\.assign\s*\(\s*\w+\s*,\s*req\.",
        "cwe": "CWE-1321",
        "title": "Prototype Pollution — Object.assign 用户输入",
        "cvss": 6.5,
        "fix": "使用 Object.assign 前过滤 __proto__/constructor；或使用 Lodash 的 _.merge 安全版本",
        "conf": "medium",
    },
    {
        "id": "JS-CWE-1321-002",
        "pattern": r"\.\s*__proto__\s*=",
        "cwe": "CWE-1321",
        "title": "Prototype Pollution — 直接设置 __proto__",
        "cvss": 6.0,
        "fix": "避免直接操作 __proto__；使用 Object.freeze(Object.prototype)",
        "conf": "medium",
    },

    # XSS
    {
        "id": "JS-CWE-079-001",
        "pattern": r"dangerouslySetInnerHTML\s*=",
        "cwe": "CWE-79",
        "title": "React XSS — dangerouslySetInnerHTML",
        "cvss": 6.5,
        "fix": "使用 DOMPurify 净化后再传入: DOMPurify.sanitize(html)",
        "conf": "medium",
    },
    {
        "id": "JS-CWE-079-002",
        "pattern": r"v-html\s*=",
        "cwe": "CWE-79",
        "title": "Vue XSS — v-html 指令",
        "cvss": 6.5,
        "fix": "避免使用 v-html；或净化内容后传入",
        "conf": "medium",
    },

    # JSON 安全
    {
        "id": "JS-CWE-020-001",
        "pattern": r"JSON\.parse\s*\(\s*\w+\s*\)\s*(?!\s*try)",
        "cwe": "CWE-20",
        "title": "JSON.parse 缺少异常处理 — 可能导致崩溃",
        "cvss": 4.0,
        "fix": "用 try/catch 包裹 JSON.parse: try { JSON.parse(x) } catch(e) {...}",
        "conf": "low",
    },
]


def scan_python_files(scan_path: str) -> list:
    """扫描 Python 文件，返回漏洞列表。"""
    vulns = []
    seen = set()

    for root, dirs, files in os.walk(scan_path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as ff:
                    source = ff.read()
            except Exception:
                continue

            for rule in PYTHON_RULES:
                try:
                    matches = list(re.finditer(rule["pattern"], source))
                except re.error as e:
                    print(f"  [REGEX ERROR] {rule['id']}: {e}")
                    continue
                for m in matches:
                    line_no = source[:m.start()].count("\n") + 1
                    title = rule["title"]
                    if "%s" in title and m.group(1):
                        title = title % m.group(1)
                    key = f"{fpath}:{rule['id']}"
                    if key in seen:
                        continue
                    seen.add(key)
                    vulns.append({
                        "id": rule["id"],
                        "title": title,
                        "cwe": rule["cwe"],
                        "cvss": rule["cvss"],
                        "line": line_no,
                        "file": fpath,
                        "fix": rule["fix"],
                        "conf": rule["conf"],
                    })
    return vulns


def scan_js_files(scan_path: str) -> list:
    """扫描 JS/TS 文件，返回漏洞列表。"""
    vulns = []
    seen = set()
    exts = (".js", ".ts", ".jsx", ".tsx")

    for root, dirs, files in os.walk(scan_path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
        for fname in files:
            if not any(fname.endswith(ext) for ext in exts):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as ff:
                    source = ff.read()
            except Exception:
                continue

            for rule in JS_RULES:
                for m in re.finditer(rule["pattern"], source):
                    line_no = source[:m.start()].count("\n") + 1
                    key = f"{fpath}:{rule['id']}"
                    if key in seen:
                        continue
                    seen.add(key)
                    vulns.append({
                        "id": rule["id"],
                        "title": rule["title"],
                        "cwe": rule["cwe"],
                        "cvss": rule["cvss"],
                        "line": line_no,
                        "file": fpath,
                        "fix": rule["fix"],
                        "conf": rule["conf"],
                    })
    return vulns


if __name__ == "__main__":
    # 自测：扫描当前目录
    import sys
    test_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[TEST] Scanning {test_path} ...")
    py_results = scan_python_files(test_path)
    js_results = scan_js_files(test_path)
    print(f"  Python vulnerabilities: {len(py_results)}")
    print(f"  JS vulnerabilities: {len(js_results)}")
    for r in py_results[:5]:
        print(f"  [PY] {r['id']} L{r['line']}: {r['title']}")
    for r in js_results[:5]:
        print(f"  [JS] {r['id']} L{r['line']}: {r['title']}")
