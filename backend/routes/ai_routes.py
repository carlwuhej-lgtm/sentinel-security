import logging
logger = logging.getLogger(__name__)
import json
import sqlite3
import os
import re
from datetime import datetime
from flask import Blueprint, request, jsonify, g, current_app, Response, stream_with_context

ai_bp = Blueprint('ai', __name__)

# Read AI config from config.py (which loads .env)
from config import AI_CONFIG as _cfg, DATABASE_PATH, _AI_PROVIDER_ENV, _AI_HAS_KEY
AI_API_KEY = _cfg['api_key']
AI_API_BASE = _cfg['api_base']
AI_MODEL = _cfg['model']
AI_PROVIDER = os.environ.get('SENTINEL_AI_PROVIDER', 'openai')
AI_ENABLED = _cfg['enabled']

# 多供应商支持：DB 优先，env 兜底（保证本地 Ollama 始终可用）
from services.crypto_service import encrypt, decrypt

def get_db():
    if '_db' not in g:
        db_path = os.environ.get('SENTINEL_DB_PATH', DATABASE_PATH)
        g._db = sqlite3.connect(db_path)
        g._db.row_factory = sqlite3.Row
    return g._db

from routes.auth import login_required, admin_required


# ---------------------------------------------------------------------------
# 多供应商配置（DB 优先，env 兜底；本地 Ollama 始终保留）
# ---------------------------------------------------------------------------

def _ensure_ai_providers(db):
    """确保 ai_providers 表存在，首次运行用当前 env 配置种子一条 Ollama/本地供应商。"""
    db.execute(
        '''CREATE TABLE IF NOT EXISTS ai_providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            provider_type TEXT NOT NULL DEFAULT 'openai',
            api_base TEXT NOT NULL,
            model TEXT NOT NULL,
            api_key TEXT DEFAULT '',
            is_active INTEGER DEFAULT 0,
            created_at TEXT DEFAULT '',
            updated_at TEXT DEFAULT ''
        )'''
    )
    db.commit()
    row = db.execute('SELECT COUNT(*) AS c FROM ai_providers').fetchone()
    if row['c'] == 0:
        now = datetime.now().isoformat()
        ptype = 'ollama' if _AI_PROVIDER_ENV in ('ollama', 'local') else 'openai'
        db.execute(
            '''INSERT INTO ai_providers (name, provider_type, api_base, model, api_key, is_active, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 1, ?, ?)''',
            ('Ollama 本地模型', ptype, AI_API_BASE, AI_MODEL, '', now, now)
        )
        db.commit()


def get_active_ai_config() -> dict:
    """返回当前激活的 AI 供应商配置。

    - 优先读 DB 中 is_active=1 的记录（运行时切换，无需重启）；
    - DB 无记录/未激活时回退到 env 配置，保证本地 Ollama 始终可用。
    """
    try:
        db = get_db()
        _ensure_ai_providers(db)
        row = db.execute(
            'SELECT provider_type, api_base, model, api_key FROM ai_providers WHERE is_active=1 ORDER BY id LIMIT 1'
        ).fetchone()
        if row:
            raw_key = row['api_key'] or ''
            key = decrypt(raw_key) if raw_key.startswith('aes256:') else raw_key
            return {
                'enabled': bool(row['api_base'] and row['model']),
                'provider': row['provider_type'],
                'api_base': row['api_base'],
                'model': row['model'],
                'api_key': key,
            }
    except Exception:
        pass
    # 兜底：env 配置
    is_local = _AI_PROVIDER_ENV in ('ollama', 'local')
    return {
        'enabled': AI_ENABLED,
        'provider': 'ollama' if is_local else AI_PROVIDER,
        'api_base': AI_API_BASE,
        'model': AI_MODEL,
        'api_key': '' if is_local else AI_API_KEY,
    }


# ---------------------------------------------------------------------------
# AI helper
# ---------------------------------------------------------------------------

def call_ai(system_prompt: str, user_prompt: str, stream: bool = False, timeout: int = 120) -> str:
    """Call AI API (OpenAI / Ollama / compatible).

    自动读取当前激活的供应商配置（DB 优先），支持运行时切换、无需重启。
    """
    cfg = get_active_ai_config()
    if not cfg['enabled']:
        raise ValueError("AI not configured")

    def _clean_response(text: str) -> str:
        """Strip ＜think＞...＜/think＞ tags from qwen3/deepseek thinking models."""
        cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
        return cleaned.strip()

    try:
        import urllib.request
        data = json.dumps({
            "model": cfg['model'],
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 4096,
            "stream": False
        }).encode()
        url = f"{cfg['api_base']}/chat/completions"
        headers = {"Content-Type": "application/json"}
        # Ollama doesn't need auth; only add Authorization for non-Ollama providers
        if cfg['provider'] != 'ollama':
            headers["Authorization"] = f"Bearer {cfg['api_key']}"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        resp = urllib.request.urlopen(req, timeout=timeout)
        result = json.loads(resp.read())
        content = result["choices"][0]["message"]["content"]
        return _clean_response(content)
    except Exception as e:
        return f"[AI Error] {str(e)}"


def check_ai_health() -> bool:
    """Quick health check — returns True if active AI service is reachable within 3s."""
    cfg = get_active_ai_config()
    if not cfg['enabled']:
        return False
    try:
        import urllib.request
        if cfg['provider'] == 'ollama':
            # Ollama /api/tags 在根路径（/v1 仅用于 OpenAI 兼容接口）
            root = cfg['api_base'].replace('/v1', '').rstrip('/')
            url = f"{root}/api/tags"
        else:
            url = cfg['api_base']
        req = urllib.request.Request(url, method="GET")
        urllib.request.urlopen(req, timeout=3)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Simulated (fallback) analysis generators
# ---------------------------------------------------------------------------

CWE_ANALYSIS_MAP = {
    # === OWASP Top 10: 注入类 ===
    "89": {
        "name": "SQL 注入",
        "category": "注入攻击",
        "owasp_rank": "A03:2021",
        "attack_path": "攻击者通过用户输入字段注入恶意 SQL 语句，绕过身份验证、提取敏感数据或执行数据库管理操作。",
        "exploitation": "低 — SQL 注入漏洞易于发现和利用，自动化工具（如 SQLMap）可在几分钟内完成利用。",
        "business_impact": "高 — 可能导致整个数据库泄露、数据篡改、身份绕过，严重损害业务信誉和合规性。",
        "fix_approaches": [
            {"title": "使用参数化查询", "language": "python",
             "before": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
             "after": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))"},
            {"title": "使用 ORM 框架", "language": "python",
             "before": "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
             "after": "User.query.filter_by(name=name).all()"},
            {"title": "输入验证与白名单", "language": "python",
             "before": "order = request.args.get('order')\ncursor.execute(f\"SELECT * FROM items ORDER BY {order}\")",
             "after": "ALLOWED = {'id','name','created_at'}\norder = request.args.get('order','id')\ncursor.execute(\"SELECT * FROM items ORDER BY ?\" if order in ALLOWED else \"SELECT * FROM items\", (order,))"}
        ],
        "verification": "1. 使用 SQLMap 验证注入点已消除\n2. 审查所有数据库交互代码，确认使用参数化查询\n3. 部署 WAF 规则作为纵深防御\n4. 定期进行渗透测试",
        "root_cause": "应用程序直接将用户输入拼接进 SQL 语句，未对输入进行验证和参数化处理。",
        "mitigation": "部署 WAF 规则拦截常见 SQL 注入模式；限制数据库用户权限至最低必要范围；实施输入长度限制。",
    },
    "78": {
        "name": "命令注入",
        "category": "注入攻击",
        "owasp_rank": "A03:2021",
        "attack_path": "攻击者在系统命令参数中注入恶意命令，通过 shell 执行任意系统命令，获取服务器控制权。",
        "exploitation": "低 — 常见命令分隔符（; | && ||）即可构造 payload，利用门槛极低。",
        "business_impact": "高 — 可导致服务器完全被控制、数据被盗取、内网横向移动，是最危险的漏洞之一。",
        "fix_approaches": [
            {"title": "使用 subprocess.run 参数化", "language": "python",
             "before": "os.system(f\"ping {user_input}\")",
             "after": "subprocess.run([\"ping\", \"-c\", \"4\", user_input], shell=False)"},
            {"title": "输入白名单校验", "language": "python",
             "before": "os.popen(f\"convert {filename} output.png\")",
             "after": "import re\nif not re.match(r'^[a-zA-Z0-9_.-]+$', filename):\n    raise ValueError('Invalid filename')\nos.popen([\"convert\", filename, \"output.png\"])"},
        ],
        "verification": "1. 测试命令注入 payload 是否被拦截\n2. 确认所有系统调用使用参数化而非字符串拼接\n3. 检查 shell=False 配置是否正确",
        "root_cause": "用户输入未经校验被直接拼接到系统命令字符串中执行。",
        "mitigation": "禁用 shell=True；实施严格的白名单校验；限制应用运行账户的权限。",
    },
    # === OWASP Top 10: XSS ===
    "79": {
        "name": "XSS（跨站脚本攻击）",
        "category": "注入攻击",
        "owasp_rank": "A03:2021",
        "attack_path": "攻击者在网页输入中注入恶意 JavaScript 脚本，当其他用户浏览该页面时脚本执行，窃取 Cookie、会话令牌或执行钓鱼操作。",
        "exploitation": "低 — XSS 漏洞易于构造攻击 payload，反射型 XSS 可通过 URL 直接传播。",
        "business_impact": "中高 — 可导致用户会话劫持、钓鱼攻击、数据泄露，影响用户信任和平台安全声誉。",
        "fix_approaches": [
            {"title": "输出编码（HTML 转义）", "language": "python",
             "before": "return f'<div>Hello, {username}!</div>'",
             "after": "from markupsafe import escape\nreturn f'<div>Hello, {escape(username)}!</div>'"},
            {"title": "CSP 安全策略头", "language": "nginx",
             "before": "# 无 CSP 配置",
             "after": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'\" always;"},
            {"title": "模板引擎自动转义", "language": "html",
             "before": "<div>{{ user_input | safe }}</div>",
             "after": "<div>{{ user_input }}</div>"},
        ],
        "verification": "1. 在所有输入点注入 XSS payload 验证转义\n2. 检查 HTTP 响应头是否包含 CSP 策略\n3. 使用浏览器 DevTools 确认脚本未执行",
        "root_cause": "应用程序未对用户输入进行输出编码，直接将原始数据渲染到 HTML 中。",
        "mitigation": "部署 CSP 安全策略；启用 HttpOnly + Secure Cookie；前端使用 DOMPurify 净化。",
    },
    # === SSRF ===
    "918": {
        "name": "SSRF（服务端请求伪造）",
        "category": "访问控制",
        "owasp_rank": "A10:2021",
        "attack_path": "攻击者操控服务器发起对内部系统的请求，访问云元数据服务、内网数据库和管理接口，绕过网络边界防护。",
        "exploitation": "中 — 需要了解内网架构和可用端点，但一旦成功可造成严重破坏。",
        "business_impact": "高 — 可导致云凭证泄露、内网服务探测、敏感数据外泄，严重危害基础设施安全。",
        "fix_approaches": [
            {"title": "URL 白名单校验", "language": "python",
             "before": "requests.get(user_url)",
             "after": "import ipaddress, socket\nfrom urllib.parse import urlparse\nparsed = urlparse(user_url)\nif parsed.hostname in ['localhost','127.0.0.1']:\n    raise ValueError('Blocked')\nip = socket.gethostbyname(parsed.hostname)\nif ipaddress.ip_address(ip).is_private:\n    raise ValueError('Private IP blocked')\nrequests.get(user_url, timeout=5)"},
            {"title": "禁用重定向跟随", "language": "python",
             "before": "requests.get(url)",
             "after": "requests.get(url, allow_redirects=False, timeout=5)"},
        ],
        "verification": "1. 测试访问内网地址是否被拦截\n2. 确认 169.254.169.254（云元数据）不可达\n3. 检查 URL 解析和重定向安全",
        "root_cause": "服务端请求的 URL 由用户控制且未做目标地址校验，可指向任意地址。",
        "mitigation": "严格限制可访问的协议（仅 HTTP/HTTPS）和 IP 范围；禁用自动重定向；使用独立网络隔离的出站代理。",
    },
    # === XXE ===
    "611": {
        "name": "XXE（XML 外部实体注入）",
        "category": "注入攻击",
        "owasp_rank": "A03:2021",
        "attack_path": "攻击者在 XML 输入中定义外部实体引用本地文件或外网资源，读取敏感文件、探测内网端口或发起 DoS 攻击。",
        "exploitation": "低 — 只需构造恶意 XML 即可利用，无需特殊工具。",
        "business_impact": "高 — 可导致源码泄露、内网探测、SSRF，影响系统机密性和完整性。",
        "fix_approaches": [
            {"title": "禁用外部实体解析", "language": "python",
             "before": "from lxml import etree\netree.parse(xml_data)",
             "after": "from defusedxml import lxml as safe_lxml\nsafe_lxml.parse(xml_data)"},
            {"title": "XML 解析器安全配置", "language": "java",
             "before": "DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();",
             "after": "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\ndbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);"},
        ],
        "verification": "1. 使用 XXE payload 测试是否可读取文件\n2. 确认 DOCTYPE 和外部实体已禁用\n3. 验证使用 defusedxml 或等效安全库",
        "root_cause": "XML 解析器默认启用了外部实体和 DTD 处理，攻击者利用此特性注入恶意实体声明。",
        "mitigation": "使用 JSON 替代 XML；如需 XML 则使用 defusedxml 等安全库；在 WAF 层过滤 XXE payload。",
    },
    # === 反序列化 ===
    "502": {
        "name": "不安全反序列化",
        "category": "软件与数据完整性故障",
        "owasp_rank": "A08:2021",
        "attack_path": "攻击者构造恶意序列化数据，利用反序列化过程中的类型混淆和 gadget chain 实现远程代码执行。",
        "exploitation": "中高 — 需要理解目标应用程序的类结构和 gadget chain，但已有成熟工具（如 ysoserial）辅助。",
        "business_impact": "高 — 可实现远程代码执行、权限提升，危害程度等同于完全控制服务器。",
        "fix_approaches": [
            {"title": "使用安全序列化格式", "language": "python",
             "before": "data = pickle.loads(user_data)",
             "after": "data = json.loads(user_data)"},
            {"title": "白名单类校验", "language": "java",
             "before": "ObjectInputStream ois = new ObjectInputStream(input);\nObject obj = ois.readObject();",
             "after": "ValidatingObjectInputStream ois = new ValidatingObjectInputStream(input);\nois.accept(AllowedClass1.class, AllowedClass2.class);\nObject obj = ois.readObject();"},
        ],
        "verification": "1. 确认不再使用 pickle/ObjectInputStream 反序列化不可信数据\n2. 验证 JSON 替代方案的兼容性\n3. 渗透测试验证 gadget chain 不可用",
        "root_cause": "应用程序对不可信数据进行反序列化，且未限制可实例化的类范围。",
        "mitigation": "避免反序列化不可信数据；如果必要，使用 HMAC 签名验证数据完整性 + 类白名单。",
    },
    # === 路径遍历 ===
    "22": {
        "name": "路径遍历",
        "category": "访问控制",
        "owasp_rank": "A01:2021",
        "attack_path": "攻击者利用文件路径中的 ../ 序列突破预期目录限制，读取或覆盖系统任意文件。",
        "exploitation": "低 — 仅需在文件名参数中插入 ../ 即可，无需工具。",
        "business_impact": "高 — 可泄露系统配置、源码、数据库文件，是信息收集阶段的高价值目标。",
        "fix_approaches": [
            {"title": "路径规范化和校验", "language": "python",
             "before": "with open(f'/app/uploads/{filename}') as f:\n    return f.read()",
             "after": "import os\nsafe_path = os.path.realpath(os.path.join('/app/uploads/', filename))\nif not safe_path.startswith('/app/uploads/'):\n    raise ValueError('Path traversal detected')\nwith open(safe_path) as f:\n    return f.read()"},
            {"title": "使用文件 ID 而非路径", "language": "python",
             "before": "file_path = request.args.get('path')\nreturn send_file(file_path)",
             "after": "file_id = int(request.args.get('id'))\nrow = db.execute('SELECT path FROM files WHERE id=?', (file_id,)).fetchone()\nreturn send_file(row['path'])"},
        ],
        "verification": "1. 测试 ../../etc/passwd 是否可读取\n2. 确认 realpath 校验在文件操作前执行\n3. 验证 chroot / 沙箱隔离有效",
        "root_cause": "文件名参数直接拼接到文件路径中，未校验最终路径是否在预期目录内。",
        "mitigation": "用文件 ID 替代路径参数；使用 os.path.realpath 校验；chroot 或容器隔离文件系统。",
    },
    # === 硬编码凭证 ===
    "798": {
        "name": "硬编码凭证",
        "category": "身份认证与授权",
        "owasp_rank": "A07:2021",
        "attack_path": "源代码中包含明文的 API Key、密码或数据库连接字符串，攻击者通过代码泄露、仓库公开或逆向工程获取这些凭证。",
        "exploitation": "低 — 一旦获取代码即可直接使用硬编码凭证，无需任何技术门槛。",
        "business_impact": "高 — 硬编码凭证泄露可导致服务接管、数据泄露、供应链攻击，且难以追踪和撤销。",
        "fix_approaches": [
            {"title": "环境变量存储", "language": "python",
             "before": "DB_PASSWORD = 'mysecret123'\nconn = connect(password=DB_PASSWORD)",
             "after": "import os\nconn = connect(password=os.environ['DB_PASSWORD'])"},
            {"title": "密钥管理服务（KMS）", "language": "yaml",
             "before": "api_key: sk-abc123def",
             "after": "api_key: ${VAULT_SECRET_API_KEY}"},
        ],
        "verification": "1. 使用 grep/gitleaks 确认代码中无硬编码凭证\n2. 验证 Vault/KMS 集成工作正常\n3. 测试密钥轮换流程",
        "root_cause": "开发人员为便利将凭证写入源码，缺乏安全编码意识和凭证管理流程。",
        "mitigation": "立即撤销泄露凭证；部署 Gitleaks 等扫描工具；建立凭证管理规范和密钥轮换策略。",
    },
    # === 证书验证 ===
    "295": {
        "name": "TLS 证书验证不当",
        "category": "加密失败",
        "owasp_rank": "A02:2021",
        "attack_path": "客户端关闭 SSL/TLS 证书验证，攻击者通过中间人攻击拦截并篡改通信内容。",
        "exploitation": "中 — 需要处于网络中间位置，但公共 Wi-Fi 等场景下非常可行。",
        "business_impact": "中高 — 可导致敏感数据（密码、Token、支付信息）在传输中被窃取。",
        "fix_approaches": [
            {"title": "启用证书验证", "language": "python",
             "before": "requests.get(url, verify=False)",
             "after": "requests.get(url, verify=True)"},
            {"title": "自定义 CA 证书", "language": "python",
             "before": "requests.post(url, verify=False)",
             "after": "requests.post(url, verify='/etc/ssl/certs/custom-ca.pem')"},
        ],
        "verification": "1. 搜索代码中的 verify=False\n2. 使用 mitmproxy 测试中间人攻击可行性\n3. 确认生产环境使用有效证书",
        "root_cause": "为绕过证书错误，开发阶段设置了 verify=False 但未在上线前移除。",
        "mitigation": "逐个审查所有 HTTP 客户端调用；部署网络层 TLS 拦截检测。",
    },
    # === 敏感信息泄露 ===
    "200": {
        "name": "敏感信息泄露",
        "category": "加密失败",
        "owasp_rank": "A04:2021",
        "attack_path": "应用在错误响应、调试页面或日志中暴露了内部实现细节（堆栈跟踪、数据库结构、API 密钥），攻击者借此了解系统弱点。",
        "exploitation": "低 — 无需主动利用，信息直接呈现在响应中。",
        "business_impact": "中 — 为攻击者提供系统内部信息，显著降低后续攻击的难度。",
        "fix_approaches": [
            {"title": "生产环境禁用详细错误", "language": "python",
             "before": "app.run(debug=True)",
             "after": "app.run(debug=False)\n# Flask: app.config['PROPAGATE_EXCEPTIONS'] = False"},
            {"title": "统一错误处理", "language": "python",
             "before": "@app.errorhandler(Exception)\ndef handle_error(e):\n    return str(e), 500",
             "after": "@app.errorhandler(Exception)\ndef handle_error(e):\n    logger.error(f'Error: {e}', exc_info=True)\n    return jsonify({'error': 'Internal server error'}), 500"},
        ],
        "verification": "1. 触发错误查看响应是否包含堆栈信息\n2. 确认 debug=False\n3. 检查日志中是否有敏感数据",
        "root_cause": "开发和调试配置被遗留到生产环境，或错误处理未区分内外信息。",
        "mitigation": "建立「默认安全」的部署配置；敏感信息写入服务端日志而非 HTTP 响应。",
    },
    # === 原型污染 ===
    "915": {
        "name": "原型污染",
        "category": "注入攻击",
        "owasp_rank": "A08:2021",
        "attack_path": "攻击者通过设置 __proto__ 或 constructor.prototype 属性，污染 JavaScript 对象原型链，改变所有对象的行为。",
        "exploitation": "中 — 需要理解原型链机制和应用程序的对象合并逻辑。",
        "business_impact": "高 — 可导致权限绕过、XSS、拒绝服务，影响范围覆盖所有使用该对象的代码。",
        "fix_approaches": [
            {"title": "安全合并对象", "language": "javascript",
             "before": "Object.assign(config, userInput)",
             "after": "const safeMerge = (target, source) => {\n  for (const key of Object.keys(source)) {\n    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;\n    target[key] = source[key];\n  }\n  return target;\n};"},
            {"title": "使用 Object.create(null)", "language": "javascript",
             "before": "const cache = {}",
             "after": "const cache = Object.create(null)"},
        ],
        "verification": "1. 注入 __proto__.isAdmin=true 测试权限提升\n2. 审计所有 Object.assign / 扩展运算符使用\n3. 使用 npm audit 检测原型污染相关 CVE",
        "root_cause": "不可信数据被合并到普通对象中，未过滤原型链敏感属性。",
        "mitigation": "使用 Object.create(null)；JSON.parse 替代 eval；安装原型污染防护中间件。",
    },
    # === CSRF ===
    "352": {
        "name": "CSRF（跨站请求伪造）",
        "category": "访问控制",
        "owasp_rank": "A01:2021",
        "attack_path": "攻击者诱导已登录用户在不知情的情况下向目标网站发送恶意请求，以用户身份执行非预期操作（转账、修改密码等）。",
        "exploitation": "中 — 需要构造恶意页面并诱导用户访问，但 payload 构造简单。",
        "business_impact": "中 — 可导致用户账户被操控、资金损失，影响平台可信度。",
        "fix_approaches": [
            {"title": "CSRF Token", "language": "python",
             "before": "@app.route('/transfer', methods=['POST'])\ndef transfer():\n    amount = request.form['amount']",
             "after": "from flask_wtf.csrf import CSRFProtect\ncsrf = CSRFProtect(app)\n@app.route('/transfer', methods=['POST'])\ndef transfer():\n    amount = request.form['amount']  # CSRF token auto-validated"},
            {"title": "SameSite Cookie", "language": "python",
             "before": "response.set_cookie('session', token)",
             "after": "response.set_cookie('session', token, samesite='Strict', secure=True, httponly=True)"},
        ],
        "verification": "1. 确认所有状态变更操作需要 CSRF Token\n2. 验证跨域请求被正确拦截\n3. 检查 Cookie 的 SameSite 属性",
        "root_cause": "应用程序依赖 Cookie 认证但未实施 CSRF 防护，攻击者可伪造用户请求。",
        "mitigation": "为所有状态变更请求添加 CSRF Token；设置 SameSite=Strict。",
    },
    # === 文件上传 ===
    "434": {
        "name": "无限制文件上传",
        "category": "注入攻击",
        "owasp_rank": "A03:2021",
        "attack_path": "攻击者上传恶意文件（Web Shell、可执行脚本、超大文件），获取服务器控制权或导致服务不可用。",
        "exploitation": "低 — 上传恶意文件即完成攻击，门槛极低。",
        "business_impact": "高 — 可导致服务器被完全控制、恶意文件分发、存储资源耗尽。",
        "fix_approaches": [
            {"title": "文件类型白名单", "language": "python",
             "before": "file.save(f'/uploads/{file.filename}')",
             "after": "ALLOWED = {'jpg','png','pdf'}\next = file.filename.rsplit('.',1)[1].lower()\nif ext not in ALLOWED:\n    raise ValueError('File type not allowed')\nimport uuid\nsafe_name = f'{uuid.uuid4()}.{ext}'\nfile.save(f'/uploads/{safe_name}')"},
            {"title": "内容检测（Magic Bytes）", "language": "python",
             "before": "file.save(f'/uploads/{filename}')",
             "after": "import magic\ncontent = file.read(2048)\nmime = magic.from_buffer(content, mime=True)\nif mime not in ['image/jpeg','image/png']:\n    raise ValueError('Invalid file content')"},
        ],
        "verification": "1. 尝试上传 .php/.jsp 等可执行文件\n2. 验证文件内容类型和白名单\n3. 检查上传目录的执行权限",
        "root_cause": "文件上传功能未限制文件类型、大小和内容，攻击者可上传可执行文件。",
        "mitigation": "限制文件类型白名单；文件重命名为随机名；上传目录禁止脚本执行（nginx/apache 配置）。",
    },
    # === IDOR ===
    "639": {
        "name": "IDOR（不安全的直接对象引用）",
        "category": "访问控制",
        "owasp_rank": "A01:2021",
        "attack_path": "攻击者修改请求中的资源 ID 参数（如 user_id=123 改为 124），访问或操作其他用户的数据。",
        "exploitation": "低 — 仅需修改 URL 或请求体中的数字 ID，无需工具。",
        "business_impact": "高 — 可导致大规模数据泄露、用户信息遍历，是业务数据安全的首要威胁。",
        "fix_approaches": [
            {"title": "服务端权限校验", "language": "python",
             "before": "order = Order.query.get(order_id)\nreturn jsonify(order.to_dict())",
             "after": "order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()\nif not order:\n    abort(403)\nreturn jsonify(order.to_dict())"},
            {"title": "使用不可预测的资源 ID", "language": "python",
             "before": "GET /api/user/123/profile",
             "after": "GET /api/user/a1b2c3d4-e5f6/profile  # UUID"},
        ],
        "verification": "1. 遍历资源 ID 验证是否可访问他人数据\n2. 审查所有 CRUD 端点是否有属主校验\n3. 确认 UUID 替代自增 ID 的完整性",
        "root_cause": "API 端点信任客户端提供的资源 ID，未校验当前用户对该资源的访问权限。",
        "mitigation": "为每个资源操作添加属主校验；使用 UUID 替代自增 ID；实施集中式授权中间件。",
    },
    # === 日志注入 ===
    "117": {
        "name": "日志注入与日志伪造",
        "category": "软件与数据完整性故障",
        "owasp_rank": "A08:2021",
        "attack_path": "攻击者在用户输入中插入换行符或日志分隔符，伪造日志条目、注入恶意内容到日志分析系统。",
        "exploitation": "中 — 需要了解目标日志格式，但可严重影响安全监控和审计。",
        "business_impact": "中 — 可绕过安全监控告警、伪造操作记录，妨碍事后追溯。",
        "fix_approaches": [
            {"title": "日志内容清理", "language": "python",
             "before": "logger.info(f\"User login: {username}\")",
             "after": "import re\nsafe = re.sub(r'[\\r\\n\\t]', '_', username)\nlogger.info(f\"User login: {safe}\")"},
        ],
        "verification": "1. 输入包含 \\n 的内容验证日志不被分割\n2. 确认日志分析系统不受注入影响",
        "root_cause": "用户输入直接写入日志，未转义或清理特殊控制字符。",
        "mitigation": "所有用户输入写入日志前进行换行符和分隔符转义；日志收集端实施内容校验。",
    },
    # === 整数溢出 ===
    "190": {
        "name": "整数溢出",
        "category": "软件与数据完整性故障",
        "owasp_rank": "A08:2021",
        "attack_path": "攻击者提供极大或负数的数值输入，导致整数溢出、缓冲区溢出或逻辑错误。",
        "exploitation": "中 — 需要理解目标系统的整数表示范围。",
        "business_impact": "中 — 可导致内存破坏、权限绕过或拒绝服务。",
        "fix_approaches": [
            {"title": "边界检查", "language": "go",
             "before": "size := int(userSize)\nbuf := make([]byte, size)",
             "after": "if userSize < 0 || userSize > maxSize {\n    return nil, errors.New(\"invalid size\")\n}\nbuf := make([]byte, userSize)"},
        ],
        "verification": "1. 输入 INT_MAX/INT_MIN 测试边界行为\n2. 确认所有类型转换有范围检查\n3. 使用 safe 算术库防止溢出",
        "root_cause": "数值运算和类型转换未检查边界条件，导致溢出引发非预期行为。",
        "mitigation": "在类型转换和大数运算前实施范围检查；使用语言内置的安全算术函数。",
    },
    # === CORS ===
    "942": {
        "name": "CORS 配置不当",
        "category": "访问控制",
        "owasp_rank": "A01:2021",
        "attack_path": "CORS 配置为 Access-Control-Allow-Origin: * 或反射请求 origin，攻击者可在恶意网站中跨域窃取用户敏感数据。",
        "exploitation": "低 — 仅需诱导用户访问恶意页面。",
        "business_impact": "中 — 可导致用户数据被跨域窃取，影响用户隐私。",
        "fix_approaches": [
            {"title": "限制允许的 Origin", "language": "python",
             "before": "CORS(app, origins='*')",
             "after": "CORS(app, origins=['https://example.com'])"},
        ],
        "verification": "1. 从恶意域名发起跨域请求验证被拒绝\n2. 确认 Access-Control-Allow-Origin 不是 *\n3. 验证 Allow-Credentials 配置的安全性",
        "root_cause": "CORS 配置过于宽松，允许任意域跨域访问需要认证的 API。",
        "mitigation": "限制 origins 白名单；禁止将 * 与 credentials 同时使用。",
    },
    # === 依赖 CVE（通用） ===
    "dep-cve": {
        "name": "依赖库已知漏洞",
        "category": "软件成分",
        "owasp_rank": "A06:2021",
        "attack_path": "第三方依赖库存在已知安全漏洞，攻击者利用该漏洞通过供应链攻击或直接利用依赖的缺陷入侵应用。",
        "exploitation": "中 — 取决于 CVE 的具体类型，部分已有公开 PoC，部分需要特定条件触发。",
        "business_impact": "中高 — 可能导致远程代码执行、权限提升或数据泄露，影响范围取决于依赖的使用方式。",
        "fix_approaches": [
            {"title": "升级依赖版本", "language": "bash",
             "before": "\"lodash\": \"4.17.15\"",
             "after": "\"lodash\": \"4.17.21\"  # npm update lodash"},
            {"title": "替换安全替代库", "language": "bash",
             "before": "\"request\": \"2.88.0\"",
             "after": "\"node-fetch\": \"3.3.2\"  # 或 axios"},
            {"title": "临时缓解（无法升级时）", "language": "python",
             "before": "from vuln_lib import parse_input\nresult = parse_input(user_data)",
             "after": "from vuln_lib import parse_input\nfrom security import sanitize\nresult = parse_input(sanitize(user_data))"},
        ],
        "verification": "1. 使用 SCA 工具确认漏洞已消除\n2. 验证升级后功能正常\n3. 建立依赖定期审查机制",
        "root_cause": "项目使用含已知漏洞的依赖版本，未及时跟进安全更新。",
        "mitigation": "如无法升级，评估缓解方案；启用 Dependabot 自动更新；建立 SBOM 流程。",
    },

    # === CWE-327: 弱密码哈希 ===
    "327": {
        "name": "弱密码哈希算法",
        "category": "加密",
        "owasp_rank": "A02:2021",
        "attack_path": "使用 MD5/SHA1/SHA256 等单次哈希存储密码，攻击者通过彩虹表或暴力破解在秒级时间内恢复明文密码。",
        "exploitation": "低 — 攻击者可离线批量破解哈希，工具成熟（hashcat/john），无需与目标系统交互。",
        "business_impact": "严重 — 所有用户密码可能被批量破解，导致大规模账户接管、数据泄露和合规违规。",
        "fix_approaches": [
            {"title": "使用 bcrypt（推荐）", "language": "python",
             "before": "import hashlib\npw_hash = hashlib.sha256(password.encode()).hexdigest()",
             "after": "import bcrypt\npw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()"},
            {"title": "使用 Argon2（最安全）", "language": "python",
             "before": "pw_hash = hashlib.sha256(password).hexdigest()",
             "after": "from argon2 import PasswordHasher\nph = PasswordHasher()\npw_hash = ph.hash(password)"},
            {"title": "旧用户自动升级哈希", "language": "python",
             "before": "if hashlib.sha256(pwd).hexdigest() == stored_hash:\n    login()",
             "after": "if bcrypt.checkpw(pwd.encode(), stored_hash):\n    if needs_upgrade(stored_hash):\n        new_hash = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())\n        update_hash(user_id, new_hash)\n    login()"},
        ],
        "verification": "1. 新用户使用强哈希（bcrypt/Argon2）\n2. 旧用户登录时自动升级\n3. 代码审计确保无残留弱哈希",
        "root_cause": "开发者使用通用哈希算法（SHA256/MD5）存储密码，未使用专为密码设计的慢哈希函数。",
        "mitigation": "立即迁移到 bcrypt/Argon2；设置最小 cost factor（bcrypt≥10，Argon2≥3次迭代）。",
    },

    # === CWE-732: 不正确的权限分配 ===
    "732": {
        "name": "不正确的权限分配",
        "category": "授权",
        "owasp_rank": "A01:2021",
        "attack_path": "文件或资源被分配了过于宽松的权限（如 777），攻击者或低权限用户可读取、修改甚至执行敏感文件。",
        "exploitation": "中低 — 需要文件系统或应用层访问权限，但一旦获权影响严重。",
        "business_impact": "高 — 敏感配置文件、私钥或数据库文件可能被泄露或篡改，导致服务中断和数据泄露。",
        "fix_approaches": [
            {"title": "设置最小权限", "language": "bash",
             "before": "chmod 777 /app/config/secrets.yml",
             "after": "chmod 600 /app/config/secrets.yml  # 仅 owner 可读写"},
            {"title": "程序化控制文件权限", "language": "python",
             "before": "open('/etc/app/secrets', 'w').write(data)",
             "after": "import os\nfd = os.open('/etc/app/secrets', os.O_WRONLY|os.O_CREAT, 0o600)\nwith os.fdopen(fd, 'w') as f:\n    f.write(data)"},
        ],
        "verification": "1. find / -perm /o+w 检查可写文件\n2. 确认所有配置目录权限为 700 或 750\n3. CI 中集成权限检查",
        "root_cause": "部署或开发过程中使用过于宽松的文件权限（777），未遵循最小权限原则。",
        "mitigation": "立即收紧敏感文件权限；部署脚本中显式设置 umask 027 或更严格。",
    },

    # === CWE-862: 缺失授权检查 ===
    "862": {
        "name": "缺失授权检查",
        "category": "授权",
        "owasp_rank": "A01:2021",
        "attack_path": "API 端点缺少授权验证，用户 A 可直接访问用户 B 的资源（IDOR），绕过业务逻辑限制。",
        "exploitation": "低 — 攻击者只需修改请求中的资源 ID 即可访问他人数据，无需高级技能。",
        "business_impact": "严重 — 用户数据大面积泄露，且通常难以通过 WAF 等传统手段检测。",
        "fix_approaches": [
            {"title": "添加资源所有权验证", "language": "python",
             "before": "@app.route('/api/order/<order_id>')\ndef get_order(order_id):\n    return Order.query.get(order_id)",
             "after": "@app.route('/api/order/<order_id>')\n@login_required\ndef get_order(order_id):\n    order = Order.query.get(order_id)\n    if order.user_id != current_user.id:\n        abort(403)\n    return order"},
            {"title": "使用中间件统一鉴权", "language": "python",
             "before": "def get_resource(resource_id):\n    return db.query(Resource).get(resource_id)",
             "after": "def get_resource(resource_id):\n    resource = db.query(Resource).get(resource_id)\n    if not can_access(current_user, resource):\n        raise Forbidden('无权访问此资源')\n    return resource"},
        ],
        "verification": "1. 对所有 API 端点审查授权逻辑\n2. 自动化测试覆盖越权场景\n3. 使用 BOLA/IDOR 检测工具扫描",
        "root_cause": "API 设计中只验证了认证（你是谁），未验证授权（你能做什么/访问什么）。",
        "mitigation": "为所有资源访问添加所有权检查；使用 RBAC/ABAC 框架；定期进行授权审计。",
    },

    # === CWE-522: 凭证保护不足 ===
    "522": {
        "name": "凭证保护不足",
        "category": "认证",
        "owasp_rank": "A07:2021",
        "attack_path": "密码、API Key 等凭证以明文或弱加密存储在数据库/日志/配置文件中，攻击者通过数据库泄露或日志分析获取凭证。",
        "exploitation": "低 — 一旦获取数据库或日志文件访问权限即可直接读取凭证，无需额外破解。",
        "business_impact": "严重 — 所有用户凭证和 API Key 泄露，攻击者可直接冒充用户或访问第三方服务。",
        "fix_approaches": [
            {"title": "密码哈希存储", "language": "python",
             "before": "db.execute('INSERT INTO users (email, password) VALUES (?,?)', (email, password))",
             "after": "import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\ndb.execute('INSERT INTO users (email, password) VALUES (?,?)', (email, hashed.decode()))"},
            {"title": "API Key 加密存储", "language": "python",
             "before": "api_key = 'sk-abc123'\ndb.save({'service': 'OpenAI', 'key': api_key})",
             "after": "from cryptography.fernet import Fernet\ncipher = Fernet(os.environ['ENCRYPTION_KEY'])\nencrypted = cipher.encrypt(api_key.encode())\ndb.save({'service': 'OpenAI', 'key': encrypted})"},
        ],
        "verification": "1. 全库扫描确认无明文密码\n2. 日志脱敏验证\n3. 渗透测试确认凭证不可恢复",
        "root_cause": "凭证以明文或可逆加密方式存储，开发者认为数据库安全即等同于凭证安全。",
        "mitigation": "密码必须哈希存储（bcrypt/Argon2）；API Key/Token 使用 AES-256-GCM 加密；禁止在日志中输出凭证。",
    },

    # === CWE-601: URL 重定向 ===
    "601": {
        "name": "不安全的 URL 重定向",
        "category": "输入验证",
        "owasp_rank": "其他",
        "attack_path": "应用根据用户输入的 URL 参数进行重定向但未验证目标，攻击者构造恶意链接将用户导向钓鱼网站。",
        "exploitation": "低 — 攻击者只需构造恶意 URL 并通过社工诱导用户点击，利用真实域名增加可信度。",
        "business_impact": "中 — 用于钓鱼攻击，损害品牌信誉；可能被用于 OAuth 重定向劫持导致账户接管。",
        "fix_approaches": [
            {"title": "白名单验证跳转目标", "language": "python",
             "before": "redirect_url = request.args.get('next')\nreturn redirect(redirect_url)",
             "after": "from urllib.parse import urlparse\nALLOWED_HOSTS = {'example.com', 'app.example.com'}\nredirect_url = request.args.get('next')\nif redirect_url:\n    host = urlparse(redirect_url).netloc\n    if host in ALLOWED_HOSTS:\n        return redirect(redirect_url)\nreturn redirect('/dashboard')"},
            {"title": "使用相对路径跳转", "language": "python",
             "before": "return redirect(request.args.get('redirect'))",
             "after": "target = request.args.get('redirect', '/dashboard')\nif target.startswith('/'):\n    return redirect(target)\nreturn redirect('/dashboard')"},
        ],
        "verification": "1. 测试 //evil.com、https://evil.com、javascript: 等 payload\n2. 确保只有白名单域名可跳转\n3. 检查 OAuth/Deeplink 中的 redirect_uri 验证",
        "root_cause": "应用直接将用户提供的 URL 作为重定向目标，未进行白名单验证。",
        "mitigation": "实施白名单域名验证；优先使用相对路径跳转；在响应头中设置 Referrer-Policy。",
    },

    # === CWE-770: 无限制资源分配 ===
    "770": {
        "name": "无限制资源分配（DoS）",
        "category": "可用性",
        "owasp_rank": "其他",
        "attack_path": "攻击者发送精心构造的请求，消耗服务器 CPU、内存或磁盘资源直至耗尽，导致服务不可用。",
        "exploitation": "中 — 单次请求即可触发，但需要了解系统资源分配机制；自动化脚本可批量放大攻击。",
        "business_impact": "高 — 服务中断直接影响业务收入和用户信任，恢复时间可能数小时。",
        "fix_approaches": [
            {"title": "限制请求体大小", "language": "python",
             "before": "data = request.get_data()\nprocess(data)",
             "after": "MAX_SIZE = 10 * 1024 * 1024  # 10MB\nif request.content_length > MAX_SIZE:\n    abort(413)\ndata = request.get_data()"},
            {"title": "设置处理超时", "language": "python",
             "before": "result = process_image(image_data)",
             "after": "import signal\nsignal.alarm(30)  # 30秒超时\ntry:\n    result = process_image(image_data)\nfinally:\n    signal.alarm(0)"},
            {"title": "速率限制与队列", "language": "python",
             "before": "for task in user_tasks:\n    execute(task)",
             "after": "from queue import Queue\nfrom threading import Thread\nq = Queue(maxsize=100)\nfor task in user_tasks:\n    q.put(task, timeout=30)\nThread(target=worker, args=(q,), daemon=True).start()"},
        ],
        "verification": "1. 压力测试确认资源上限\n2. 验证超时机制触发正确\n3. 监控服务资源使用趋势",
        "root_cause": "系统未对用户输入的资源消耗设置上限，导致单个或少量请求即可耗尽系统资源。",
        "mitigation": "设置请求大小/频率限制；使用异步队列处理重任务；CPU/内存密集型操作设置超时和资源上限。",
    },
}


def _severity_to_score(severity: str) -> int:
    mapping = {"critical": 95, "high": 80, "medium": 55, "low": 25, "info": 5}
    return mapping.get(severity.lower(), 30)


def _match_cwe_key(vuln) -> str:
    """智能匹配漏洞类型到 CWE 知识库，支持 CWE ID 精确匹配和关键词模糊匹配。"""
    cwe_id = str(vuln["cwe_id"] or "").strip().replace("CWE-", "") if "cwe_id" in vuln.keys() else ""
    title = str(vuln["title"] or "").lower() if "title" in vuln.keys() else ""
    vuln_type = str(vuln["vuln_type"] or "").lower() if "vuln_type" in vuln.keys() else ""
    desc = str(vuln.get("description", "") or "").lower()
    combined = f"{title} {vuln_type} {desc}"

    # 精确 CWE ID 匹配
    if cwe_id in CWE_ANALYSIS_MAP:
        return cwe_id

    # 关键词 → CWE 映射表（按优先级排序，越具体越靠前）
    KEYWORD_MAP = [
        # 注入类
        (["sql", "注入", "inject", "sqli", "nosql inject"], "89"),
        (["命令注入", "command inject", "os.system", "subprocess", "shell inject", "rce"], "78"),
        (["xss", "跨站脚本", "cross-site", "script inject", "dom-based", "stored xss", "reflected xss", "html inject"], "79"),
        (["xxe", "xml外部实体", "xml external", "xml entity", "documentbuilder"], "611"),
        (["日志注入", "log injection", "log forge", "crlf"], "117"),
        (["原型污染", "prototype pollution", "__proto__", "constructor.prototype"], "915"),
        # 访问控制类
        (["ssrf", "服务端请求伪造", "server side request", "url注入"], "918"),
        (["路径遍历", "path traversal", "目录遍历", "directory traversal", "../", "file path"], "22"),
        (["csrf", "跨站请求伪造", "cross-site request", "xsrf"], "352"),
        (["idor", "直接对象引用", "direct object", "authorization bypass", "越权", "权限绕过", "access control"], "639"),
        (["cors", "跨域", "cross-origin", "access-control-allow"], "942"),
        # 数据完整性类
        (["反序列化", "deserial", "pickle", "objectinputstream", "ysoserial", "unserialize"], "502"),
        (["文件上传", "file upload", "unrestricted upload", "任意文件上传"], "434"),
        (["整数溢出", "integer overflow", "int overflow", "buffer overflow"], "190"),
        # 加密类
        (["证书验证", "certificate", "tls", "ssl", "verify=false", "中间人", "mitm"], "295"),
        (["弱哈希", "weak hash", "md5", "sha1", "sha256 password", "bcrypt", "argon", "password hash", "明文密码", "plaintext password", "加密算法"], "327"),
        (["敏感信息", "信息泄露", "information exposure", "stack trace", "debug mode", "exception", "error message"], "200"),
        # 认证类
        (["硬编码", "hardcod", "credential", "secret", "密码", "passwd", "api key", "token leak"], "798"),
        (["凭证保护", "明文存储", "plaintext storage", "credential storage", "密钥存储"], "522"),
        # 授权类
        (["权限分配", "permission", "chmod", "file mode", "incorrect permission", "777", "过于宽松"], "732"),
        (["授权检查", "missing auth", "缺失授权", "authorization missing", "no permission check"], "862"),
        # 输入验证
        (["重定向", "redirect", "open redirect", "url跳转", "redirect_uri"], "601"),
        # 可用性
        (["资源耗尽", "dos", "denial of service", "资源分配", "resource exhaustion", "无限制", "unlimited"], "770"),
        # 依赖/SBOM类
        (["cve", "depend", "依赖", "supply chain", "供应链", "known vulnerability", "component", "outdated"], "dep-cve"),
    ]

    for keywords, cwe_key in KEYWORD_MAP:
        if any(kw in combined for kw in keywords):
            return cwe_key

    return "89"  # 默认 SQL 注入


EXPLOITATION_LEVELS = [
    {"label": "极低", "desc": "无需任何技术门槛，自动化脚本即可利用", "value": 85},
    {"label": "低", "desc": "攻击向量清晰，公开 PoC 可用", "value": 65},
    {"label": "中", "desc": "需一定安全知识和自定义 payload", "value": 40},
    {"label": "高", "desc": "需特定条件触发或深度技术能力", "value": 20},
    {"label": "极高", "desc": "理论上可被利用，但实际难以达成", "value": 5},
]

def _parse_exploitation_difficulty(text: str) -> dict:
    """Parse '低 — ...' formatted exploitation text into structured data."""
    for level in EXPLOITATION_LEVELS:
        if text.startswith(level["label"]):
            return {"label": level["label"], "description": text, "value": level["value"]}
    return {"label": "未知", "description": text, "value": 30}

def _build_attack_steps(cwe_key: str) -> list:
    """为每种漏洞类型生成可视化的攻击步骤。"""
    STEPS = {
        "89": [
            {"title": "信息探测", "detail": "攻击者识别应用中可能存在 SQL 交互的入口点（登录表单、搜索框、URL 参数等）", "icon": "search"},
            {"title": "注入点验证", "detail": "输入单引号、布尔表达式等探测 payload，观察响应异常或错误信息泄露", "icon": "target"},
            {"title": "Payload 构造", "detail": "根据数据库类型构造 UNION SELECT、Boolean/Time-based 盲注或堆叠查询", "icon": "code"},
            {"title": "数据提取", "detail": "逐列提取数据库结构、用户表信息，批量导出敏感数据", "icon": "download"},
            {"title": "持久化与横向移动", "detail": "通过写入文件、执行系统命令建立后门，横向渗透至内网其他服务", "icon": "shield-off"},
        ],
        "78": [
            {"title": "定位命令执行点", "detail": "识别将用户输入传递给系统命令的代码（os.system、subprocess、exec 等）", "icon": "search"},
            {"title": "命令分隔符注入", "detail": "插入 ; | && || 等 shell 元字符，注入额外的系统命令", "icon": "code"},
            {"title": "建立反向 Shell", "detail": "注入 nc/bash 反向连接命令，获取交互式 shell 访问", "icon": "terminal"},
            {"title": "权限提升", "detail": "利用 SUID 二进制文件、内核漏洞提升至 root 权限", "icon": "unlock"},
            {"title": "内网横向移动", "detail": "以被控服务器为跳板，扫描和渗透内网其他系统", "icon": "git-branch"},
        ],
        "79": [
            {"title": "注入点探测", "detail": "攻击者在表单、URL 参数、评论等输入点注入 <script> 标签，检查是否被反射回 HTML", "icon": "search"},
            {"title": "Payload 构造", "detail": "设计恶意脚本：窃取 Cookie、构造钓鱼弹窗、修改页面 DOM 进行社会工程攻击", "icon": "code"},
            {"title": "载荷分发", "detail": "通过链接、邮件或存储型 XSS 将 payload 传递给目标受害者", "icon": "send"},
            {"title": "会话劫持", "detail": "JavaScript 读取 document.cookie、localStorage 并发送至攻击者 C2 服务器", "icon": "key"},
            {"title": "持久化后门", "detail": "修改页面核心 JS 逻辑，在后续访问中持续执行恶意代码", "icon": "repeat"},
        ],
        "918": [
            {"title": "识别 SSRF 入口", "detail": "找到接受 URL 参数的 API 端点（文件下载、webhook 回调、URL 预览等）", "icon": "search"},
            {"title": "内网地址探测", "detail": "将 URL 替换为 localhost/127.0.0.1/10.x/192.168.x 测试是否能访问内网服务", "icon": "target"},
            {"title": "云元数据窃取", "detail": "构造对 169.254.169.254 的请求获取 AWS/Azure/阿里云 临时凭证", "icon": "cloud"},
            {"title": "内网服务扫描", "detail": "利用 SSRF 端点作为代理扫描内网端口和服务版本", "icon": "radio"},
            {"title": "权限拓展", "detail": "使用窃取的云凭证管理云资源，创建后门访问通道", "icon": "unlock"},
        ],
        "611": [
            {"title": "发现 XML 解析端点", "detail": "定位接受 XML 输入的 API（SOAP/REST XML、文件上传导入）", "icon": "search"},
            {"title": "注入 DOCTYPE 声明", "detail": "在 XML 中声明外部实体指向本地文件 /etc/passwd 或 /proc/self/environ", "icon": "code"},
            {"title": "文件读取与泄露", "detail": "从错误消息或回显中读取目标文件内容", "icon": "download"},
            {"title": "内网 SSRF", "detail": "将实体 URI 指向内网地址，探测内部服务", "icon": "radio"},
            {"title": "DoS 攻击", "detail": "利用 Billion Laughs 实体扩展攻击耗尽服务器内存", "icon": "alert-triangle"},
        ],
        "502": [
            {"title": "识别序列化端点", "detail": "发现接受序列化数据的接口（Cookie、POST 载荷、RPC 调用）", "icon": "search"},
            {"title": "逆向分析类结构", "detail": "分析应用程序 classpath 和依赖，寻找可用 gadget chain", "icon": "code"},
            {"title": "构造恶意 Payload", "detail": "使用 ysoserial/marshalsec 生成恶意序列化数据", "icon": "zap"},
            {"title": "触发反序列化", "detail": "将 payload 发送至目标接口，触发 gadget chain 实现 RCE", "icon": "play"},
            {"title": "后渗透操作", "detail": "获取 shell 后部署持久化后门、横向移动", "icon": "shield-off"},
        ],
        "22": [
            {"title": "定位文件操作端点", "detail": "找到接受 filename/path 参数的接口（文件下载、预览、读取）", "icon": "search"},
            {"title": "注入路径遍历符号", "detail": "将文件名替换为 ../../etc/passwd 测试能否读取上级目录文件", "icon": "code"},
            {"title": "敏感文件读取", "detail": "读取配置文件、数据库文件、SSH 密钥等系统敏感信息", "icon": "download"},
            {"title": "源码泄露", "detail": "读取应用源码中的数据库密码、API 密钥和业务逻辑", "icon": "eye-off"},
            {"title": "写入 Web Shell", "detail": "如果同时存在文件写入功能，在 Web 目录写入可执行脚本", "icon": "upload"},
        ],
        "352": [
            {"title": "分析状态变更 API", "detail": "识别无 CSRF 防护的 POST/PUT/DELETE 端点（转账、改密、删数据）", "icon": "search"},
            {"title": "构造恶意页面", "detail": "创建包含自动提交表单或 AJAX 请求的 HTML 页面", "icon": "code"},
            {"title": "诱导用户访问", "detail": "通过钓鱼邮件、论坛链接、XSS 将恶意页面发送给登录用户", "icon": "send"},
            {"title": "执行非预期操作", "detail": "以受害者身份完成交易、修改密码、删除数据", "icon": "play"},
            {"title": "清理痕迹", "detail": "删除操作日志、隐藏攻击证据", "icon": "trash"},
        ],
        "434": [
            {"title": "定位上传端点", "detail": "找到文件上传功能（头像上传、附件、文件导入）", "icon": "search"},
            {"title": "绕过类型检查", "detail": "修改 Content-Type、文件扩展名或 Magic Bytes 伪装文件类型", "icon": "code"},
            {"title": "上传 Web Shell", "detail": "上传 PHP/JSP/ASPX 一句话木马到可执行目录", "icon": "upload"},
            {"title": "获取代码执行", "detail": "访问上传的 Web Shell，获取服务器命令执行权限", "icon": "terminal"},
            {"title": "横向扩展", "detail": "下载提权工具、扫描内网、部署持久化后门", "icon": "git-branch"},
        ],
        "639": [
            {"title": "遍历资源 ID", "detail": "修改 API 请求中的数字 ID 参数（user_id=123 → 124），观察是否返回他人数据", "icon": "search"},
            {"title": "信息收集", "detail": "批量遍历 ID 范围，收集其他用户的个人信息、订单记录", "icon": "download"},
            {"title": "权限操作", "detail": "尝试修改他人资源的状态、删除他人数据", "icon": "edit"},
            {"title": "数据外泄", "detail": "将收集到的敏感数据打包导出", "icon": "package"},
            {"title": "长期监控", "detail": "定期轮询 API 获取最新数据变更", "icon": "eye"},
        ],
        "798": [
            {"title": "凭证发现", "detail": "攻击者通过公开仓库监控、代码泄露、反向工程获取源码中的硬编码凭证", "icon": "search"},
            {"title": "凭证验证", "detail": "使用获取的凭证尝试登录目标服务（数据库、API、云平台）", "icon": "key"},
            {"title": "权限拓展", "detail": "利用高权限凭证创建新账户、提升权限、关闭审计日志", "icon": "unlock"},
            {"title": "数据窃取", "detail": "导出业务数据、删除关键记录、植入勒索软件", "icon": "alert-triangle"},
            {"title": "长期潜伏", "detail": "创建隐蔽访问通道，持续窃取数据直至被发现", "icon": "eye-off"},
        ],
        "117": [
            {"title": "注入控制字符", "detail": "在日志输入（用户名、User-Agent 等）中插入 \\n 换行符或日志分隔符", "icon": "code"},
            {"title": "伪造日志条目", "detail": "构造虚假的访问记录、登录事件，混淆安全审计", "icon": "edit"},
            {"title": "注入 XSS Payload", "detail": "在日志内容中嵌入 <script> 标签，攻击基于 Web 的日志查看器", "icon": "zap"},
            {"title": "绕过安全告警", "detail": "伪造正常操作日志掩盖恶意行为", "icon": "eye-off"},
        ],
        "190": [
            {"title": "识别数值输入", "detail": "找到接受整数参数的接口（分配大小、循环计数、数组索引）", "icon": "search"},
            {"title": "输入边界值", "detail": "输入 INT_MAX、INT_MIN、负数测试溢出行为", "icon": "code"},
            {"title": "触发缓冲区溢出", "detail": "利用溢出写入越界内存，覆盖函数指针或返回地址", "icon": "alert-triangle"},
            {"title": "代码执行", "detail": "构造 ROP chain 或 shellcode 获取程序控制权", "icon": "terminal"},
        ],
        "295": [
            {"title": "中间人定位", "detail": "攻击者通过 ARP 欺骗或恶意 WiFi 热点进入通信路径", "icon": "radio"},
            {"title": "TLS 降级", "detail": "利用 verify=False 特性，将 HTTPS 降级为明文 HTTP", "icon": "arrow-down"},
            {"title": "流量嗅探", "detail": "使用 Wireshark/tcpdump 捕获明文传输的密码和 Token", "icon": "eye"},
            {"title": "会话劫持", "detail": "提取会话 Cookie 或 JWT Token，冒充用户身份", "icon": "key"},
        ],
        "200": [
            {"title": "触发错误", "detail": "发送畸形请求、SQL 注入 payload 或非法参数触发应用异常", "icon": "target"},
            {"title": "分析错误响应", "detail": "从堆栈跟踪中提取文件路径、框架版本、数据库结构", "icon": "search"},
            {"title": "利用泄露信息", "detail": "根据泄露的技术栈信息选择精准的攻击工具和 exploit", "icon": "code"},
            {"title": "目标攻击", "detail": "针对已知框架版本和配置缺陷发起定向攻击", "icon": "crosshair"},
        ],
        "915": [
            {"title": "注入 __proto__", "detail": "在 JSON 请求体中设置 __proto__.isAdmin 或 constructor.prototype 属性", "icon": "code"},
            {"title": "污染对象原型", "detail": "通过 Object.assign 或 lodash merge 将恶意属性注入全局原型", "icon": "zap"},
            {"title": "触发权限绕过", "detail": "利用污染后的属性检查逻辑，绕过身份认证或授权判断", "icon": "unlock"},
            {"title": "持久化污染", "detail": "污染的属性影响后续所有请求的权限判断", "icon": "repeat"},
        ],
        "942": [
            {"title": "跨域探测", "detail": "从恶意域名发起对目标 API 的 OPTIONS 预检请求", "icon": "search"},
            {"title": "验证 CORS 配置", "detail": "检查 Access-Control-Allow-Origin 是否反射请求 Origin 或设为 *", "icon": "target"},
            {"title": "构造钓鱼页面", "detail": "创建恶意网站，通过 fetch/XHR 跨域窃取用户数据", "icon": "code"},
            {"title": "数据外泄", "detail": "将窃取的用户数据发送至攻击者服务器", "icon": "download"},
        ],
        "dep-cve": [
            {"title": "漏洞情报收集", "detail": "攻击者监控 CVE DB 和 GitHub Advisory，定位使用该依赖的目标", "icon": "search"},
            {"title": "PoC 获取", "detail": "从 Exploit-DB、Metasploit 或 GitHub 获取公开利用代码", "icon": "download"},
            {"title": "漏洞触发", "detail": "构造特制请求或输入触发依赖库的已知漏洞", "icon": "zap"},
            {"title": "权限获取", "detail": "利用漏洞实现 RCE、权限提升或信息泄露", "icon": "unlock"},
            {"title": "供应链扩散", "detail": "如攻击者控制上游依赖，可通过 npm/pip 更新注入恶意代码", "icon": "git-branch"},
        ],
    }
    return STEPS.get(cwe_key, STEPS["89"])

def _build_simulated_analysis(vuln) -> dict:
    severity = vuln["severity"] if "severity" in vuln.keys() else "medium"
    cwe_key = _match_cwe_key(vuln)
    info = CWE_ANALYSIS_MAP.get(cwe_key, CWE_ANALYSIS_MAP["89"])
    risk_score = _severity_to_score(severity)
    exploitation = _parse_exploitation_difficulty(info["exploitation"])
    attack_steps = _build_attack_steps(cwe_key)

    # Business impact areas
    impact_areas = [
        {"name": "数据安全", "level": "高", "level_value": 85, "detail": "可能导致数据库完全泄露，包含用户个人信息、业务交易记录等核心数据"},
        {"name": "业务连续性", "level": "中", "level_value": 60, "detail": "攻击可能导致服务中断或数据损坏，影响正常业务运营"},
        {"name": "合规风险", "level": "高", "level_value": 80, "detail": "违反 GDPR/个人信息保护法/PCI DSS 等数据安全法规，面临处罚"},
        {"name": "品牌信誉", "level": "高", "level_value": 75, "detail": "安全事件公开后将严重损害用户信任和品牌形象"},
        {"name": "财务损失", "level": "中", "level_value": 55, "detail": "修复成本、合规罚款、业务损失总和高"},
    ]
    # Adjust based on severity
    if severity.lower() == "low":
        for area in impact_areas:
            area["level_value"] = max(10, area["level_value"] - 40)
            area["level"] = "低" if area["level_value"] < 35 else ("中" if area["level_value"] < 65 else "高")

    analysis_sections = {
        "vulnerability_type": info["name"],
        "severity_assessment": {
            "original_level": severity.upper(),
            "ai_risk_score": risk_score,
            "recommendation": "立即修复" if risk_score >= 70 else ("尽快修复" if risk_score >= 40 else "持续监控"),
            "recommendation_color": "#ef4444" if risk_score >= 70 else ("#f97316" if risk_score >= 40 else "#22c55e"),
        },
        "attack_path": {
            "summary": info["attack_path"],
            "steps": attack_steps,
        },
        "exploitation_difficulty": exploitation,
        "business_impact": {
            "summary": info["business_impact"],
            "areas": impact_areas,
        },
        "mitigation": {
            "priority": "立即修复" if risk_score >= 70 else ("尽快修复" if risk_score >= 40 else "持续监控"),
            "recommendation": info["mitigation"],
        },
    }

    analysis_md = (
        f"## {info['name']} — 漏洞分析报告\n\n"
        f"### 严重性评估\n\n"
        f"当前漏洞等级为 **{severity.upper()}**，AI 风险评分 **{risk_score}/100**。\n\n"
        f"### 攻击路径分析\n\n"
        f"{info['attack_path']}\n\n"
        f"### 利用难度\n\n"
        f"{info['exploitation']}\n\n"
        f"### 业务影响\n\n"
        f"{info['business_impact']}\n\n"
        f"### 修复优先级建议\n\n"
        f"**{analysis_sections['severity_assessment']['recommendation']}** — {info['mitigation']}\n\n"
        f"---\n"
        f"*此分析由哨兵安全平台模拟生成，配置 AI 服务后可获得更精准的分析结果。*"
    )

    return {
        "analysis": analysis_md,
        "analysis_sections": analysis_sections,
        "risk_score": risk_score,
        "ai_model": "simulated"
    }


def _build_simulated_fix(vuln) -> dict:
    cwe_key = _match_cwe_key(vuln)
    info = CWE_ANALYSIS_MAP.get(cwe_key, CWE_ANALYSIS_MAP["89"])

    fix_md = (
        f"## {info['name']} — 修复建议\n\n"
        f"### 根因分析\n\n"
        f"{info['root_cause']}\n\n"
        f"### 修复方案\n\n"
    )

    for i, approach in enumerate(info["fix_approaches"], 1):
        fix_md += (
            f"#### 方案 {i}：{approach['title']}\n\n"
            f"**修复前：**\n\n```{approach['language']}\n{approach['before']}\n```\n\n"
            f"**修复后：**\n\n```{approach['language']}\n{approach['after']}\n```\n\n"
        )

    fix_md += (
        f"### 验证步骤\n\n"
        f"{info['verification']}\n\n"
        f"### 临时缓解\n\n"
        f"{info['mitigation']}\n\n"
        f"---\n"
        f"*此建议由哨兵安全平台模拟生成，配置 AI 服务后可获得更精准的修复方案。*"
    )

    code_examples = [
        {
            "title": a["title"],
            "before": a["before"],
            "after": a["after"],
            "language": a["language"]
        }
        for a in info["fix_approaches"]
    ]

    return {"suggestion": fix_md, "code_examples": code_examples}


def _build_chat_fallback(message: str, context: dict) -> str:
    """Local rule-engine fallback for /chat when AI service is unreachable."""
    msg_lower = message.lower()

    # Keyword-based response routing
    if any(kw in msg_lower for kw in ["sql注入", "sqli", "注入"]):
        return (
            "## SQL 注入防护建议\n\n"
            "SQL 注入是 OWASP Top 10 中最危险的漏洞之一。核心防御措施：\n\n"
            "**1. 使用参数化查询（首选）**\n"
            "```python\n# 危险写法\ncursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
            "# 安全写法\ncursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n```\n\n"
            "**2. 使用 ORM**\n"
            "```python\nUser.query.filter_by(id=user_id).first()\n```\n\n"
            "**3. 额外防护**\n"
            "- WAF 规则拦截 SQL 注入模式\n"
            "- 数据库账户最小权限\n"
            "- 输入长度和类型校验\n\n"
            "> ⚠ AI 服务当前不可达，以上为本地规则引擎回复。配置可用的 AI 服务后将提供更精准的分析。"
        )

    if any(kw in msg_lower for kw in ["xss", "跨站脚本", "跨站"]):
        return (
            "## XSS（跨站脚本攻击）防护建议\n\n"
            "**核心防御：输出编码 + CSP**\n\n"
            "**1. HTML 转义**\n"
            "```python\nfrom markupsafe import escape\nreturn f'<div>{escape(user_input)}</div>'\n```\n\n"
            "**2. CSP 安全策略**\n"
            "```nginx\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self'\";\n```\n\n"
            "**3. Cookie 安全**\n"
            "- HttpOnly: 防 JavaScript 读取\n"
            "- Secure: 仅 HTTPS 传输\n"
            "- SameSite=Strict: 防 CSRF 携带\n\n"
            "> ⚠ AI 服务当前不可达，以上为本地规则引擎回复。"
        )

    if any(kw in msg_lower for kw in ["命令注入", "rce", "命令执行", "os.system"]):
        return (
            "## 命令注入防护建议\n\n"
            "**核心原则：永远不要将用户输入拼入 shell 命令**\n\n"
            "**1. 使用 subprocess 参数化**\n"
            "```python\nimport subprocess\n# 危险\nos.system(f'ping {user_input}')\n# 安全\nsubprocess.run(['ping', '-c', '4', user_input], shell=False)\n```\n\n"
            "**2. 输入白名单**\n"
            "- 仅允许字母、数字、连字符等安全字符\n"
            "- 禁用 `shell=True`（除非绝对必要）\n\n"
            "**3. 最小权限运行**\n"
            "- 应用以非 root 用户运行\n"
            "- 容器内禁用 CAP_SYS_ADMIN 等特权\n\n"
            "> ⚠ AI 服务当前不可达，以上为本地规则引擎回复。"
        )

    if any(kw in msg_lower for kw in ["csrf", "跨站请求伪造", "token"]):
        return (
            "## CSRF 防护建议\n\n"
            "**1. CSRF Token（服务端验证）**\n"
            "```python\nfrom flask_wtf.csrf import CSRFProtect\ncsrf = CSRFProtect(app)\n```\n\n"
            "**2. SameSite Cookie**\n"
            "```python\nresponse.set_cookie('session', token, samesite='Strict', secure=True, httponly=True)\n```\n\n"
            "**3. 自定义 Header 验证**\n"
            "关键操作检查 `X-Requested-With` 或自定义 header\n\n"
            "> ⚠ AI 服务当前不可达，以上为本地规则引擎回复。"
        )

    if any(kw in msg_lower for kw in ["认证", "登录", "密码", "jwt", "session"]):
        return (
            "## 身份认证安全建议\n\n"
            "**1. 密码存储**\n"
            "```\n# 禁止：MD5/SHA256 单次哈希\nhashlib.sha256(password)  # ❌\n# 推荐：bcrypt/Argon2\nbcrypt.hashpw(pwd.encode(), bcrypt.gensalt())  # ✅\n```\n\n"
            "**2. JWT 最佳实践**\n"
            "- 使用强密钥（≥256 bit）\n"
            "- 设置合理过期时间（access: 15min, refresh: 7d）\n"
            "- 包含 `iat`、`exp`、`jti` 标准声明\n\n"
            "**3. Session 安全**\n"
            "- 登录后重新生成 session ID\n"
            "- 多设备登录支持强制踢出\n"
            "- 敏感操作要求二次验证（MFA）\n\n"
            "> ⚠ AI 服务当前不可达，以上为本地规则引擎回复。"
        )

    if any(kw in msg_lower for kw in ["你好", "hello", "hi", "你是谁", "帮助", "help", "能做什么"]):
        return (
            "👋 你好！我是「哨兵」应用安全平台的 **AI 安全顾问**。\n\n"
            "**我可以帮你：**\n"
            "- 📊 分析漏洞的攻击路径和利用难度\n"
            "- 🔧 提供具体的修复方案和代码示例\n"
            "- 🛡️ 解答 OWASP Top 10 相关安全问题\n"
            "- 📝 给出 DevSecOps 流程建议\n\n"
            "**使用方式：**\n"
            "- 直接描述你的安全问题（如 \"如何防止 SQL 注入\"）\n"
            "- 在左侧选择一个漏洞关联后提问，我会结合漏洞上下文回答\n\n"
            "**注意：** 当前 AI 服务未连通，我在使用本地规则引擎为你解答。"
            "如需更精准的分析，请检查 Ollama/AI 服务是否正常运行。\n"
            "配置方法：修改 `.env` 文件中的 `SENTINEL_AI_BASE` 地址。"
        )

    # Generic security response
    return (
        f"感谢你的问题：「{message}」\n\n"
        "我理解你关心的是应用安全问题。以下是一些通用的安全最佳实践建议：\n\n"
        "**1. 输入验证与净化**\n"
        "- 所有用户输入都应视为不可信\n"
        "- 服务端做白名单校验（而非黑名单）\n"
        "- 输出时进行编码转义\n\n"
        "**2. 认证与授权**\n"
        "- 密码使用 bcrypt/Argon2 哈希\n"
        "- API 使用 Token + 过期机制\n"
        "- 关键操作做权限校验\n\n"
        "**3. 依赖管理**\n"
        "- 定期更新依赖版本\n"
        "- 使用 SCA 工具扫描已知 CVE\n"
        "- 启用 Dependabot 自动更新提醒\n\n"
        "**4. 日志与监控**\n"
        "- 记录安全相关事件（登录失败、权限变更）\n"
        "- 敏感信息不写入日志\n"
        "- 设置异常行为告警\n\n"
        "如果你有具体的安全场景需要分析，欢迎详细描述！\n\n"
        "> ⚠ AI 服务当前不可达，以上为本地规则引擎回复。配置可用的 AI 服务后可获得更精准的回答。"
    )


# ---------------------------------------------------------------------------
# Fetch vulnerability with scan info
# ---------------------------------------------------------------------------

def _fetch_vulnerability(vuln_id: int) -> dict | None:
    db = get_db()
    row = db.execute(
        "SELECT v.*, s.tool_type as tool_name, s.tool_type as scan_type, "
        "s.started_at, s.finished_at as completed_at "
        "FROM vulnerabilities v "
        "LEFT JOIN scan_tasks s ON v.scan_id = s.id "
        "WHERE v.id = ?",
        (vuln_id,)
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def _fetch_project(project_id: int) -> dict | None:
    db = get_db()
    row = db.execute(
        "SELECT * FROM projects WHERE id = ?",
        (project_id,)
    ).fetchone()
    if row is None:
        return None
    return dict(row)


# ---------------------------------------------------------------------------
# 1. POST /analyze-vulnerability
# ---------------------------------------------------------------------------

@ai_bp.route('/analyze-vulnerability', methods=['POST'])
@login_required
def analyze_vulnerability():
    try:
        data = request.get_json(silent=True) or {}
        vuln_id = data.get('vulnerability_id')
        if vuln_id is None:
            return jsonify({"error": "vulnerability_id is required"}), 400

        vuln = _fetch_vulnerability(int(vuln_id))
        if vuln is None:
            return jsonify({"error": "Vulnerability not found"}), 404

        if not AI_ENABLED:
            result = _build_simulated_analysis(vuln)
            return jsonify(result)

        # Build prompt for real AI analysis
        vuln_summary = (
            f"漏洞标题: {vuln.get('title', 'N/A')}\n"
            f"严重性: {vuln.get('severity', 'N/A')}\n"
            f"CWE ID: {vuln.get('cwe_id', 'N/A')}\n"
            f"漏洞类型: {vuln.get('vuln_type', 'N/A')}\n"
            f"描述: {vuln.get('description', 'N/A')}\n"
            f"文件路径: {vuln.get('file_path', 'N/A')}\n"
            f"行号: {vuln.get('line_number', 'N/A')}\n"
            f"扫描工具: {vuln.get('tool_name', 'N/A')}\n"
        )

        # ── Simplified prompt for small models (e.g. qwen3:0.6b) ──
        system_prompt = (
            "你是安全分析专家。用中文分析漏洞，输出格式如下：\n\n"
            "## 严重性评估\n（风险等级和评分）\n"
            "## 攻击路径\n（攻击者如何利用此漏洞，分步骤）\n"
            "## 利用难度\n（技术门槛评估）\n"
            "## 业务影响\n（对数据/服务/声誉/合规/财务的影响）\n"
            "## 修复建议\n（优先级和具体措施）\n\n"
            "最后一行写：风险评分: XX（0-100整数）"
        )

        user_prompt = f"漏洞信息：{vuln.get('title','')} | 级别:{vuln.get('severity','')} | 类型:{vuln.get('vuln_type','')} | CWE:{vuln.get('cwe_id','')}\n描述：{vuln.get('description','N/A')}"

        ai_response = call_ai(system_prompt, user_prompt)

        # Extract risk score from response
        risk_score = _severity_to_score(vuln.get('severity', 'medium'))
        for line in ai_response.split('\n'):
            line = line.strip()
            if line.startswith('风险评分:'):
                try:
                    risk_score = int(line.split(':')[1].strip())
                    risk_score = max(0, min(100, risk_score))
                except ValueError:
                    pass

        if ai_response.startswith("[AI Error]"):
            result = _build_simulated_analysis(vuln)
            result["analysis"] += f"\n\n> ⚠ AI 服务调用失败：{ai_response}\n> 已回退为模拟分析。"
            return jsonify(result)

        # ═══════════════════════════════════════════════════════
        # HYBRID MODE: Always enrich with structured sections
        # Even small-model AI gets the rich visualization treatment
        # ═══════════════════════════════════════════════════════
        simulated = _build_simulated_analysis(vuln)
        analysis_sections = simulated.get("analysis_sections", {})

        # Merge AI's actual text into the structured data so user sees both
        # Store full AI response as an extra field for reference
        return jsonify({
            "analysis": ai_response,
            "analysis_sections": analysis_sections,
            "risk_score": risk_score,
            "ai_model": AI_MODEL,
            "_ai_raw": ai_response  # keep raw for debugging
        })
    except Exception as e:
        import traceback
        traceback.print_exc()  # 仅服务端日志
        return jsonify({"error": "AI 分析服务暂时不可用，请稍后重试"}), 500


# ---------------------------------------------------------------------------
# 2. POST /fix-suggestion
# ---------------------------------------------------------------------------

@ai_bp.route('/fix-suggestion', methods=['POST'])
@login_required
def fix_suggestion():
    data = request.get_json(silent=True) or {}
    vuln_id = data.get('vulnerability_id')
    if vuln_id is None:
        return jsonify({"error": "vulnerability_id is required"}), 400

    vuln = _fetch_vulnerability(int(vuln_id))
    if vuln is None:
        return jsonify({"error": "Vulnerability not found"}), 404

    if not AI_ENABLED:
        result = _build_simulated_fix(vuln)
        return jsonify(result)

    vuln_summary = (
        f"漏洞标题: {vuln.get('title', 'N/A')}\n"
        f"严重性: {vuln.get('severity', 'N/A')}\n"
        f"CWE ID: {vuln.get('cwe_id', 'N/A')}\n"
        f"漏洞类型: {vuln.get('vuln_type', 'N/A')}\n"
        f"描述: {vuln.get('description', 'N/A')}\n"
        f"文件路径: {vuln.get('file_path', 'N/A')}\n"
        f"代码片段: {vuln.get('code_snippet', 'N/A')}\n"
        f"行号: {vuln.get('line_number', 'N/A')}\n"
    )

    system_prompt = (
        "你是「哨兵」应用安全平台的安全修复专家。请对以下漏洞提供详细的修复建议，使用中文输出。\n"
        "修复建议应包括：\n"
        "1. 根因分析 — 解释漏洞产生的根本原因\n"
        "2. 多种修复方案 — 提供至少 2-3 种修复方法，每种包含代码示例（修复前/修复后）\n"
        "3. 验证步骤 — 说明如何验证修复是否有效\n\n"
        "对于每种修复方案，请使用以下格式输出代码示例：\n"
        "【方案标题】\n"
        "修复前代码:\n```\n代码内容\n```\n修复后代码:\n```\n代码内容\n```\n语言: xxx"
    )

    user_prompt = f"请为以下漏洞提供修复建议：\n\n{vuln_summary}"

    ai_response = call_ai(system_prompt, user_prompt)

    # Parse code examples from AI response
    code_examples = []
    lines = ai_response.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith('【') and line.endswith('】'):
            title = line[1:-1]
            before_code = ""
            after_code = ""
            language = ""
            # Find before block
            while i < len(lines) and '修复前代码' not in lines[i]:
                i += 1
            i += 1
            if i < len(lines) and lines[i].strip().startswith('```'):
                lang_hint = lines[i].strip()[3:].strip()
                i += 1
                while i < len(lines) and not lines[i].strip().startswith('```'):
                    before_code += lines[i] + '\n'
                    i += 1
            # Find after block
            while i < len(lines) and '修复后代码' not in lines[i]:
                i += 1
            i += 1
            if i < len(lines) and lines[i].strip().startswith('```'):
                language = lines[i].strip()[3:].strip() or lang_hint or "text"
                i += 1
                while i < len(lines) and not lines[i].strip().startswith('```'):
                    after_code += lines[i] + '\n'
                    i += 1
            # Find language line
            while i < len(lines) and '语言:' not in lines[i]:
                i += 1
            if i < len(lines):
                language = lines[i].strip().split(':')[1].strip() or language
            if before_code.strip() or after_code.strip():
                code_examples.append({
                    "title": title,
                    "before": before_code.strip(),
                    "after": after_code.strip(),
                    "language": language
                })
        i += 1

    if ai_response.startswith("[AI Error]"):
        result = _build_simulated_fix(vuln)
        result["suggestion"] += f"\n\n> ⚠ AI 服务调用失败：{ai_response}\n> 已回退为模拟建议。"
        return jsonify(result)

    return jsonify({
        "suggestion": ai_response,
        "code_examples": code_examples
    })


# ---------------------------------------------------------------------------
# 3. POST /chat
# ---------------------------------------------------------------------------

@ai_bp.route('/chat', methods=['POST'])
@login_required
def chat():
    data = request.get_json(silent=True) or {}
    message = data.get('message', '').strip()
    if not message:
        return jsonify({"error": "message is required"}), 400

    context = data.get('context') or {}

    if not AI_ENABLED:
        return jsonify({
            "reply": "AI 服务未配置，请设置 `SENTINEL_AI_API_KEY` 环境变量后重启服务。\n\n"
                     "当前哨兵平台可在无 AI 模式下运行，漏洞分析和修复建议将以模拟数据提供。\n\n"
                     "配置步骤：\n"
                     "1. 在环境变量中设置 `SENTINEL_AI_API_KEY`（OpenAI 或兼容 API 的密钥）\n"
                     "2. 如使用非 OpenAI 服务，同时设置 `SENTINEL_AI_BASE` 和 `SENTINEL_AI_MODEL`\n"
                     "3. 重启哨兵后端服务"
        })

    # Build system prompt
    system_prompt = (
        "你是「哨兵」应用安全平台的 AI 安全专家。你的角色是帮助开发人员和安全工程师理解和修复应用安全漏洞。\n\n"
        "你的专长包括：\n"
        "- 漏洞分析与风险评估\n"
        "- 代码安全审查与修复方案\n"
        "- 安全架构设计与最佳实践\n"
        "- OWASP Top 10、CWE、CVE 知识库\n"
        "- DevSecOps 流程建议\n\n"
        "回答原则：\n"
        "1. 使用中文回答\n"
        "2. 提供具体、可操作的建议，而非泛泛而谈\n"
        "3. 当涉及代码修复时，给出 before/after 示例\n"
        "4. 对不确定的内容明确标注，避免误导\n"
        "5. 优先关注最有效的修复方案，而非列举所有可能性"
    )

    # Append context data
    context_parts = []
    vuln_id = context.get('vulnerability_id')
    project_id = context.get('project_id')

    if vuln_id:
        vuln = _fetch_vulnerability(int(vuln_id))
        if vuln:
            context_parts.append(
                f"当前讨论的漏洞信息：\n"
                f"- 标题: {vuln.get('title', 'N/A')}\n"
                f"- 严重性: {vuln.get('severity', 'N/A')}\n"
                f"- CWE ID: {vuln.get('cwe_id', 'N/A')}\n"
                f"- 类型: {vuln.get('vuln_type', 'N/A')}\n"
                f"- 文件: {vuln.get('file_path', 'N/A')}\n"
                f"- 行号: {vuln.get('line_number', 'N/A')}\n"
                f"- 描述: {vuln.get('description', 'N/A')}\n"
            )

    if project_id:
        project = _fetch_project(int(project_id))
        if project:
            context_parts.append(
                f"当前项目信息：\n"
                f"- 名称: {project.get('name', 'N/A')}\n"
                f"- 语言: {project.get('language', 'N/A')}\n"
                f"- 框架: {project.get('framework', 'N/A')}\n"
            )

    if context_parts:
        system_prompt += "\n\n" + "\n\n".join(context_parts)

    user_prompt = message
    ai_response = call_ai(system_prompt, user_prompt, timeout=10)

    # Estimate tokens (rough)
    total_chars = len(system_prompt) + len(user_prompt) + len(ai_response)
    tokens_used = total_chars // 4  # rough approximation for mixed CJK/ASCII

    if ai_response.startswith("[AI Error]"):
        # ── Graceful fallback: use local rule engine when AI unreachable ──
        fallback_reply = _build_chat_fallback(message, context)
        return jsonify({
            "reply": fallback_reply,
            "tokens_used": 0,
            "_fallback": True,
        })

    # 持久化：保存用户提问 + AI 回复到 ai_chat_history
    try:
        user_id = getattr(request, 'current_user_id', None)
        if user_id is not None:
            db = get_db()
            db.execute(
                "INSERT INTO ai_chat_history (user_id, role, content, vuln_id, project_id, tokens_used) "
                "VALUES (?, 'user', ?, ?, ?, 0)",
                (user_id, message, vuln_id, project_id)
            )
            db.execute(
                "INSERT INTO ai_chat_history (user_id, role, content, vuln_id, project_id, tokens_used) "
                "VALUES (?, 'assistant', ?, ?, ?, ?)",
                (user_id, ai_response, vuln_id, project_id, tokens_used)
            )
            db.commit()
    except Exception as e:
        # 落库失败不影响正常返回
        logger.error(f"[AI chat history] 保存失败: {e}")

    return jsonify({
        "reply": ai_response,
        "tokens_used": tokens_used
    })


# ---------------------------------------------------------------------------
# 3b. GET /history  — 拉取当前用户的历史对话
#     DELETE /history — 清空当前用户的历史对话
# ---------------------------------------------------------------------------

@ai_bp.route('/history', methods=['GET'])
@login_required
def get_history():
    user_id = request.current_user_id
    try:
        limit = int(request.args.get('limit', 200))
    except (TypeError, ValueError):
        limit = 200
    limit = max(1, min(limit, 1000))

    db = get_db()
    rows = db.execute(
        "SELECT id, role, content, vuln_id, project_id, tokens_used, created_at "
        "FROM ai_chat_history WHERE user_id=? ORDER BY id ASC LIMIT ?",
        (user_id, limit)
    ).fetchall()

    messages = [{
        "id": r["id"],
        "role": r["role"],
        "content": r["content"],
        "vuln_id": r["vuln_id"],
        "project_id": r["project_id"],
        "tokens_used": r["tokens_used"],
        "created_at": r["created_at"],
    } for r in rows]

    return jsonify({"messages": messages, "total": len(messages)})


@ai_bp.route('/history', methods=['DELETE'])
@admin_required
def clear_history():
    user_id = request.current_user_id
    db = get_db()
    db.execute("DELETE FROM ai_chat_history WHERE user_id=?", (user_id,))
    db.commit()
    return jsonify({"success": True, "message": "历史对话已清空"})


# ---------------------------------------------------------------------------
# 3.5 多供应商管理（CRUD / 激活 / 测试）
# ---------------------------------------------------------------------------

def _serialize_provider(row) -> dict:
    raw_key = row['api_key'] or ''
    masked = '****' if raw_key else ''
    return {
        'id': row['id'],
        'name': row['name'],
        'provider_type': row['provider_type'],
        'api_base': row['api_base'],
        'model': row['model'],
        'api_key': masked,
        'is_active': bool(row['is_active']),
        'created_at': row['created_at'],
        'updated_at': row['updated_at'],
    }


@ai_bp.route('/providers', methods=['GET'])
@login_required
def list_providers():
    """GET /api/ai/providers — 列出所有已配置的 AI 供应商（api_key 掩码）。"""
    db = get_db()
    _ensure_ai_providers(db)
    rows = db.execute('SELECT * FROM ai_providers ORDER BY is_active DESC, id').fetchall()
    return jsonify([_serialize_provider(r) for r in rows])


@ai_bp.route('/providers', methods=['POST'])
@admin_required
def create_provider():
    """POST /api/ai/providers — 新增供应商。首个供应商自动激活。"""
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get('name') or '').strip()
    ptype = (data.get('provider_type') or 'openai').strip().lower()
    api_base = (data.get('api_base') or '').strip()
    model = (data.get('model') or '').strip()
    api_key = (data.get('api_key') or '').strip()
    if not name or not api_base or not model:
        return jsonify({'error': '名称、API 地址、模型名称均为必填'}), 400
    if ptype not in ('ollama', 'openai', 'azure'):
        return jsonify({'error': 'provider_type 仅支持 ollama / openai / azure'}), 400

    now = datetime.now().isoformat()
    stored_key = encrypt(api_key) if api_key else ''
    db = get_db()
    _ensure_ai_providers(db)
    count = db.execute('SELECT COUNT(*) AS c FROM ai_providers').fetchone()['c']
    is_active = 1 if count == 0 else 0
    db.execute(
        '''INSERT INTO ai_providers (name, provider_type, api_base, model, api_key, is_active, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
        (name, ptype, api_base, model, stored_key, is_active, now, now)
    )
    db.commit()
    new_id = db.execute('SELECT last_insert_rowid() AS id').fetchone()['id']
    return jsonify({'message': '供应商已添加', 'id': new_id, 'is_active': bool(is_active)}), 201


@ai_bp.route('/providers/<int:pid>', methods=['PUT'])
@admin_required
def update_provider(pid: int):
    """PUT /api/ai/providers/<id> — 更新供应商配置。"""
    data = request.get_json(force=True, silent=True) or {}
    db = get_db()
    _ensure_ai_providers(db)
    row = db.execute('SELECT * FROM ai_providers WHERE id=?', (pid,)).fetchone()
    if not row:
        return jsonify({'error': '供应商不存在'}), 404

    name = (data.get('name') or row['name']).strip()
    ptype = (data.get('provider_type') or row['provider_type']).strip().lower()
    api_base = (data.get('api_base') or row['api_base']).strip()
    model = (data.get('model') or row['model']).strip()
    raw_key = (data.get('api_key') or '').strip()
    if not name or not api_base or not model:
        return jsonify({'error': '名称、API 地址、模型名称均为必填'}), 400
    if ptype not in ('ollama', 'openai', 'azure'):
        return jsonify({'error': 'provider_type 仅支持 ollama / openai / azure'}), 400

    # api_key 处理：传 '****' 或不传则保留原值；传新值则加密存储
    if raw_key and raw_key != '****':
        stored_key = encrypt(raw_key)
    else:
        stored_key = row['api_key']

    now = datetime.now().isoformat()
    db.execute(
        '''UPDATE ai_providers SET name=?, provider_type=?, api_base=?, model=?, api_key=?, updated_at=?
           WHERE id=?''',
        (name, ptype, api_base, model, stored_key, now, pid)
    )
    db.commit()
    return jsonify({'message': '供应商已更新'})


@ai_bp.route('/providers/<int:pid>', methods=['DELETE'])
@admin_required
def delete_provider(pid: int):
    """DELETE /api/ai/providers/<id> — 删除供应商。"""
    db = get_db()
    _ensure_ai_providers(db)
    row = db.execute('SELECT * FROM ai_providers WHERE id=?', (pid,)).fetchone()
    if not row:
        return jsonify({'error': '供应商不存在'}), 404
    db.execute('DELETE FROM ai_providers WHERE id=?', (pid,))
    db.commit()
    return jsonify({'message': '供应商已删除'})


@ai_bp.route('/providers/<int:pid>/activate', methods=['POST'])
@admin_required
def activate_provider(pid: int):
    """POST /api/ai/providers/<id>/activate — 设为激活供应商（运行时切换，无需重启）。"""
    db = get_db()
    _ensure_ai_providers(db)
    row = db.execute('SELECT id FROM ai_providers WHERE id=?', (pid,)).fetchone()
    if not row:
        return jsonify({'error': '供应商不存在'}), 404
    db.execute('UPDATE ai_providers SET is_active=0')
    db.execute('UPDATE ai_providers SET is_active=1 WHERE id=?', (pid,))
    db.commit()
    return jsonify({'message': '已切换为激活供应商', 'active_id': pid})


@ai_bp.route('/providers/<int:pid>/test', methods=['POST'])
@login_required
def test_provider(pid: int):
    """POST /api/ai/providers/<id>/test — 临时用该供应商做一次极小调用，验证连通性与鉴权。"""
    db = get_db()
    _ensure_ai_providers(db)
    row = db.execute('SELECT provider_type, api_base, model, api_key FROM ai_providers WHERE id=?', (pid,)).fetchone()
    if not row:
        return jsonify({'error': '供应商不存在'}), 404

    raw_key = row['api_key'] or ''
    key = decrypt(raw_key) if raw_key.startswith('aes256:') else raw_key
    ptype = row['provider_type']
    base = row['api_base']
    model = row['model']
    reachable = False
    reply_ok = False
    detail = ''
    try:
        import urllib.request
        if ptype == 'ollama':
            root = base.replace('/v1', '').rstrip('/')
            urllib.request.urlopen(urllib.request.Request(f"{root}/api/tags"), timeout=5)
        else:
            urllib.request.urlopen(urllib.request.Request(base, method='GET'), timeout=5)
        reachable = True
    except Exception as e:
        detail = f'连接失败: {str(e)}'

    if reachable:
        try:
            data = json.dumps({
                "model": model,
                "messages": [{"role": "user", "content": "ping"}],
                "temperature": 0,
                "max_tokens": 8,
                "stream": False,
            }).encode()
            url = f"{base}/chat/completions"
            headers = {"Content-Type": "application/json"}
            if ptype != 'ollama':
                headers["Authorization"] = f"Bearer {key}"
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            resp = urllib.request.urlopen(req, timeout=30)
            result = json.loads(resp.read())
            content = result["choices"][0]["message"]["content"]
            reply_ok = bool(content and content.strip())
            detail = f'模型响应: {content.strip()[:60]}'
        except Exception as e:
            detail = f'连接可达但调用失败(可能是 Key/模型名错误): {str(e)}'

    return jsonify({'reachable': reachable, 'reply_ok': reply_ok, 'detail': detail})


# ---------------------------------------------------------------------------
# 4. GET /health — AI 服务健康检查
# ---------------------------------------------------------------------------

@ai_bp.route('/health', methods=['GET'])
def health():
    """Quick AI service health check (no auth required)."""
    healthy = check_ai_health()
    return jsonify({
        "enabled": AI_ENABLED,
        "healthy": healthy,
        "model": AI_MODEL if AI_ENABLED else None,
        "provider": AI_PROVIDER if AI_ENABLED else None,
        "reachable": healthy,  # alias for clarity
    })


# ---------------------------------------------------------------------------
# 5. GET /status
# ---------------------------------------------------------------------------

@ai_bp.route('/status', methods=['GET'])
@login_required
def status():
    cfg = get_active_ai_config()
    base = (cfg['api_base'] or '').lower()
    ptype = cfg['provider']
    # Derive provider display name
    if ptype == 'ollama':
        provider = "Ollama (本地)"
    elif "azure" in base:
        provider = "Azure OpenAI"
    elif "deepseek" in base:
        provider = "DeepSeek"
    elif "moonshot" in base or "kimi" in base:
        provider = "Moonshot"
    elif "qwen" in base or "dashscope" in base:
        provider = "通义千问"
    elif "zhipu" in base or "bigmodel" in base:
        provider = "智谱 GLM"
    elif "baichuan" in base:
        provider = "百川"
    elif "minimax" in base:
        provider = "MiniMax"
    elif "localhost" in base or "127.0.0.1" in base:
        provider = "本地模型"
    else:
        provider = "OpenAI 兼容"

    # Check actual reachability (cached result)
    reachable = check_ai_health()

    return jsonify({
        "enabled": cfg['enabled'],
        "model": cfg['model'],
        "provider": provider,
        "reachable": reachable,
        "api_base": cfg['api_base'],
    })
