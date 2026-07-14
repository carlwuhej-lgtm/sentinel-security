"""demo_sec_tips.py — 自定义 skill 示例脚本（由 manifest 的 script runner 调用）。

规则：
- 只从 stdout 输出一个 JSON 对象，后端会原样返回给前端。
- 不读环境变量里的密钥、不出网、不写文件（保持低风险）。
- 想接你自己的逻辑：改这里 + 改 demo-sec-tips.manifest.json 的 id/name 即可。
"""
import json
import sys


def main():
    tips = [
        {"cwe": "CWE-94", "title": "注入 (Injection)",
         "note": "SQLi / 命令注入 / XXE 统一靠参数化查询与输入白名单"},
        {"cwe": "CWE-79", "title": "跨站脚本 (XSS)",
         "note": "输出编码 + CSP + 避免 innerHTML 拼接不可信数据"},
        {"cwe": "CWE-287", "title": "身份鉴别失效 (Broken Auth)",
         "note": "多因素认证、限速、会话固定防护"},
        {"cwe": "CWE-732", "title": "敏感数据暴露 (Sensitive Data)",
         "note": "传输 TLS、存储加密、密钥进 KMS、日志脱敏"},
        {"cwe": "CWE-502", "title": "不安全反序列化 (Insecure Deserialization)",
         "note": "禁止反序列化不可信数据，或做签名/类型白名单"},
        {"cwe": "CWE-918", "title": "服务端请求伪造 (SSRF)",
         "note": "出站 URL 白名单 + 阻断内网地址段"},
        {"cwe": "CWE-862", "title": "权限控制失效 (Broken Access Control)",
         "note": "默认拒绝、对象级鉴权（IDOR 防护）、服务端再校验"},
        {"cwe": "CWE-352", "title": "CSRF",
         "note": "同源幂等令牌 + SameSite Cookie"},
        {"cwe": "CWE-613", "title": "安全配置错误 (Security Misconfig)",
         "note": "关闭调试、最小权限、依赖与镜像基线扫描"},
        {"cwe": "CWE-937", "title": "易受攻击与过时的组件 (Vulnerable Components)",
         "note": "SCA 持续盯版本、及时打补丁、SBOM 管理"},
    ]
    out = {
        "skill": "demo-sec-tips",
        "count": len(tips),
        "items": tips,
        "message": "自定义 skill 运行成功（这是你接入自己逻辑的模板）",
    }
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
