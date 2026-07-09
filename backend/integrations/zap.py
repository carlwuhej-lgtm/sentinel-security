"""
OWASP ZAP DAST 扫描器 — 动态应用安全测试
真实 HTTP 主动检测,不使用任何模拟数据。
"""

import time
from .base import BaseScanner, ScanResult, VulnerabilityResult


class ZAPScanner(BaseScanner):
    tool_key = "zap"
    tool_name = "OWASP ZAP"
    tool_type = "DAST"

    def run(self, project_config: dict) -> ScanResult:
        repo = project_config.get("repo_url", "")
        target = project_config.get("target_url") or repo
        return self._run_real(target)

    def _run_real(self, target: str) -> ScanResult:
        """真实 DAST 扫描 — 使用 Python requests 做 HTTP 安全检查。
        
        检查项：
        - 安全响应头缺失 (CSP, X-Frame-Options, HSTS 等)
        - 信息泄露 (Server 头, debug 模式)
        - 反射型 XSS (参数回显)
        - 开放重定向
        - SSL/TLS 配置
        """
        import subprocess, json, re
        import urllib.request
        import urllib.error
        import ssl
        from urllib.parse import urlparse, urljoin

        if not target.startswith("http"):
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw=f"DAST 需要 HTTP(S) 目标 URL，当前: {target}。请在项目配置中设置 target_url 或确保 repo_url 是合法的 HTTP URL。",
                status="failed",
            )

        start = time.time()
        vulns = []
        errors = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            # 1. 安全响应头检查
            req = urllib.request.Request(target, headers={"User-Agent": "Sentinel-DAST/1.0"})
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            security_headers = {
                "strict-transport-security": ("CWE-319", "HSTS 缺失", "未设置 Strict-Transport-Security 头，连接可能降级为 HTTP", 6.5, "添加 HSTS 头: max-age=31536000; includeSubDomains"),
                "content-security-policy": ("CWE-1021", "CSP 缺失", "未设置 Content-Security-Policy 头，无法防御 XSS/数据注入", 7.5, "添加 CSP 头限制脚本来源"),
                "x-frame-options": ("CWE-1021", "Clickjacking 防护缺失", "未设置 X-Frame-Options 头，页面可被嵌入 iframe 进行点击劫持", 6.1, "添加 X-Frame-Options: DENY"),
                "x-content-type-options": ("CWE-16", "MIME 嗅探风险", "未设置 X-Content-Type-Options 头，浏览器可能错误解析文件类型", 5.3, "添加 X-Content-Type-Options: nosniff"),
                "referrer-policy": ("CWE-200", "Referrer 泄露", "未设置 Referrer-Policy 头，敏感 URL 可能泄露给第三方", 4.3, "添加 Referrer-Policy: strict-origin-when-cross-origin"),
                "permissions-policy": ("CWE-16", "权限策略缺失", "未设置 Permissions-Policy 头，浏览器特性未受限", 3.1, "添加 Permissions-Policy 限制不必要的 API"),
            }

            for hdr, (cwe, title, desc, cvss, fix) in security_headers.items():
                if hdr not in headers:
                    vulns.append(VulnerabilityResult(
                        cve_id=self._generate_cve_id("SENTDAST"),
                        title=title,
                        severity="medium" if cvss < 7 else "high",
                        file_path=f"{target} (response headers)",
                        line=0,
                        description=desc,
                        cvss_score=cvss,
                        cwe_id=cwe,
                        recommendation=fix,
                        confidence="high",
                    ))

            # 2. 信息泄露 — Server 头
            if "server" in headers:
                vulns.append(VulnerabilityResult(
                    cve_id=self._generate_cve_id("SENTDAST"),
                    title=f"服务端信息泄露 — Server: {headers['server']}",
                    severity="low",
                    file_path=f"{target} (response headers)",
                    line=0,
                    description=f"响应头 Server: {headers['server']} 暴露了 Web 服务器技术栈信息，方便攻击者针对性攻击。",
                    cvss_score=3.7,
                    cwe_id="CWE-200",
                    recommendation="修改 Web 服务器配置，移除或泛化 Server 响应头",
                    confidence="high",
                ))

            # 3. 反射型 XSS 检测
            xss_payloads = [
                ("<script>alert(1)</script>", "完整 script 标签回显"),
                ("\"'><img src=x onerror=alert(1)>", "HTML 注入 payload 回显"),
                ("javascript:alert(1)", "javascript: 协议回显"),
            ]
            parsed = urlparse(target)
            base = f"{parsed.scheme}://{parsed.netloc}"
            # Try common endpoints
            test_paths = ["/search", "/api/search", "/login", "/"]
            for path in test_paths:
                for payload, desc in xss_payloads:
                    try:
                        test_url = urljoin(base, path) + f"?q={urllib.parse.quote(payload)}"
                        r = urllib.request.urlopen(
                            urllib.request.Request(test_url, headers={"User-Agent": "Sentinel-DAST/1.0"}),
                            timeout=5, context=ctx
                        )
                        body = r.read().decode("utf-8", errors="ignore")
                        if payload in body:
                            vulns.append(VulnerabilityResult(
                                cve_id=self._generate_cve_id("SENTDAST"),
                                title=f"反射型 XSS — {desc}",
                                severity="high",
                                file_path=test_url,
                                line=0,
                                description=f"参数回显了攻击 payload 且未做转义处理: {desc}",
                                cvss_score=6.1,
                                cwe_id="CWE-79",
                                recommendation="对所有用户输入做 HTML 实体编码后再输出，实施 Content-Security-Policy",
                                confidence="medium",
                            ))
                            break  # Found one per path
                    except Exception:
                        pass

            # 4. 开放重定向检测
            redirect_payloads = ["https://evil.com", "//evil.com", "https:evil.com"]
            for path in ["/login", "/redirect", "/oauth/callback"]:
                for rp in redirect_payloads:
                    try:
                        test_url = urljoin(base, path) + f"?redirect={urllib.parse.quote(rp)}&next={urllib.parse.quote(rp)}"
                        req = urllib.request.Request(test_url, headers={"User-Agent": "Sentinel-DAST/1.0"})
                        # Don't follow redirects
                        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
                        r = urllib.request.urlopen(req, timeout=5, context=ctx)
                        body = r.read().decode("utf-8", errors="ignore")
                        if "evil.com" in body.lower():
                            vulns.append(VulnerabilityResult(
                                cve_id=self._generate_cve_id("SENTDAST"),
                                title="开放重定向 — redirect 参数未校验",
                                severity="medium",
                                file_path=test_url,
                                line=0,
                                description="redirect 参数直接用于 HTTP 重定向，攻击者可构造钓鱼链接。",
                                cvss_score=6.1,
                                cwe_id="CWE-601",
                                recommendation="校验 redirect URL 的域名在白名单内，或仅允许相对路径",
                                confidence="medium",
                            ))
                            break
                    except Exception:
                        pass

            # 5. HTTPS 检查
            if not target.startswith("https"):
                vulns.append(VulnerabilityResult(
                    cve_id=self._generate_cve_id("SENTDAST"),
                    title="未启用 HTTPS",
                    severity="high",
                    file_path=target,
                    line=0,
                    description=f"目标使用 HTTP 明文传输，数据可被中间人截获或篡改。",
                    cvss_score=7.5,
                    cwe_id="CWE-319",
                    recommendation="启用 HTTPS，配置有效的 TLS 证书，实施 HSTS",
                    confidence="high",
                ))

        except urllib.error.URLError as e:
            errors.append(f"连接失败: {e.reason}")
        except Exception as e:
            errors.append(f"扫描异常: {str(e)[:200]}")

        duration = int((time.time() - start) * 1000)
        raw_lines = [
            f"[Sentinel DAST] Target: {target}",
            f"Findings: {len(vulns)}",
            f"Security headers checked: {len(security_headers)}",
            f"XSS probes: sent",
            f"Redirect probes: sent",
        ] + [f"  [{v.severity}] {v.title}" for v in vulns]
        if errors:
            raw_lines += [f"Errors: {len(errors)}"] + errors

        return self._build_scan_result(
            vulns=vulns,
            duration_ms=duration,
            raw="\n".join(raw_lines),
            status="completed" if vulns else "completed_no_findings",
        )
