"""
CodeQL 语义分析扫描器(增强版实现)

说明:真正的 GitHub CodeQL 需要 database create + analyze 两步,依赖编译环境、
磁盘和时间开销大,本机未部署。为保证"真实可用、零编造",此扫描器改为调用
项目内置的 enhanced_scanner 真实正则引擎(75+ 条 Python/JS 安全规则,覆盖
OWASP Top 10 2021 + CWE Top 25),对 local_path 下的源码做真实静态检测。

如需接入原生 CodeQL,可在此扩展 _run_codeql_cli()。
"""

import os
import time

from .base import BaseScanner, ScanResult, VulnerabilityResult
from .enhanced_scanner import scan_python_files, scan_js_files


class CodeQLScanner(BaseScanner):
    tool_key = "codeql"
    tool_name = "CodeQL"
    tool_type = "SAST"

    def run(self, project_config: dict) -> ScanResult:
        scan_target = (
            project_config.get("local_path")
            or project_config.get("repo_url")
            or ""
        ).strip().strip('"').strip("'")

        if not scan_target:
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw="CodeQL(增强引擎)扫描失败:项目未配置 local_path/repo_url。",
                status="failed",
            )
        if not os.path.exists(scan_target):
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw=f"CodeQL(增强引擎)扫描失败:扫描路径不存在: {scan_target}",
                status="failed",
            )

        start = time.time()
        try:
            py_findings = scan_python_files(scan_target)
            js_findings = scan_js_files(scan_target)
        except Exception as exc:
            return self._build_scan_result(
                vulns=[], duration_ms=int((time.time() - start) * 1000),
                raw=f"CodeQL(增强引擎)执行异常: {exc}", status="failed",
            )

        vulns = [self._to_vuln(f) for f in (py_findings + js_findings)]
        duration = int((time.time() - start) * 1000)
        return self._build_scan_result(
            vulns=vulns, duration_ms=duration,
            raw=f"[CodeQL/enhanced] path={scan_target}; "
                f"py={len(py_findings)} js={len(js_findings)} total={len(vulns)}; "
                f"duration_ms={duration}",
            status="completed",
        )

    def _to_vuln(self, f: dict) -> VulnerabilityResult:
        cvss = float(f.get("cvss") or 5.0)
        return VulnerabilityResult(
            cve_id=self._generate_cve_id("SENTQL"),
            title=f.get("title") or f.get("id") or "Static finding",
            severity=self._cvss_to_severity(cvss),
            file_path=f.get("file") or "",
            line=int(f.get("line") or 0),
            description=(
                f"[规则 {f.get('id')}] {f.get('title')}。"
                f"由 Sentinel 增强静态引擎检测。"
            ),
            cvss_score=cvss,
            cwe_id=f.get("cwe") or "N/A",
            recommendation=f.get("fix") or "参考规则建议修复。",
            confidence=(f.get("conf") or "medium"),
        )

    @staticmethod
    def _cvss_to_severity(cvss: float) -> str:
        if cvss >= 9:
            return "critical"
        if cvss >= 7:
            return "high"
        if cvss >= 4:
            return "medium"
        return "low"
