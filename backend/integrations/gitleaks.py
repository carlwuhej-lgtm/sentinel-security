"""
Gitleaks 密钥泄露扫描器 — 检测源码中的硬编码密钥/Token/密码
调用 gitleaks CLI 做真实检测,无模拟数据。
未安装或失败时返回 failed,绝不编造结果。
"""

import json
import os
import shutil
import subprocess
import tempfile
import time

from .base import BaseScanner, ScanResult, VulnerabilityResult


class GitleaksScanner(BaseScanner):
    tool_key = "gitleaks"
    tool_name = "Gitleaks"
    tool_type = "SECRET"

    def run(self, project_config: dict) -> ScanResult:
        scan_target = (
            project_config.get("local_path")
            or project_config.get("repo_url")
            or ""
        ).strip().strip('"').strip("'")
        return self._run_real(scan_target)

    def _resolve_gitleaks_bin(self) -> str:
        if self.api_endpoint and os.path.exists(self.api_endpoint):
            return self.api_endpoint
        found = shutil.which("gitleaks")
        return found or "gitleaks"

    def _run_real(self, scan_target: str) -> ScanResult:
        if not scan_target:
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw="Gitleaks 扫描失败:项目未配置 local_path/repo_url。",
                status="failed",
            )
        if not os.path.exists(scan_target):
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw=f"Gitleaks 扫描失败:扫描路径不存在: {scan_target}",
                status="failed",
            )

        gitleaks_bin = self._resolve_gitleaks_bin()
        report_fd, report_path = tempfile.mkstemp(prefix="gitleaks_", suffix=".json")
        os.close(report_fd)
        start = time.time()
        # gitleaks 8.x: detect --source <dir> --no-git 扫描目录(非git仓库)
        cmd = [
            gitleaks_bin, "detect",
            "--source", scan_target,
            "--report-format", "json",
            "--report-path", report_path,
            "--no-git",
            "--exit-code", "0",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=300,
            )
        except FileNotFoundError:
            os.path.exists(report_path) and os.remove(report_path)
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw="Gitleaks 未安装。请安装后重试: https://github.com/gitleaks/gitleaks",
                status="failed",
            )
        except subprocess.TimeoutExpired:
            os.path.exists(report_path) and os.remove(report_path)
            return self._build_scan_result(
                vulns=[], duration_ms=int((time.time() - start) * 1000),
                raw="Gitleaks 扫描超时(300s)。", status="failed",
            )
        except Exception as exc:
            os.path.exists(report_path) and os.remove(report_path)
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw=f"Gitleaks 执行异常: {exc}", status="failed",
            )

        duration = int((time.time() - start) * 1000)
        try:
            with open(report_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
            findings = json.loads(content) if content else []
        except FileNotFoundError:
            return self._build_scan_result(
                vulns=[], duration_ms=duration,
                raw=f"Gitleaks 未生成报告 (rc={result.returncode})\n{(result.stderr or '')[:1500]}",
                status="failed",
            )
        except json.JSONDecodeError as exc:
            return self._build_scan_result(
                vulns=[], duration_ms=duration,
                raw=f"Gitleaks JSON 解析失败: {exc}", status="failed",
            )
        finally:
            if os.path.exists(report_path):
                os.remove(report_path)

        vulns = self._parse_findings(findings or [])
        return self._build_scan_result(
            vulns=vulns, duration_ms=duration,
            raw=f"[Gitleaks] path={scan_target}; secrets={len(vulns)}; duration_ms={duration}",
            status="completed",
        )

    def _parse_findings(self, findings: list) -> list:
        """解析 gitleaks JSON 报告。每条含 RuleID/File/StartLine/Secret 等。"""
        vulns = []
        seen = set()
        for item in findings:
            rule = item.get("RuleID") or item.get("Rule") or "secret"
            file_path = item.get("File") or ""
            line = item.get("StartLine") or item.get("startLine") or 0
            desc = item.get("Description") or rule
            key = (file_path, line, rule)
            if key in seen:
                continue
            seen.add(key)
            vulns.append(VulnerabilityResult(
                cve_id=self._generate_cve_id("SENTLK"),
                title=f"密钥泄露 — {desc}"[:250],
                severity="critical" if self._is_high_risk(rule) else "high",
                file_path=file_path,
                line=int(line) if line else 0,
                description=(
                    f"Gitleaks 规则 [{rule}] 命中:检测到疑似硬编码密钥/凭证。"
                    f"匹配内容已脱敏,请人工核实。"
                ),
                cvss_score=9.1 if self._is_high_risk(rule) else 8.0,
                cwe_id="CWE-798",
                recommendation="立即从代码中移除并轮换该凭证,改用环境变量/密钥管理服务注入。",
                confidence="high",
            ))
        return vulns

    @staticmethod
    def _is_high_risk(rule: str) -> bool:
        r = (rule or "").lower()
        return any(k in r for k in ("private-key", "private_key", "rsa", "aws", "gcp", "azure"))
