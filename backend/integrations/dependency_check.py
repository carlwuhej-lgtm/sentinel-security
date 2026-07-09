"""
OWASP Dependency-Check SCA 扫描器
调用 dependency-check CLI 检测依赖中的已知 CVE。真实扫描,无模拟数据。
未安装或失败时返回 failed,绝不编造结果。

注意:OWASP Dependency-Check 是 Java 工具,首次运行会下载 NVD 漏洞库,
耗时较长;需要系统已安装 dependency-check(CLI)。
"""

import json
import os
import shutil
import subprocess
import tempfile
import time

from .base import BaseScanner, ScanResult, VulnerabilityResult


class DependencyCheckScanner(BaseScanner):
    tool_key = "dependency-check"
    tool_name = "Dependency-Check"
    tool_type = "SCA"

    def run(self, project_config: dict) -> ScanResult:
        scan_target = (
            project_config.get("local_path")
            or project_config.get("repo_url")
            or ""
        ).strip().strip('"').strip("'")
        return self._run_real(scan_target)

    def _resolve_bin(self) -> str:
        if self.api_endpoint and os.path.exists(self.api_endpoint):
            return self.api_endpoint
        for name in ("dependency-check", "dependency-check.bat", "dependency-check.sh"):
            found = shutil.which(name)
            if found:
                return found
        return "dependency-check"

    def _run_real(self, scan_target: str) -> ScanResult:
        if not scan_target:
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw="Dependency-Check 扫描失败:项目未配置 local_path/repo_url。",
                status="failed",
            )
        if not os.path.exists(scan_target):
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw=f"Dependency-Check 扫描失败:扫描路径不存在: {scan_target}",
                status="failed",
            )

        dc_bin = self._resolve_bin()
        out_dir = tempfile.mkdtemp(prefix="depcheck_")
        report_json = os.path.join(out_dir, "dependency-check-report.json")
        start = time.time()
        cmd = [
            dc_bin,
            "--scan", scan_target,
            "--format", "JSON",
            "--out", out_dir,
            "--prettyPrint",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=1800,
            )
        except FileNotFoundError:
            shutil.rmtree(out_dir, ignore_errors=True)
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw="Dependency-Check 未安装。请安装后重试: "
                    "https://owasp.org/www-project-dependency-check/",
                status="failed",
            )
        except subprocess.TimeoutExpired:
            shutil.rmtree(out_dir, ignore_errors=True)
            return self._build_scan_result(
                vulns=[], duration_ms=int((time.time() - start) * 1000),
                raw="Dependency-Check 扫描超时(1800s)。首次运行需下载 NVD 库,请稍后重试。",
                status="failed",
            )
        except Exception as exc:
            shutil.rmtree(out_dir, ignore_errors=True)
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw=f"Dependency-Check 执行异常: {exc}", status="failed",
            )

        duration = int((time.time() - start) * 1000)
        try:
            with open(report_json, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except FileNotFoundError:
            shutil.rmtree(out_dir, ignore_errors=True)
            return self._build_scan_result(
                vulns=[], duration_ms=duration,
                raw=f"Dependency-Check 未生成报告 (rc={result.returncode})\n{(result.stderr or '')[:1500]}",
                status="failed",
            )
        except json.JSONDecodeError as exc:
            shutil.rmtree(out_dir, ignore_errors=True)
            return self._build_scan_result(
                vulns=[], duration_ms=duration,
                raw=f"Dependency-Check JSON 解析失败: {exc}", status="failed",
            )

        vulns = self._parse_report(data)
        shutil.rmtree(out_dir, ignore_errors=True)
        return self._build_scan_result(
            vulns=vulns, duration_ms=duration,
            raw=f"[Dependency-Check] path={scan_target}; findings={len(vulns)}; duration_ms={duration}",
            status="completed",
        )

    def _parse_report(self, data: dict) -> list:
        """解析 dependency-check JSON 报告的 dependencies[].vulnerabilities[]。"""
        vulns = []
        seen = set()
        for dep in data.get("dependencies") or []:
            file_name = dep.get("fileName") or dep.get("filePath") or "dependency"
            for v in dep.get("vulnerabilities") or []:
                cve = v.get("name") or "UNKNOWN"
                key = (cve, file_name)
                if key in seen:
                    continue
                seen.add(key)
                sev, cvss = self._extract_severity(v)
                cwes = v.get("cwes") or []
                cwe = cwes[0] if cwes else "N/A"
                vulns.append(VulnerabilityResult(
                    cve_id=cve,
                    title=f"{file_name} — {cve}"[:250],
                    severity=sev,
                    file_path=file_name,
                    line=0,
                    description=(v.get("description") or cve)[:1000],
                    cvss_score=cvss,
                    cwe_id=cwe,
                    recommendation="升级到不受影响的依赖版本;参考 CVE 公告与厂商补丁。",
                    confidence="high",
                ))
        return vulns

    @staticmethod
    def _extract_severity(v: dict):
        """从 dependency-check 漏洞条目提取严重度与 CVSS。"""
        cvss_score = 5.0
        for key in ("cvssv3", "cvssv2"):
            block = v.get(key) or {}
            score = block.get("baseScore") or block.get("score")
            if score:
                try:
                    cvss_score = float(score)
                    break
                except (TypeError, ValueError):
                    continue
        raw_sev = (v.get("severity") or "").upper()
        if raw_sev in ("CRITICAL",):
            return "critical", cvss_score
        if raw_sev in ("HIGH",):
            return "high", cvss_score
        if raw_sev in ("MEDIUM", "MODERATE"):
            return "medium", cvss_score
        if raw_sev in ("LOW",):
            return "low", cvss_score
        # 无明确 severity 时按 CVSS 分档
        if cvss_score >= 9:
            return "critical", cvss_score
        if cvss_score >= 7:
            return "high", cvss_score
        if cvss_score >= 4:
            return "medium", cvss_score
        return "low", cvss_score
