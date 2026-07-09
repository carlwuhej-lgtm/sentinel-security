"""
Trivy SCA 扫描器 — 软件成分分析
调用 trivy CLI 检测依赖库中的已知 CVE。真实扫描,无模拟数据。
未安装 trivy 或扫描失败时返回 failed,绝不编造结果。
"""

import json
import os
import shutil
import subprocess
import time

from .base import BaseScanner, ScanResult, VulnerabilityResult


class TrivyScanner(BaseScanner):
    tool_key = "trivy"
    tool_name = "Trivy"
    tool_type = "SCA"

    def run(self, project_config: dict) -> ScanResult:
        scan_target = (
            project_config.get("local_path")
            or project_config.get("repo_url")
            or ""
        ).strip().strip('"').strip("'")
        return self._run_real(scan_target)

    def _resolve_trivy_bin(self) -> str:
        """定位 trivy 可执行文件:优先 api_endpoint(工具配置的自定义路径),否则 PATH。"""
        if self.api_endpoint and os.path.exists(self.api_endpoint):
            return self.api_endpoint
        found = shutil.which("trivy")
        return found or "trivy"

    def _run_real(self, scan_target: str) -> ScanResult:
        if not scan_target:
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw="Trivy 扫描失败:项目未配置 local_path/repo_url。",
                status="failed",
            )
        if not os.path.exists(scan_target):
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw=f"Trivy 扫描失败:扫描路径不存在: {scan_target}",
                status="failed",
            )

        trivy_bin = self._resolve_trivy_bin()
        start = time.time()
        cmd = [
            trivy_bin, "fs",
            "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--scanners", "vuln",
            "--quiet",
            scan_target,
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=600,
            )
        except FileNotFoundError:
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw="Trivy 未安装。请安装后重试: https://github.com/aquasecurity/trivy",
                status="failed",
            )
        except subprocess.TimeoutExpired:
            return self._build_scan_result(
                vulns=[], duration_ms=int((time.time() - start) * 1000),
                raw="Trivy 扫描超时(600s)。", status="failed",
            )
        except Exception as exc:
            return self._build_scan_result(
                vulns=[], duration_ms=0,
                raw=f"Trivy 执行异常: {exc}", status="failed",
            )

        duration = int((time.time() - start) * 1000)
        stdout = result.stdout or ""
        if not stdout.strip():
            return self._build_scan_result(
                vulns=[], duration_ms=duration,
                raw=f"Trivy 无输出 (rc={result.returncode})\n{(result.stderr or '')[:1500]}",
                status="failed" if result.returncode not in (0,) else "completed",
            )

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return self._build_scan_result(
                vulns=[], duration_ms=duration,
                raw=f"Trivy JSON 解析失败: {exc}\n{stdout[:500]}",
                status="failed",
            )

        vulns = self._parse_results(data)
        return self._build_scan_result(
            vulns=vulns, duration_ms=duration,
            raw=f"[Trivy] path={scan_target}; findings={len(vulns)}; duration_ms={duration}",
            status="completed",
        )

    def _parse_results(self, data: dict) -> list:
        """解析 trivy JSON 输出为统一漏洞结构。"""
        sev_map = {
            "CRITICAL": "critical", "HIGH": "high",
            "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low",
        }
        vulns = []
        seen = set()
        for target in data.get("Results") or []:
            target_file = target.get("Target") or "dependencies"
            for v in target.get("Vulnerabilities") or []:
                cve = v.get("VulnerabilityID") or "UNKNOWN"
                pkg = v.get("PkgName") or ""
                installed = v.get("InstalledVersion") or ""
                fixed = v.get("FixedVersion") or ""
                key = (cve, pkg, installed, target_file)
                if key in seen:
                    continue
                seen.add(key)

                sev = sev_map.get((v.get("Severity") or "LOW").upper(), "low")
                cvss = self._extract_cvss(v)
                title = v.get("Title") or f"{pkg} {installed} — {cve}"
                cwe_ids = v.get("CweIDs") or []
                cwe = cwe_ids[0] if cwe_ids else "N/A"
                fix = (
                    f"升级 {pkg} 至 {fixed}" if fixed
                    else f"关注 {pkg} 的官方修复版本"
                )
                vulns.append(VulnerabilityResult(
                    cve_id=cve,
                    title=f"{pkg} {installed} — {title}"[:250],
                    severity=sev,
                    file_path=target_file,
                    line=0,
                    description=(v.get("Description") or title)[:1000],
                    cvss_score=cvss,
                    cwe_id=cwe,
                    recommendation=fix,
                    confidence="high",
                ))
        return vulns

    @staticmethod
    def _extract_cvss(v: dict) -> float:
        """从 trivy 的 CVSS 字段提取分数,取任一厂商的 V3Score。"""
        cvss = v.get("CVSS") or {}
        for vendor in cvss.values():
            score = vendor.get("V3Score") or vendor.get("V2Score")
            if score:
                try:
                    return float(score)
                except (TypeError, ValueError):
                    continue
        # 回退:按严重度给个近似分
        return {
            "CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0,
        }.get((v.get("Severity") or "LOW").upper(), 5.0)
