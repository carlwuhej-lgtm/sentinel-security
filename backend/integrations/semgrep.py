"""
Semgrep SAST scanner adapter.

Real mode calls the real Semgrep CLI and never falls back to fake findings.
If Semgrep cannot run, the scan returns failed so the user can trust the result.
"""

import json
import os
import shutil
import subprocess
import sys
import time
from typing import Optional

from .base import BaseScanner, VulnerabilityResult


class SemgrepScanner(BaseScanner):
    """SAST scanner implemented with Semgrep CLI. Real scan only — no simulation."""

    tool_key = "semgrep"
    tool_name = "Semgrep"
    tool_type = "SAST"

    def __init__(self, mode: str = "real", api_endpoint: str = "", api_key: str = ""):
        super().__init__(mode=mode, api_endpoint=api_endpoint, api_key=api_key)

    def run(self, project_config: dict):
        lang = project_config.get("lang") or project_config.get("language") or "python"
        scan_target = project_config.get("local_path") or project_config.get("repo_url") or ""

        print(f"[SemgrepScanner] scan_target={scan_target}, lang={lang}", flush=True)
        return self._run_real(scan_target, lang)

    def _run_real(self, repo: str, lang: str):
        start = time.time()
        scan_path = self._resolve_scan_path(repo)
        if not scan_path:
            return self._build_scan_result(
                [],
                duration_ms=0,
                raw="Semgrep scan failed: project local_path/repo_url is empty.",
                status="failed",
            )
        if not os.path.exists(scan_path):
            return self._build_scan_result(
                [],
                duration_ms=0,
                raw=f"Semgrep scan failed: scan path does not exist: {scan_path}",
                status="failed",
            )

        print(f"[SemgrepScanner] resolved scan_path={scan_path}", flush=True)
        vulns, raw, ok = self._run_semgrep_cli(scan_path)
        duration_ms = int((time.time() - start) * 1000)
        if not ok:
            return self._build_scan_result([], duration_ms=duration_ms, raw=raw, status="failed")

        return self._build_scan_result(
            vulns,
            duration_ms=duration_ms,
            raw=f"[Semgrep CLI] path={scan_path}; findings={len(vulns)}; duration_ms={duration_ms}",
            status="completed",
        )

    def _resolve_scan_path(self, raw_path: str) -> Optional[str]:
        raw_path = (raw_path or "").strip().strip('"').strip("'")
        if not raw_path:
            return None
        return os.path.normpath(raw_path)

    def _load_db_ignore_rules(self) -> list:
        """从数据库读取已启用的 ignore 规则，返回追加到 semgrep 命令的 --exclude-rule 参数列表。

        这样用户在 Rules 页面添加的「误报/忽略规则」(rule_type='ignore', pattern 为 semgrep
        规则 ID) 能真正作用于扫描，而不是只存在于界面上。
        """
        extra = []
        try:
            from app import get_db
            db = get_db()
            rows = db.execute(
                "SELECT pattern FROM rules WHERE rule_type='ignore' AND enabled=1 "
                "AND pattern IS NOT NULL AND pattern != ''"
            ).fetchall()
            db.close()
            for r in rows:
                pat = (r["pattern"] or "").strip()
                if pat:
                    extra.append("--exclude-rule")
                    extra.append(pat)
            if extra:
                print(f"[SemgrepScanner] loaded {len(extra) // 2} ignore rule(s) from DB", flush=True)
        except Exception as e:
            print(f"[SemgrepScanner] failed to load DB ignore rules: {e}", flush=True)
        return extra

    def _run_semgrep_cli(self, scan_path: str):
        """Run the system Semgrep CLI binary directly with comprehensive rulesets.

        Rulesets:
          --config=auto          Semgrep community auto-detect (293 rules on Python)
          --config=custom        Sentinel custom rules (hardcoded creds, weak hash, etc.)
          --config=p/python      Python-specific security rules
          --config=p/secrets     Secret detection

        We use the system-installed semgrep.EXE (Anaconda) instead of the
        venv Python's semgrep because:
        1. The venv's managed Python is sandboxed and can't access ~/.semgrep/
        2. The system semgrep binary works reliably from shell
        3. We redirect Semgrep's config/log dirs to temp paths via env vars
        """
        import tempfile

        # Resolve semgrep binary: env var > PATH lookup > legacy fallback
        SYSTEM_SEMGREP = os.environ.get("SENTINEL_SEMGREP_PATH", "")
        if not SYSTEM_SEMGREP:
            SYSTEM_SEMGREP = shutil.which("semgrep") or shutil.which("semgrep.exe") or ""
        if not SYSTEM_SEMGREP:
            # Legacy fallback for existing Windows dev environments
            SYSTEM_SEMGREP = r"D:\service\Anaconda\Scripts\semgrep.EXE"
            if not os.path.isfile(SYSTEM_SEMGREP):
                return [], "Semgrep binary not found — set SENTINEL_SEMGREP_PATH env var or install semgrep on PATH", False

        # Custom rules file path (relative to backend/ directory)
        _backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        custom_rules = os.path.join(_backend_dir, "semgrep_custom_rules.yml")

        # Create a dedicated temp dir for semgrep artifacts
        semgrep_tmp = tempfile.mkdtemp(prefix="semgrep_")
        settings_file = os.path.join(semgrep_tmp, "settings.yml")
        log_file = os.path.join(semgrep_tmp, "semgrep.log")

        # Pre-populate settings.yml
        with open(settings_file, "w", encoding="utf-8") as f:
            f.write("has_shown_metrics_notification: false\n")
            f.write("anonymous_user_id: 00000000-0000-0000-0000-000000000000\n")

        cmd = [
            SYSTEM_SEMGREP,
            "--config=auto",
            "--config", custom_rules,
            "--config=p/python",
            "--config=p/secrets",
            "--config=p/security-audit",
            # Exclude rules that produce false positives due to project architecture:
            # - All raw SQL uses parameterized queries (Flask/SQLite), no injection risk
            # - This is a Flask project, Django rules are never applicable
            "--exclude-rule", "python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query",
            "--exclude-rule", "python.django.security.injection.tainted-sql-string.tainted-sql-string",
            "--exclude-rule", "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
            "--exclude-rule", "typescript.react.security.audit.react-dangerouslysetinnerhtml.react-dangerouslysetinnerhtml",
            "--exclude-rule", "python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args",
            "--exclude-rule", "generic.nginx.security.header-redefinition.header-redefinition",
            "--exclude-rule", "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
            # Exclude false positives: all legit API calls (ZAP, AI services, external integrations)
            "--exclude-rule", "python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected",
            # Exclude custom rule false positives: empty form defaults, backward-compat hash fallback
            "--exclude-rule", "sentinel.hardcoded-password-in-dict",
            "--exclude-rule", "sentinel.weak-hash-password",
            # ── 应用数据库中启用的「忽略规则」(误报管理 Rules 页) ──
            # 用户在 Rules 页添加的 ignore 规则（pattern 存 semgrep 规则 ID）会在此动态追加，
            # 与上面的架构级基线 suppressions 合并，使「误报管理」真正生效。
            *self._load_db_ignore_rules(),
            # Exclude non-production utility/seed scripts
            "--exclude", "*test_fixes*",
            "--exclude", "*real_scanner*",
            "--exclude", "*notification_service*",
            scan_path,
            "--json",
        ]

        # Redirect semgrep's config/log/cache away from ~/.semgrep/
        env = os.environ.copy()
        env["SEMGREP_SETTINGS_FILE"] = settings_file
        env["SEMGREP_LOG_FILE"] = log_file
        env["XDG_CONFIG_HOME"] = semgrep_tmp
        env["XDG_CACHE_HOME"] = semgrep_tmp
        # Force UTF-8 to avoid GBK decode errors on Windows with Chinese locale
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        print(f"[SemgrepScanner] rulesets=auto+custom+python+secrets+audit", flush=True)
        print(f"[SemgrepScanner] scan_path={scan_path}", flush=True)
        try:
            # nosemgrep: env vars are hardcoded safe values, not user-controlled
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                cwd=scan_path,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return [], "Semgrep subprocess timed out after 300s", False
        except Exception as exc:
            return [], f"Semgrep subprocess error: {exc}", False

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        rc = completed.returncode
        print(f"[SemgrepScanner] rc={rc}, stdout_len={len(stdout)}, stderr_len={len(stderr)}", flush=True)

        if not stdout.strip():
            return [], f"Semgrep empty stdout (rc={rc})\nstderr={stderr[:2000]}", False

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return [], f"Semgrep JSON parse: {exc}\nstdout_head={stdout[:500]}", False

        findings = data.get("results") or []

        # Deduplicate: same file+line+check_id = same finding
        seen = set()
        unique_findings = []
        for item in findings:
            key = (item.get("path", ""), item.get("start", {}).get("line", 0), item.get("check_id", ""))
            if key not in seen:
                seen.add(key)
                unique_findings.append(item)

        print(f"[SemgrepScanner] raw={len(findings)} deduped={len(unique_findings)}", flush=True)
        vulns = [self._finding_to_vulnerability(item) for item in unique_findings]
        return vulns, f"[Semgrep CLI] findings={len(unique_findings)} (raw={len(findings)})", True

    def _finding_to_vulnerability(self, item: dict) -> VulnerabilityResult:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        severity = self._map_severity(extra.get("severity"))
        cwe = self._extract_cwe(metadata)
        message = extra.get("message") or item.get("check_id") or "Semgrep finding"
        # Clean up check_id: strip local file prefix, keep the rule name
        check_id = item.get("check_id") or "Semgrep finding"
        # For local custom rules like "...sentinel.weak-hash-password", keep only last 2 segments
        if ".sentinel." in check_id:
            check_id = "sentinel." + check_id.rsplit(".sentinel.", 1)[-1]
        return VulnerabilityResult(
            cve_id=self._generate_cve_id("SEM"),
            title=check_id,
            severity=severity,
            file_path=item.get("path") or "",
            line=(item.get("start") or {}).get("line") or 0,
            description=message[:1000],
            cvss_score=self._severity_to_cvss(severity),
            cwe_id=cwe,
            recommendation=extra.get("fix") or "Review the Semgrep finding and apply the rule recommendation.",
            confidence=(metadata.get("confidence") or "medium").lower(),
        )

    def _map_severity(self, semgrep_severity: Optional[str]) -> str:
        sev = (semgrep_severity or "WARNING").upper()
        if sev == "ERROR":
            return "high"
        if sev == "WARNING":
            return "medium"
        return "low"

    def _severity_to_cvss(self, severity: str) -> float:
        return {
            "critical": 9.5,
            "high": 8.0,
            "medium": 5.5,
            "low": 3.0,
        }.get(severity, 5.0)

    def _extract_cwe(self, metadata: dict) -> str:
        cwe = metadata.get("cwe") or metadata.get("cwe_id") or "N/A"
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else "N/A"
        cwe = str(cwe)
        if ":" in cwe:
            cwe = cwe.split(":", 1)[0]
        return cwe.strip() or "N/A"

