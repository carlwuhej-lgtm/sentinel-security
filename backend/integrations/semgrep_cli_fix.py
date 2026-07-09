    def _try_semgrep_cli(self, scan_path: str, lang: str) -> Optional[list]:
        """尝试调用 Semgrep CLI 进行扫描。失败返回 None。"""
        import subprocess, json, shutil, os, sys

        # 1. 查找 semgrep 可执行文件
        semgrep_bin = shutil.which("semgrep")
        if not semgrep_bin:
            # Windows 下尝试常见安装位置
            possible_paths = [
                "C:\\Users\\Jy\\.workbuddy\\binaries\\python\\versions\\3.13.12\\Scripts\\semgrep.exe",
                os.path.join(os.path.dirname(sys.executable), "semgrep.exe"),
                "semgrep.exe",
            ]
            for p in possible_paths:
                if os.path.exists(p):
                    semgrep_bin = p
                    break

        if not semgrep_bin:
            print(f"[Semgrep] CLI not found, falling back to built-in scanner")
            return None

        # 2. 构建扫描命令
        # 使用 auto 规则（自动检测所有适用规则）
        cmd = [semgrep_bin, "--json", "--config", "auto", "--no-git-ignore", scan_path]

        print(f"[Semgrep] Running: {' '.join(cmd)}")

        # 3. 执行扫描
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5分钟超时
                cwd=scan_path if os.path.isdir(scan_path) else None
            )

            # 4. 解析输出
            if result.returncode not in (0, 1):  # 0=找到漏洞, 1=未找到漏洞
                print(f"[Semgrep] CLI error (returncode={result.returncode}): {result.stderr}")
                return None

            if not result.stdout:
                print(f"[Semgrep] No output from Semgrep CLI")
                return None

            data = json.loads(result.stdout)
            findings = data.get("results", [])

            if not findings:
                print(f"[Semgrep] No findings")
                return []  # 返回空列表（不是 None），表示扫描成功但没发现问题

            # 5. 转换为 VulnerabilityResult
            vulns = []
            for f in findings:
                extra = f.get("extra", {})
                metadata = extra.get("metadata", {})

                # 映射严重程度
                sev = extra.get("severity", "WARNING")
                if sev == "ERROR":
                    severity = "critical"
                elif sev == "WARNING":
                    severity = "high"
                else:
                    severity = "medium"

                # 提取 CWE
                cwe_list = metadata.get("cwe", [])
                cwe = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else "N/A"

                vulns.append(VulnerabilityResult(
                    cve_id=self._generate_cve_id("SEM"),
                    title=f.get("check_id", "Unknown"),
                    severity=severity,
                    file_path=f.get("path", ""),
                    line=f.get("start", {}).get("line", 0),
                    description=extra.get("message", "")[:200],
                    cvss_score=8.5 if severity == "critical" else 7.0 if severity == "high" else 5.0,
                    cwe_id=cwe.split(":")[0].strip() if ":" in cwe else cwe,
                    recommendation="See Semgrep rule documentation",
                    confidence="high" if severity in ("critical", "high") else "medium",
                ))

            print(f"[Semgrep] Found {len(vulns)} vulnerabilities")
            return vulns

        except subprocess.TimeoutExpired:
            print(f"[Semgrep] CLI timeout")
            return None
        except json.JSONDecodeError as e:
            print(f"[Semgrep] JSON parse error: {e}")
            return None
        except Exception as e:
            print(f"[Semgrep] Unexpected error: {e}")
            return None
