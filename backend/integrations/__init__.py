"""
应用安全工具集成框架 — 适配器模式
每个安全工具实现统一的 BaseScanner 接口,通过注册表统一调度。
所有扫描器均为真实检测,不使用模拟数据;工具缺失/失败时返回 failed。

  - Semgrep          真实 CLI(SAST)
  - CodeQL           增强正则引擎(SAST,零外部依赖)
  - ZAP              真实 HTTP 主动检测(DAST)
  - Trivy            真实 CLI(SCA,需安装 trivy)
  - Gitleaks         真实 CLI(密钥,需安装 gitleaks)
  - Dependency-Check 真实 CLI(SCA,需安装 dependency-check)
"""

from .base import BaseScanner, ScanResult, VulnerabilityResult
from .semgrep import SemgrepScanner
from .trivy import TrivyScanner
from .zap import ZAPScanner
from .gitleaks import GitleaksScanner
from .dependency_check import DependencyCheckScanner
from .codeql import CodeQLScanner

# 工具注册表：tool_key → scanner 类
REGISTRY = {
    "semgrep":           SemgrepScanner,
    "trivy":             TrivyScanner,
    "zap":               ZAPScanner,
    "gitleaks":          GitleaksScanner,
    "dependency-check":  DependencyCheckScanner,
    "codeql":            CodeQLScanner,
}

__all__ = [
    "BaseScanner", "ScanResult", "VulnerabilityResult",
    "SemgrepScanner", "TrivyScanner", "ZAPScanner",
    "GitleaksScanner", "DependencyCheckScanner", "CodeQLScanner",
    "REGISTRY",
]
