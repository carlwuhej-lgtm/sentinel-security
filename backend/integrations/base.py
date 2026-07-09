"""
基础扫描器 — 所有安全工具的抽象基类

子类只需实现 run() 方法，返回 ScanResult。
框架负责：结果入库、告警通知、统计聚合。
"""

import uuid
import hashlib
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone


@dataclass
class VulnerabilityResult:
    """统一漏洞结果数据结构"""
    cve_id: str          # CVE 编号（模拟则为 SENTINEL-xxxx）
    title: str           # 漏洞标题
    severity: str        # critical / high / medium / low
    file_path: str       # 影响的文件路径
    line: int            # 行号
    description: str     # 详细描述
    cvss_score: float    # CVSS 评分
    cwe_id: str          # CWE 编号
    recommendation: str  # 修复建议
    confidence: str = "high"  # 置信度：high / medium / low

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "severity": self.severity,
            "file_path": self.file_path,
            "line": self.line,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
        }


@dataclass
class ScanResult:
    """扫描结果"""
    scan_id: str
    tool_key: str
    project_name: str
    status: str               # completed / failed
    vulnerabilities: list = field(default_factory=list)
    duration_ms: int = 0
    summary: dict = field(default_factory=dict)
    raw_output: str = ""      # 工具原始输出（供调试）


class BaseScanner(ABC):
    """
    安全扫描器基类

    使用方式：
        scanner = SemgrepScanner(mode="real")
        result = scanner.run(project_config={"local_path": "...", "lang": "python"})
    """

    tool_key: str = "base"
    tool_name: str = "Base"
    tool_type: str = "SAST"   # SAST / SCA / DAST / SECRET

    # 真实运行可执行此命令
    command_template: str = ""

    def __init__(self, mode: str = "real", api_endpoint: str = "", api_key: str = ""):
        """
        Args:
            mode: 运行模式(当前所有扫描器均为真实检测,保留此参数仅为兼容)
            api_endpoint: 工具 API / CLI 路径
            api_key: API 密钥
        """
        self.mode = mode
        self.api_endpoint = api_endpoint
        self.api_key = api_key

    @abstractmethod
    def run(self, project_config: dict) -> ScanResult:
        """执行扫描，子类必须实现"""
        ...

    # ---- 以下为子类可复用的辅助方法 ----

    @staticmethod
    def _generate_cve_id(prefix: str = "SENTINEL") -> str:
        """生成漏洞编号"""
        return f"{prefix}-{random.randint(1000, 9999)}-{uuid.uuid4().hex[:4].upper()}"

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _build_scan_result(self, vulns: list, duration_ms: int = 0,
                           raw: str = "", status: str = "completed") -> ScanResult:
        """构建统一的 ScanResult"""
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulns:
            sev_counts[v.severity] += 1

        return ScanResult(
            scan_id=uuid.uuid4().hex[:12],
            tool_key=self.tool_key,
            project_name="",
            status=status,
            vulnerabilities=vulns,
            duration_ms=duration_ms,
            summary={
                "total": len(vulns),
                "critical": sev_counts["critical"],
                "high": sev_counts["high"],
                "medium": sev_counts["medium"],
                "low": sev_counts["low"],
            },
            raw_output=raw,
        )
