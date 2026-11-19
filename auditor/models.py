"""Data models for the Ubuntu server hardening and log auditor."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .explanations import get_explanation


@dataclass
class CheckResult:
    """Single security hardening check outcome."""

    id: str
    category: str
    title: str
    status: str  # "pass" | "warn" | "fail" | "info"
    severity: str  # "high" | "medium" | "low" | "info"
    details: str
    remediation: str = ""
    evidence: str = ""
    benchmark: str = ""  # e.g. "CIS 5.2.8" or "Lynis SSH-7408"
    remediation_cmd: str = ""  # Optional copyable shell command

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["explanation"] = get_explanation(self.id)
        return data


@dataclass
class ListeningPort:
    """Locally listening network socket discovered via ss."""

    protocol: str
    bind_address: str
    port: str
    process: str
    exposure: str  # "public" | "local" | "vpn_or_private"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LogSummary:
    """Aggregated findings from auth and firewall logs."""

    sources_checked: list[str] = field(default_factory=list)
    failed_ssh_attempts: int = 0
    invalid_user_attempts: int = 0
    accepted_ssh_logins: int = 0
    sudo_commands: int = 0
    ufw_blocks: int = 0
    top_failed_ips: list[dict[str, Any]] = field(default_factory=list)
    top_targeted_users: list[dict[str, Any]] = field(default_factory=list)
    top_blocked_ports: list[dict[str, Any]] = field(default_factory=list)
    recent_events: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    """Complete hardening and log audit report."""

    generated_at: str
    hostname: str
    os_info: str
    kernel: str
    is_root: bool
    is_linux: bool
    demo_mode: bool
    score: int
    summary: dict[str, int]
    checks: list[CheckResult]
    listening_ports: list[ListeningPort]
    logs: LogSummary

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "kernel": self.kernel,
            "is_root": self.is_root,
            "is_linux": self.is_linux,
            "demo_mode": self.demo_mode,
            "score": self.score,
            "summary": self.summary,
            "checks": [c.to_dict() for c in self.checks],
            "listening_ports": [p.to_dict() for p in self.listening_ports],
            "logs": self.logs.to_dict(),
        }


def compute_score(checks: list[CheckResult]) -> tuple[int, dict[str, int]]:
    """Calculate a 0-100 hardening score weighted by severity."""
    counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
    weights = {"high": 15, "medium": 8, "low": 4, "info": 0}

    max_points = 0
    earned_points = 0.0

    for check in checks:
        status = check.status if check.status in counts else "info"
        counts[status] += 1
        weight = weights.get(check.severity, 0)
        if weight == 0 or status == "info":
            continue
        max_points += weight
        if status == "pass":
            earned_points += weight
        elif status == "warn":
            earned_points += weight * 0.4

    if max_points == 0:
        return 100, counts

    score = max(0, min(100, round((earned_points / max_points) * 100)))
    return score, counts
