"""Read-only log analysis for Ubuntu authentication and firewall logs."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import subprocess
from typing import Iterable

from .models import LogSummary

# Patterns for OpenSSH & sudo in syslog / journald output
RE_FAILED_PWD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
RE_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
RE_ACCEPTED = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
RE_SUDO = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.+)"
)
RE_UFW_BLOCK = re.compile(
    r"\[UFW BLOCK\].*SRC=(?P<src>[0-9a-fA-F:.]+).*PROTO=(?P<proto>\S+)(?:.*DPT=(?P<dpt>\d+))?"
)
RE_TIMESTAMP = re.compile(
    r"^(?P<ts>(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}))"
)


def _extract_timestamp(line: str) -> str:
    m = RE_TIMESTAMP.match(line.strip())
    return m.group("ts") if m else ""


def _read_tail_lines(path: Path, max_lines: int = 5000, max_bytes: int = 2 * 1024 * 1024) -> list[str]:
    """Read up to the last `max_lines` lines from a log file without loading huge files into RAM."""
    file_size = path.stat().st_size
    with path.open("rb") as f:
        if file_size > max_bytes:
            f.seek(file_size - max_bytes)
            # Discard partial first line after seeking into the middle of the file
            f.readline()
        raw = f.read()
    lines = raw.decode("utf-8", errors="replace").splitlines()
    return lines[-max_lines:]


def _read_journal_ssh(max_lines: int = 2000) -> list[str]:
    """Fallback to journalctl when /var/log/auth.log is absent or empty."""
    for unit in ("ssh", "sshd"):
        try:
            proc = subprocess.run(
                ["journalctl", "-u", unit, "-n", str(max_lines), "--no-pager", "-o", "short-iso"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.splitlines()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return []


def parse_auth_lines(lines: Iterable[str], summary: LogSummary) -> None:
    """Parse auth.log / journald SSH & sudo lines into a LogSummary."""
    failed_ips: Counter[str] = Counter()
    targeted_users: Counter[str] = Counter()
    events: list[dict[str, str]] = []

    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        ts = _extract_timestamp(line)

        m_fail = RE_FAILED_PWD.search(line)
        if m_fail:
            user = m_fail.group("user")
            ip = m_fail.group("ip")
            summary.failed_ssh_attempts += 1
            failed_ips[ip] += 1
            targeted_users[user] += 1
            events.append(
                {
                    "timestamp": ts,
                    "type": "ssh_failed",
                    "source": ip,
                    "summary": f"Password errata per utente '{user}' da {ip}",
                }
            )
            continue

        m_inv = RE_INVALID_USER.search(line)
        if m_inv:
            user = m_inv.group("user")
            ip = m_inv.group("ip")
            summary.invalid_user_attempts += 1
            failed_ips[ip] += 1
            targeted_users[user] += 1
            events.append(
                {
                    "timestamp": ts,
                    "type": "ssh_invalid_user",
                    "source": ip,
                    "summary": f"Tentativo con utente inesistente '{user}' da {ip}",
                }
            )
            continue

        m_acc = RE_ACCEPTED.search(line)
        if m_acc:
            method = m_acc.group("method")
            user = m_acc.group("user")
            ip = m_acc.group("ip")
            summary.accepted_ssh_logins += 1
            events.append(
                {
                    "timestamp": ts,
                    "type": "ssh_accepted",
                    "source": ip,
                    "summary": f"Accesso SSH riuscito ({method}) per '{user}' da {ip}",
                }
            )
            continue

        m_sudo = RE_SUDO.search(line)
        if m_sudo:
            user = m_sudo.group("user")
            cmd = m_sudo.group("cmd").strip()[:120]
            summary.sudo_commands += 1
            events.append(
                {
                    "timestamp": ts,
                    "type": "sudo",
                    "source": user,
                    "summary": f"sudo eseguito da '{user}': {cmd}",
                }
            )

    summary.top_failed_ips = [
        {"ip": ip, "count": count} for ip, count in failed_ips.most_common(10)
    ]
    summary.top_targeted_users = [
        {"user": user, "count": count} for user, count in targeted_users.most_common(10)
    ]
    # Keep the 40 most recent notable events (newest first)
    summary.recent_events = list(reversed(events[-40:]))


def parse_ufw_lines(lines: Iterable[str], summary: LogSummary) -> None:
    """Parse UFW firewall block lines into a LogSummary."""
    blocked_ports: Counter[str] = Counter()

    for raw in lines:
        if "[UFW BLOCK]" not in raw:
            continue
        m = RE_UFW_BLOCK.search(raw)
        if not m:
            continue
        summary.ufw_blocks += 1
        proto = m.group("proto")
        dpt = m.group("dpt") or "n/a"
        blocked_ports[f"{dpt}/{proto.lower()}"] += 1

    summary.top_blocked_ports = [
        {"port": port, "count": count} for port, count in blocked_ports.most_common(10)
    ]


def analyze_system_logs(max_lines: int = 5000) -> LogSummary:
    """Read local Ubuntu auth and firewall logs (read-only)."""
    summary = LogSummary()

    auth_path = Path("/var/log/auth.log")
    auth_lines: list[str] = []

    if auth_path.exists():
        try:
            auth_lines = _read_tail_lines(auth_path, max_lines=max_lines)
            summary.sources_checked.append(str(auth_path))
        except PermissionError:
            summary.warnings.append(
                "Permessi insufficienti per leggere /var/log/auth.log (esegui con sudo o aggiungi l'utente al gruppo adm)."
            )
        except OSError as exc:
            summary.warnings.append(f"Errore lettura /var/log/auth.log: {exc}")
    else:
        journal_lines = _read_journal_ssh(max_lines=max_lines)
        if journal_lines:
            auth_lines = journal_lines
            summary.sources_checked.append("journalctl (ssh/sshd)")
        else:
            summary.warnings.append(
                "Nessun log SSH trovato (/var/log/auth.log assente e journalctl non disponibile o vuoto)."
            )

    if auth_lines:
        parse_auth_lines(auth_lines, summary)

    # Check UFW logs
    ufw_candidates = [Path("/var/log/ufw.log"), Path("/var/log/kern.log")]
    for candidate in ufw_candidates:
        if not candidate.exists():
            continue
        try:
            ufw_lines = _read_tail_lines(candidate, max_lines=max_lines)
            summary.sources_checked.append(str(candidate))
            parse_ufw_lines(ufw_lines, summary)
            break
        except PermissionError:
            summary.warnings.append(
                f"Permessi insufficienti per leggere {candidate} (esegui con sudo o gruppo adm)."
            )
        except OSError as exc:
            summary.warnings.append(f"Errore lettura {candidate}: {exc}")

    return summary
