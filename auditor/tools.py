"""Read-only detection of best-practice Ubuntu security tools.

Grounded in CIS Ubuntu Linux Benchmark, Canonical Ubuntu Security Docs, and NIST SP 800-53.
Never installs or modifies anything; only inspects presence/service state and provides
copyable installation commands.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from typing import Any

from .models import SecurityTool

TOOL_CATALOG: list[dict[str, Any]] = [
    {
        "id": "ufw",
        "name": "UFW (Uncomplicated Firewall)",
        "category": "Firewall",
        "priority": "high",
        "packages": ["ufw"],
        "binaries": ["ufw"],
        "service": "ufw",
        "source": "CIS Benchmark 3.5.1 · Canonical Ubuntu",
        "description": "Firewall host-based per applicare una policy 'default deny incoming' e limitare le porte esposte.",
        "install_cmd": "sudo apt update && sudo apt install -y ufw && sudo ufw allow OpenSSH && sudo ufw default deny incoming && sudo ufw enable",
    },
    {
        "id": "auditd",
        "name": "auditd (Linux Audit Daemon)",
        "category": "Auditing & Forensics",
        "priority": "high",
        "packages": ["auditd"],
        "binaries": ["auditd", "auditctl"],
        "service": "auditd",
        "source": "CIS Benchmark 4.1 · NIST AU-2",
        "description": "Registra eventi di sicurezza a livello kernel (modifiche a /etc/passwd, /etc/sudoers, comandi privilegiati) per audit e forensics.",
        "install_cmd": "sudo apt update && sudo apt install -y auditd audispd-plugins && sudo systemctl enable --now auditd",
    },
    {
        "id": "apparmor-utils",
        "name": "AppArmor & apparmor-utils",
        "category": "MAC (Mandatory Access Control)",
        "priority": "high",
        "packages": ["apparmor", "apparmor-utils"],
        "binaries": ["aa-status"],
        "service": "apparmor",
        "source": "CIS Benchmark 1.6.1 · Canonical Ubuntu",
        "description": "Confina i servizi di sistema tramite profili MAC in modalità enforce limitando i danni in caso di compromissione.",
        "install_cmd": "sudo apt update && sudo apt install -y apparmor apparmor-utils && sudo systemctl enable --now apparmor",
    },
    {
        "id": "unattended-upgrades",
        "name": "unattended-upgrades",
        "category": "Patch Management",
        "priority": "high",
        "packages": ["unattended-upgrades"],
        "binaries": ["unattended-upgrade"],
        "service": None,
        "source": "CIS Benchmark 1.9 · Canonical Ubuntu",
        "description": "Applica automaticamente gli aggiornamenti di sicurezza critici dai repository ufficiali Ubuntu riducendo la finestra di esposizione alle CVE.",
        "install_cmd": "sudo apt update && sudo apt install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
    },
    {
        "id": "fail2ban",
        "name": "Fail2ban",
        "category": "IPS / Anti-Brute-Force",
        "priority": "high",
        "packages": ["fail2ban"],
        "binaries": ["fail2ban-client"],
        "service": "fail2ban",
        "source": "Ubuntu Security Best Practice",
        "description": "Monitora i log di autenticazione (SSH, Nginx, ecc.) e banna temporaneamente gli IP che effettuano tentativi ripetuti di brute-force.",
        "install_cmd": "sudo apt update && sudo apt install -y fail2ban && sudo systemctl enable --now fail2ban",
    },
    {
        "id": "aide",
        "name": "AIDE (File Integrity Monitoring)",
        "category": "Integrità File (FIM)",
        "priority": "medium",
        "packages": ["aide"],
        "binaries": ["aide"],
        "service": None,
        "source": "CIS Benchmark 1.3 · NIST SI-7",
        "description": "Crea una baseline crittografica dei binari e file di sistema per rilevare manomissioni non autorizzate o rootkit.",
        "install_cmd": "sudo apt update && sudo apt install -y aide && sudo aideinit",
    },
    {
        "id": "libpam-pwquality",
        "name": "libpam-pwquality",
        "category": "PAM & Credenziali",
        "priority": "medium",
        "packages": ["libpam-pwquality"],
        "binaries": [],
        "service": None,
        "source": "CIS Benchmark 5.4.1",
        "description": "Modulo PAM che impone lunghezza minima e requisiti di complessità per le password degli account locali.",
        "install_cmd": "sudo apt update && sudo apt install -y libpam-pwquality",
    },
    {
        "id": "chrony",
        "name": "Chrony (NTP Time Sync)",
        "category": "Sincronizzazione Oraria",
        "priority": "medium",
        "packages": ["chrony"],
        "binaries": ["chronyc"],
        "service": "chrony",
        "source": "CIS Benchmark 2.1.1 · NIST AU-8",
        "description": "Mantiene l'orologio di sistema sincronizzato in modo affidabile, essenziale per correlazione log, certificati TLS e Kerberos/TOTP.",
        "install_cmd": "sudo apt update && sudo apt install -y chrony && sudo systemctl enable --now chrony",
    },
    {
        "id": "crowdsec",
        "name": "CrowdSec",
        "category": "IPS Collaborativo",
        "priority": "medium",
        "packages": ["crowdsec"],
        "binaries": ["cscli"],
        "service": "crowdsec",
        "source": "Open-Source IPS Best Practice",
        "description": "Motore IPS moderno (alternativa/complemento a Fail2ban) con blocklist condivisa dalla community e bouncer per nftables/iptables.",
        "install_cmd": "curl -s https://install.crowdsec.net | sudo sh && sudo apt install -y crowdsec crowdsec-firewall-bouncer-nftables",
    },
    {
        "id": "lynis",
        "name": "Lynis",
        "category": "Compliance & Hardening Audit",
        "priority": "medium",
        "packages": ["lynis"],
        "binaries": ["lynis"],
        "service": None,
        "source": "CISOfy · Linux Hardening",
        "description": "Strumento di audit approfondito da riga di comando per verificare periodicamente configurazioni, permessi, kernel e conformità.",
        "install_cmd": "sudo apt update && sudo apt install -y lynis",
    },
    {
        "id": "needrestart",
        "name": "needrestart",
        "category": "Patch Management",
        "priority": "low",
        "packages": ["needrestart"],
        "binaries": ["needrestart"],
        "service": None,
        "source": "Ubuntu Server Best Practice",
        "description": "Identifica automaticamente demoni e librerie obsoleti ancora in memoria dopo un aggiornamento APT che richiedono riavvio.",
        "install_cmd": "sudo apt update && sudo apt install -y needrestart",
    },
    {
        "id": "rkhunter",
        "name": "rkhunter (Rootkit Hunter)",
        "category": "Rilevamento Rootkit",
        "priority": "low",
        "packages": ["rkhunter"],
        "binaries": ["rkhunter"],
        "service": None,
        "source": "Defense-in-Depth · Lynis",
        "description": "Scansiona periodicamente il sistema alla ricerca di rootkit noti, backdoor, file nascosti e permessi sospetti.",
        "install_cmd": "sudo apt update && sudo apt install -y rkhunter",
    },
]


def _dpkg_installed(package: str) -> bool:
    """Return True if a Debian/Ubuntu package is installed (read-only)."""
    try:
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", package],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        return proc.returncode == 0 and "install ok installed" in proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _service_active(service: str) -> bool:
    """Return True if a systemd service is active (read-only)."""
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", service],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        return proc.returncode == 0 and proc.stdout.strip() == "active"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def check_security_tools() -> list[SecurityTool]:
    """Inspect presence and service status of best-practice Ubuntu security tools."""
    is_linux = platform.system().lower() == "linux"
    results: list[SecurityTool] = []

    for spec in TOOL_CATALOG:
        installed = False
        active: bool | None = None

        if is_linux:
            pkgs = spec["packages"]
            bins = spec["binaries"]
            if pkgs:
                installed = all(_dpkg_installed(p) for p in pkgs)
            if not installed and bins:
                installed = any(shutil.which(b) is not None for b in bins)

            if installed and spec["service"]:
                active = _service_active(spec["service"])

        if not installed:
            status = "missing"
        elif active is False:
            status = "inactive"
        else:
            status = "ok"

        results.append(
            SecurityTool(
                id=spec["id"],
                name=spec["name"],
                category=spec["category"],
                priority=spec["priority"],
                installed=installed,
                active=active,
                status=status,
                source=spec["source"],
                description=spec["description"],
                install_cmd=spec["install_cmd"],
            )
        )

    return results


def build_demo_security_tools() -> list[SecurityTool]:
    """Return a realistic Ubuntu 24.04 tool inventory for demo mode."""
    demo_states: dict[str, tuple[bool, bool | None]] = {
        "ufw": (True, True),
        "auditd": (False, None),
        "apparmor-utils": (True, True),
        "unattended-upgrades": (True, None),
        "fail2ban": (True, False),
        "aide": (False, None),
        "libpam-pwquality": (False, None),
        "chrony": (True, True),
        "crowdsec": (False, None),
        "lynis": (False, None),
        "needrestart": (True, None),
        "rkhunter": (False, None),
    }

    tools: list[SecurityTool] = []
    for spec in TOOL_CATALOG:
        installed, active = demo_states.get(spec["id"], (False, None))
        status = "missing" if not installed else ("inactive" if active is False else "ok")
        tools.append(
            SecurityTool(
                id=spec["id"],
                name=spec["name"],
                category=spec["category"],
                priority=spec["priority"],
                installed=installed,
                active=active,
                status=status,
                source=spec["source"],
                description=spec["description"],
                install_cmd=spec["install_cmd"],
            )
        )
    return tools
