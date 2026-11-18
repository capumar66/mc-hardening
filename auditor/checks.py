"""Read-only Ubuntu server hardening checks (CIS Benchmark & Lynis inspired)."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import subprocess

from .logs import analyze_system_logs
from .models import AuditReport, CheckResult, ListeningPort, compute_score


def _run_cmd(cmd: list[str], timeout: int = 6) -> tuple[int, str, str]:
    """Run a local read-only command safely."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"Comando non trovato: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout esecuzione: {' '.join(cmd)}"
    except OSError as exc:
        return 1, "", str(exc)


def parse_sshd_config_text(lines: list[str]) -> dict[str, str]:
    """Parse sshd_config lines respecting OpenSSH first-match-wins semantics."""
    config: dict[str, str] = {}
    in_match_block = False

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()

        parts = re.split(r"[\s=]+", line, maxsplit=1)
        if len(parts) != 2:
            continue
        key = parts[0].lower()
        val = parts[1].strip().strip('"')

        if key == "match":
            in_match_block = True
            continue
        if in_match_block:
            continue
        if key not in config:
            config[key] = val

    return config


def _load_sshd_config() -> tuple[dict[str, str], str]:
    """Load effective OpenSSH config via `sshd -T` (if root) or file parsing."""
    rc, out, _ = _run_cmd(["sshd", "-T"])
    if rc == 0 and out.strip():
        parsed: dict[str, str] = {}
        for line in out.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and parts[0].lower() not in parsed:
                parsed[parts[0].lower()] = parts[1].strip()
        return parsed, "sshd -T"

    main_path = Path("/etc/ssh/sshd_config")
    if not main_path.exists():
        return {}, ""

    collected_lines: list[str] = []
    dropin_dir = Path("/etc/ssh/sshd_config.d")
    if dropin_dir.is_dir():
        for conf_file in sorted(dropin_dir.glob("*.conf")):
            try:
                collected_lines.extend(
                    conf_file.read_text(encoding="utf-8", errors="replace").splitlines()
                )
            except OSError:
                pass
    try:
        collected_lines.extend(
            main_path.read_text(encoding="utf-8", errors="replace").splitlines()
        )
    except OSError:
        return {}, ""

    return parse_sshd_config_text(collected_lines), "/etc/ssh/sshd_config"


def check_ssh_hardening() -> list[CheckResult]:
    """Audit OpenSSH daemon configuration."""
    cfg, source = _load_sshd_config()
    if not cfg:
        return [
            CheckResult(
                id="ssh-config-missing",
                category="SSH",
                title="Configurazione OpenSSH",
                status="info",
                severity="info",
                benchmark="CIS 5.2",
                details="File /etc/ssh/sshd_config non trovato o non leggibile.",
                remediation="Verifica se openssh-server è installato o esegui lo script con sudo.",
            )
        ]

    results: list[CheckResult] = []

    root_login = cfg.get("permitrootlogin", "prohibit-password").lower()
    if root_login == "no":
        results.append(
            CheckResult(
                id="ssh-permit-root",
                category="SSH",
                title="Accesso SSH diretto come root disabilitato",
                status="pass",
                severity="high",
                benchmark="CIS 5.2.8",
                details=f"PermitRootLogin è impostato su '{root_login}'.",
                evidence=f"{source}: PermitRootLogin {root_login}",
            )
        )
    elif root_login in ("prohibit-password", "without-password"):
        results.append(
            CheckResult(
                id="ssh-permit-root",
                category="SSH",
                title="Accesso SSH diretto come root (solo chiavi)",
                status="warn",
                severity="high",
                benchmark="CIS 5.2.8",
                details=f"PermitRootLogin è '{root_login}'. È preferibile disabilitarlo completamente.",
                remediation="Imposta 'PermitRootLogin no' in /etc/ssh/sshd_config.d/99-hardening.conf e ricarica sshd.",
                remediation_cmd="echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config.d/99-hardening.conf && sudo sshd -t && sudo systemctl reload ssh",
                evidence=f"{source}: PermitRootLogin {root_login}",
            )
        )
    else:
        results.append(
            CheckResult(
                id="ssh-permit-root",
                category="SSH",
                title="Accesso SSH diretto come root abilitato",
                status="fail",
                severity="high",
                benchmark="CIS 5.2.8",
                details=f"PermitRootLogin è '{root_login}'. Espone l'account root a tentativi di accesso diretto.",
                remediation="Disabilita l'accesso root diretto e usa un utente non-root con sudo.",
                remediation_cmd="echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config.d/99-hardening.conf && sudo sshd -t && sudo systemctl reload ssh",
                evidence=f"{source}: PermitRootLogin {root_login}",
            )
        )

    pwd_auth = cfg.get("passwordauthentication", "yes").lower()
    results.append(
        CheckResult(
            id="ssh-password-auth",
            category="SSH",
            title=(
                "Autenticazione SSH con password disabilitata"
                if pwd_auth == "no"
                else "Autenticazione SSH con password abilitata"
            ),
            status="pass" if pwd_auth == "no" else "fail",
            severity="high",
            benchmark="CIS 5.2.10",
            details=(
                "PasswordAuthentication è 'no' (accesso consentito solo tramite chiavi SSH)."
                if pwd_auth == "no"
                else f"PasswordAuthentication è '{pwd_auth}'. Il server è esposto a brute-force sulle password."
            ),
            remediation="" if pwd_auth == "no" else "Configura le chiavi SSH, poi disabilita PasswordAuthentication e KbdInteractiveAuthentication.",
            remediation_cmd="" if pwd_auth == "no" else "printf 'PasswordAuthentication no\\nKbdInteractiveAuthentication no\\n' | sudo tee -a /etc/ssh/sshd_config.d/99-hardening.conf && sudo sshd -t && sudo systemctl reload ssh",
            evidence=f"{source}: PasswordAuthentication {pwd_auth}",
        )
    )

    empty_pwd = cfg.get("permitemptypasswords", "no").lower()
    results.append(
        CheckResult(
            id="ssh-empty-passwords",
            category="SSH",
            title="Password vuote SSH bloccate",
            status="pass" if empty_pwd == "no" else "fail",
            severity="high",
            benchmark="CIS 5.2.9",
            details=f"PermitEmptyPasswords è '{empty_pwd}'.",
            remediation="" if empty_pwd == "no" else "Imposta 'PermitEmptyPasswords no' nella configurazione SSH.",
            evidence=f"{source}: PermitEmptyPasswords {empty_pwd}",
        )
    )

    max_tries_raw = cfg.get("maxauthtries", "6")
    try:
        max_tries = int(max_tries_raw)
    except ValueError:
        max_tries = 6
    results.append(
        CheckResult(
            id="ssh-max-auth-tries",
            category="SSH",
            title="Limite tentativi autenticazione SSH (MaxAuthTries)",
            status="pass" if max_tries <= 4 else "warn",
            severity="medium",
            benchmark="CIS 5.2.5",
            details=f"MaxAuthTries è {max_tries} (consigliato <= 4).",
            remediation="" if max_tries <= 4 else "Riduci MaxAuthTries a 3 per limitare tentativi per connessione.",
            remediation_cmd="" if max_tries <= 4 else "echo 'MaxAuthTries 3' | sudo tee -a /etc/ssh/sshd_config.d/99-hardening.conf && sudo sshd -t && sudo systemctl reload ssh",
            evidence=f"{source}: MaxAuthTries {max_tries_raw}",
        )
    )

    x11 = cfg.get("x11forwarding", "no").lower()
    results.append(
        CheckResult(
            id="ssh-x11-forwarding",
            category="SSH",
            title="X11Forwarding disabilitato",
            status="pass" if x11 == "no" else "warn",
            severity="low",
            benchmark="CIS 5.2.6",
            details=f"X11Forwarding è '{x11}'.",
            remediation="" if x11 == "no" else "Imposta 'X11Forwarding no' sui server headless.",
            evidence=f"{source}: X11Forwarding {x11}",
        )
    )

    loglevel = cfg.get("loglevel", "INFO").upper()
    log_ok = loglevel in ("VERBOSE", "INFO")
    results.append(
        CheckResult(
            id="ssh-loglevel",
            category="SSH",
            title="Livello logging OpenSSH adeguato",
            status="pass" if log_ok else "warn",
            severity="low",
            benchmark="CIS 5.2.4",
            details=f"LogLevel è '{loglevel}' (consigliato VERBOSE o INFO per tracciare fingerprint chiavi).",
            remediation="" if log_ok else "Imposta 'LogLevel VERBOSE' in /etc/ssh/sshd_config.d/99-hardening.conf.",
            evidence=f"{source}: LogLevel {loglevel}",
        )
    )

    return results


def check_firewall() -> list[CheckResult]:
    """Check UFW, nftables, or iptables status."""
    rc, out, err = _run_cmd(["ufw", "status", "verbose"])
    if rc == 0:
        lower = out.lower()
        if "status: active" in lower:
            deny_incoming = "deny (incoming)" in lower or "reject (incoming)" in lower
            return [
                CheckResult(
                    id="fw-ufw-status",
                    category="Firewall",
                    title="Firewall UFW attivo",
                    status="pass" if deny_incoming else "warn",
                    severity="high",
                    benchmark="CIS 3.5.1",
                    details=(
                        "UFW è attivo con policy predefinita in ingresso restrittiva (deny/reject)."
                        if deny_incoming
                        else "UFW è attivo, ma la policy predefinita in ingresso non risulta deny/reject."
                    ),
                    remediation="" if deny_incoming else "Imposta la policy predefinita in ingresso su deny dopo aver verificato la regola SSH.",
                    remediation_cmd="" if deny_incoming else "sudo ufw default deny incoming",
                    evidence=out.strip()[:500],
                )
            ]
        return [
            CheckResult(
                id="fw-ufw-status",
                category="Firewall",
                title="Firewall UFW inattivo",
                status="fail",
                severity="high",
                benchmark="CIS 3.5.1",
                details="UFW risulta installato ma disattivato.",
                remediation="Consenti prima SSH/VPN, imposta default deny incoming e attiva UFW.",
                remediation_cmd="sudo ufw allow OpenSSH && sudo ufw default deny incoming && sudo ufw enable",
                evidence=out.strip()[:300],
            )
        ]

    rc_nft, out_nft, _ = _run_cmd(["nft", "list", "ruleset"])
    if rc_nft == 0 and out_nft.strip():
        return [
            CheckResult(
                id="fw-nftables",
                category="Firewall",
                title="Regole nftables presenti",
                status="pass",
                severity="high",
                benchmark="CIS 3.5.2",
                details="UFW non rilevato, ma è presente un ruleset nftables attivo.",
                evidence=out_nft.strip()[:400],
            )
        ]

    return [
        CheckResult(
            id="fw-status-unknown",
            category="Firewall",
            title="Stato firewall non verificabile",
            status="warn",
            severity="high",
            benchmark="CIS 3.5",
            details=f"Impossibile leggere lo stato di UFW/nftables ({err.strip() or 'permessi o comando assente'}).",
            remediation="Esegui lo strumento con sudo su Ubuntu e verifica che UFW o nftables sia attivo.",
        )
    ]


def check_fail2ban() -> CheckResult:
    """Verify whether Fail2ban is active."""
    rc, out, _ = _run_cmd(["systemctl", "is-active", "fail2ban"])
    status_str = out.strip()
    if rc == 0 and status_str == "active":
        return CheckResult(
            id="ips-fail2ban",
            category="Protezione Intrusioni",
            title="Fail2ban attivo",
            status="pass",
            severity="medium",
            benchmark="Lynis TOOL-5002",
            details="Il servizio fail2ban è attivo e protegge dai tentativi ripetuti di brute-force.",
            evidence=f"systemctl is-active fail2ban -> {status_str}",
        )
    return CheckResult(
        id="ips-fail2ban",
        category="Protezione Intrusioni",
        title="Fail2ban non attivo",
        status="warn",
        severity="medium",
        benchmark="Lynis TOOL-5002",
        details=f"Il servizio fail2ban non risulta attivo ({status_str or 'non installato'}).",
        remediation="Installa e abilita fail2ban con jail sshd attiva.",
        remediation_cmd="sudo apt update && sudo apt install -y fail2ban && sudo systemctl enable --now fail2ban",
    )


def check_apparmor() -> CheckResult:
    """Verify AppArmor Mandatory Access Control status (CIS 1.6.1)."""
    enabled_path = Path("/sys/module/apparmor/parameters/enabled")
    if enabled_path.exists():
        try:
            val = enabled_path.read_text(encoding="utf-8").strip().upper()
            if val == "Y":
                rc, out, _ = _run_cmd(["aa-status", "--json"])
                enforced = ""
                if rc == 0 and out.strip():
                    try:
                        data = json.loads(out)
                        profiles = data.get("profiles", {})
                        enf_count = sum(1 for v in profiles.values() if v == "enforce")
                        enforced = f" ({enf_count} profili in enforce)"
                    except (json.JSONDecodeError, AttributeError):
                        pass
                return CheckResult(
                    id="mac-apparmor",
                    category="MAC & Kernel",
                    title="AppArmor abilitato",
                    status="pass",
                    severity="high",
                    benchmark="CIS 1.6.1",
                    details=f"AppArmor è attivo nel kernel{enforced}.",
                    evidence=f"/sys/module/apparmor/parameters/enabled = {val}",
                )
        except OSError:
            pass

    return CheckResult(
        id="mac-apparmor",
        category="MAC & Kernel",
        title="AppArmor non attivo",
        status="fail",
        severity="high",
        benchmark="CIS 1.6.1",
        details="AppArmor non risulta abilitato nel kernel.",
        remediation="Installa apparmor e apparmor-utils e abilita il servizio all'avvio.",
        remediation_cmd="sudo apt install -y apparmor apparmor-utils && sudo systemctl enable --now apparmor",
    )


def check_pam_password_policy() -> list[CheckResult]:
    """Check PAM password quality and /etc/login.defs aging rules."""
    results: list[CheckResult] = []

    pam_pw = Path("/etc/pam.d/common-password")
    if pam_pw.exists():
        try:
            text = pam_pw.read_text(encoding="utf-8", errors="replace")
            has_pwquality = "pam_pwquality.so" in text
            results.append(
                CheckResult(
                    id="pam-pwquality",
                    category="PAM & Account",
                    title="Modulo PAM complessità password (pam_pwquality)",
                    status="pass" if has_pwquality else "warn",
                    severity="medium",
                    benchmark="CIS 5.4.1",
                    details=(
                        "pam_pwquality.so è configurato in /etc/pam.d/common-password."
                        if has_pwquality
                        else "pam_pwquality.so non rilevato in /etc/pam.d/common-password."
                    ),
                    remediation="" if has_pwquality else "Installa libpam-pwquality per imporre complessità minima alle password locali.",
                    remediation_cmd="" if has_pwquality else "sudo apt install -y libpam-pwquality",
                )
            )
        except OSError:
            pass

    login_defs = Path("/etc/login.defs")
    if login_defs.exists():
        try:
            text = login_defs.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", text, re.MULTILINE)
            if m:
                days = int(m.group(1))
                ok = 0 < days <= 365
                results.append(
                    CheckResult(
                        id="pam-pass-max-days",
                        category="PAM & Account",
                        title="Scadenza massima password (/etc/login.defs)",
                        status="pass" if ok else "warn",
                        severity="low",
                        benchmark="CIS 5.5.1.1",
                        details=f"PASS_MAX_DAYS = {days} (consigliato <= 365).",
                        remediation="" if ok else "Imposta PASS_MAX_DAYS 365 (o 90) in /etc/login.defs.",
                        evidence=f"PASS_MAX_DAYS {days}",
                    )
                )
        except OSError:
            pass

    return results


def check_apt_and_reboot() -> list[CheckResult]:
    """Verify unattended-upgrades, pending security updates, and reboot-required."""
    results: list[CheckResult] = []

    conf_path = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if conf_path.exists():
        try:
            text = conf_path.read_text(encoding="utf-8", errors="replace")
            enabled = (
                'Unattended-Upgrade "1"' in text
                and 'Update-Package-Lists "1"' in text
            )
            results.append(
                CheckResult(
                    id="updates-unattended",
                    category="Aggiornamenti",
                    title="Aggiornamenti automatici (unattended-upgrades)",
                    status="pass" if enabled else "warn",
                    severity="medium",
                    benchmark="Lynis PKGS-7392",
                    details=(
                        "Gli aggiornamenti di sicurezza automatici sono abilitati."
                        if enabled
                        else "unattended-upgrades non risulta completamente abilitato."
                    ),
                    remediation="" if enabled else "Abilita unattended-upgrades tramite dpkg-reconfigure.",
                    remediation_cmd="" if enabled else "sudo dpkg-reconfigure -plow unattended-upgrades",
                    evidence=text.strip()[:250],
                )
            )
        except OSError:
            pass
    else:
        results.append(
            CheckResult(
                id="updates-unattended",
                category="Aggiornamenti",
                title="Aggiornamenti automatici non configurati",
                status="warn",
                severity="medium",
                benchmark="Lynis PKGS-7392",
                details="File /etc/apt/apt.conf.d/20auto-upgrades non trovato.",
                remediation="Installa e configura unattended-upgrades.",
                remediation_cmd="sudo apt install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
            )
        )

    # Check pending updates via Ubuntu's apt-check (fast, read-only)
    apt_check = Path("/usr/lib/update-notifier/apt-check")
    if apt_check.exists():
        rc, out, err = _run_cmd([str(apt_check)], timeout=8)
        raw = (err or out).strip()
        if rc == 0 and ";" in raw:
            parts = raw.split(";", 1)
            try:
                total_upd = int(parts[0])
                sec_upd = int(parts[1])
                status = "fail" if sec_upd > 0 else ("warn" if total_upd > 0 else "pass")
                results.append(
                    CheckResult(
                        id="updates-apt-pending",
                        category="Aggiornamenti",
                        title="Patch di sicurezza APT pendenti",
                        status=status,
                        severity="high" if sec_upd > 0 else "low",
                        benchmark="CIS 1.9",
                        details=f"Aggiornamenti disponibili: {total_upd} totali, di cui {sec_upd} di sicurezza.",
                        remediation="" if sec_upd == 0 else "Applica gli aggiornamenti di sicurezza pendenti con apt upgrade.",
                        remediation_cmd="" if sec_upd == 0 else "sudo apt update && sudo apt upgrade -y",
                        evidence=f"apt-check: {total_upd} totali / {sec_upd} sicurezza",
                    )
                )
            except ValueError:
                pass

    # Check reboot required
    reboot_flag = Path("/var/run/reboot-required")
    if reboot_flag.exists():
        results.append(
            CheckResult(
                id="updates-reboot-required",
                category="Aggiornamenti",
                title="Riavvio del sistema richiesto",
                status="warn",
                severity="medium",
                benchmark="Lynis BOOT-5180",
                details="È presente /var/run/reboot-required: alcune patch kernel o librerie critiche non sono ancora attive.",
                remediation="Pianifica un riavvio controllato del server per attivare il nuovo kernel.",
                remediation_cmd="cat /var/run/reboot-required.pkgs && sudo reboot",
                evidence="/var/run/reboot-required presente",
            )
        )

    return results


def check_cron_and_suid() -> list[CheckResult]:
    """Verify cron directory permissions and cron.allow restriction (CIS 5.1)."""
    results: list[CheckResult] = []
    cron_targets = [
        (Path("/etc/crontab"), 0o600),
        (Path("/etc/cron.d"), 0o700),
    ]
    bad_perms: list[str] = []
    for path, _expected in cron_targets:
        if not path.exists():
            continue
        try:
            st = path.stat()
            mode = stat.S_IMODE(st.st_mode)
            if st.st_uid != 0 or (mode & 0o022):
                bad_perms.append(f"{path} ({oct(mode)})")
        except OSError:
            continue

    results.append(
        CheckResult(
            id="cron-permissions",
            category="Cron & Permessi",
            title="Permessi file e directory Cron",
            status="pass" if not bad_perms else "fail",
            severity="medium",
            benchmark="CIS 5.1.2",
            details=(
                "I file/directory cron principali appartengono a root e non sono scrivibili da altri."
                if not bad_perms
                else f"Permessi troppo permissivi su: {', '.join(bad_perms)}."
            ),
            remediation="" if not bad_perms else "Restringi i permessi di /etc/crontab (600) e /etc/cron.d (700) a root.",
            remediation_cmd="" if not bad_perms else "sudo chmod og-rwx /etc/crontab /etc/cron.d",
        )
    )

    cron_allow = Path("/etc/cron.allow")
    results.append(
        CheckResult(
            id="cron-allow-restricted",
            category="Cron & Permessi",
            title="Restrizione utenti Cron (/etc/cron.allow)",
            status="pass" if cron_allow.exists() else "warn",
            severity="low",
            benchmark="CIS 5.1.8",
            details=(
                "/etc/cron.allow è presente (solo gli utenti autorizzati possono creare crontab)."
                if cron_allow.exists()
                else "/etc/cron.allow assente: qualsiasi utente locale può pianificare job cron."
            ),
            remediation="" if cron_allow.exists() else "Crea /etc/cron.allow con i soli utenti autorizzati e rimuovi /etc/cron.deny.",
            remediation_cmd="" if cron_allow.exists() else "sudo touch /etc/cron.allow && sudo chmod 640 /etc/cron.allow && sudo rm -f /etc/cron.deny",
        )
    )

    return results


def check_docker_hardening() -> list[CheckResult]:
    """Audit Docker daemon security if Docker is installed."""
    sock = Path("/var/run/docker.sock")
    daemon_json = Path("/etc/docker/daemon.json")
    if not sock.exists() and not daemon_json.exists():
        return []

    results: list[CheckResult] = []
    if sock.exists():
        try:
            st = sock.stat()
            mode = stat.S_IMODE(st.st_mode)
            ok = st.st_uid == 0 and not (mode & 0o007)
            results.append(
                CheckResult(
                    id="docker-sock-perms",
                    category="Docker",
                    title="Permessi socket Docker (/var/run/docker.sock)",
                    status="pass" if ok else "fail",
                    severity="high",
                    benchmark="CIS Docker 3.15",
                    details=f"/var/run/docker.sock ha permessi {oct(mode)} (non deve essere accessibile a 'other').",
                    remediation="" if ok else "Imposta permessi 660 root:docker su /var/run/docker.sock.",
                    remediation_cmd="" if ok else "sudo chmod 660 /var/run/docker.sock",
                    evidence=f"mode={oct(mode)}, uid={st.st_uid}",
                )
            )
        except OSError:
            pass

    if daemon_json.exists():
        try:
            cfg = json.loads(daemon_json.read_text(encoding="utf-8", errors="replace"))
            no_new_priv = bool(cfg.get("no-new-privileges", False))
            results.append(
                CheckResult(
                    id="docker-no-new-priv",
                    category="Docker",
                    title="Docker no-new-privileges abilitato",
                    status="pass" if no_new_priv else "warn",
                    severity="medium",
                    benchmark="CIS Docker 5.25",
                    details=(
                        "no-new-privileges è attivo in /etc/docker/daemon.json."
                        if no_new_priv
                        else "no-new-privileges non impostato in /etc/docker/daemon.json."
                    ),
                    remediation="" if no_new_priv else 'Aggiungi "no-new-privileges": true in /etc/docker/daemon.json e riavvia docker.',
                )
            )
        except (OSError, json.JSONDecodeError):
            pass

    return results


def check_nginx_hardening() -> list[CheckResult]:
    """Audit Nginx basic hardening if installed."""
    nginx_conf = Path("/etc/nginx/nginx.conf")
    if not nginx_conf.exists():
        return []

    results: list[CheckResult] = []
    try:
        text = nginx_conf.read_text(encoding="utf-8", errors="replace")
        tokens_off = bool(re.search(r"^\s*server_tokens\s+off\s*;", text, re.MULTILINE))
        results.append(
            CheckResult(
                id="nginx-server-tokens",
                category="Web Server",
                title="Nginx server_tokens disabilitato",
                status="pass" if tokens_off else "warn",
                severity="low",
                benchmark="CIS Nginx 2.5.1",
                details=(
                    "server_tokens off è configurato (versione Nginx nascosta negli header)."
                    if tokens_off
                    else "server_tokens off non rilevato in /etc/nginx/nginx.conf (espone la versione Nginx)."
                ),
                remediation="" if tokens_off else "Aggiungi 'server_tokens off;' nel blocco http {} di /etc/nginx/nginx.conf e ricarica Nginx.",
                remediation_cmd="" if tokens_off else "sudo nginx -t && sudo systemctl reload nginx",
            )
        )

        legacy_tls = bool(re.search(r"ssl_protocols[^;]*\bTLSv1(\.1)?\b", text))
        results.append(
            CheckResult(
                id="nginx-tls-protocols",
                category="Web Server",
                title="Nginx protocolli TLS moderni (no TLS 1.0/1.1)",
                status="fail" if legacy_tls else "pass",
                severity="high",
                benchmark="CIS Nginx 4.1.4",
                details=(
                    "Rilevato TLSv1 o TLSv1.1 in /etc/nginx/nginx.conf."
                    if legacy_tls
                    else "Nessun protocollo TLS obsoleto rilevato in /etc/nginx/nginx.conf."
                ),
                remediation="" if not legacy_tls else "Imposta 'ssl_protocols TLSv1.2 TLSv1.3;' in Nginx.",
            )
        )
    except OSError:
        pass

    return results


def check_sysctl_hardening() -> list[CheckResult]:
    """Check key Linux kernel network and security sysctl parameters."""
    params = [
        (
            "sysctl-syncookies",
            "net.ipv4.tcp_syncookies",
            "1",
            "medium",
            "CIS 3.3.8",
            "Protezione SYN Flood (tcp_syncookies)",
            "Imposta net.ipv4.tcp_syncookies = 1 in /etc/sysctl.d/99-hardening.conf.",
            "echo 'net.ipv4.tcp_syncookies = 1' | sudo tee -a /etc/sysctl.d/99-hardening.conf && sudo sysctl --system",
        ),
        (
            "sysctl-accept-redirects",
            "net.ipv4.conf.all.accept_redirects",
            "0",
            "medium",
            "CIS 3.3.2",
            "ICMP Redirect in ingresso disabilitati",
            "Imposta net.ipv4.conf.all.accept_redirects = 0 in /etc/sysctl.d/99-hardening.conf.",
            "echo 'net.ipv4.conf.all.accept_redirects = 0' | sudo tee -a /etc/sysctl.d/99-hardening.conf && sudo sysctl --system",
        ),
        (
            "sysctl-rp-filter",
            "net.ipv4.conf.all.rp_filter",
            "1",
            "medium",
            "CIS 3.3.7",
            "Reverse Path Filtering attivo (anti-spoofing)",
            "Imposta net.ipv4.conf.all.rp_filter = 1 in /etc/sysctl.d/99-hardening.conf.",
            "echo 'net.ipv4.conf.all.rp_filter = 1' | sudo tee -a /etc/sysctl.d/99-hardening.conf && sudo sysctl --system",
        ),
        (
            "sysctl-dmesg-restrict",
            "kernel.dmesg_restrict",
            "1",
            "low",
            "Lynis KRNL-6000",
            "Accesso a dmesg limitato a root",
            "Imposta kernel.dmesg_restrict = 1 in /etc/sysctl.d/99-hardening.conf.",
            "echo 'kernel.dmesg_restrict = 1' | sudo tee -a /etc/sysctl.d/99-hardening.conf && sudo sysctl --system",
        ),
    ]

    results: list[CheckResult] = []
    for check_id, key, expected, severity, bench, title, remediation, cmd in params:
        proc_path = Path("/proc/sys") / key.replace(".", "/")
        if not proc_path.exists():
            continue
        try:
            actual = proc_path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        ok = actual == expected
        results.append(
            CheckResult(
                id=check_id,
                category="MAC & Kernel",
                title=title,
                status="pass" if ok else "warn",
                severity=severity,
                benchmark=bench,
                details=f"{key} = {actual} (atteso: {expected}).",
                remediation="" if ok else remediation,
                remediation_cmd="" if ok else cmd,
                evidence=f"{key} = {actual}",
            )
        )
    return results


def check_permissions_and_accounts() -> list[CheckResult]:
    """Check sensitive file permissions and UID 0 accounts."""
    results: list[CheckResult] = []

    file_checks = [
        ("perm-shadow", Path("/etc/shadow"), {0o640, 0o600, 0o000}, "high", "CIS 6.1.4", "Permessi /etc/shadow"),
        ("perm-passwd", Path("/etc/passwd"), {0o644}, "medium", "CIS 6.1.2", "Permessi /etc/passwd"),
        ("perm-sshd", Path("/etc/ssh/sshd_config"), {0o600, 0o644}, "medium", "CIS 5.2.1", "Permessi /etc/ssh/sshd_config"),
    ]

    for cid, path, allowed_modes, severity, bench, title in file_checks:
        if not path.exists():
            continue
        try:
            st = path.stat()
            mode = stat.S_IMODE(st.st_mode)
            ok = mode in allowed_modes and st.st_uid == 0
            allowed_str = ", ".join(oct(m) for m in sorted(allowed_modes))
            results.append(
                CheckResult(
                    id=cid,
                    category="PAM & Account",
                    title=title,
                    status="pass" if ok else "fail",
                    severity=severity,
                    benchmark=bench,
                    details=f"{path} ha permessi {oct(mode)} e UID {st.st_uid} (atteso root, {allowed_str}).",
                    remediation="" if ok else f"Ripristina i permessi corretti su {path}.",
                    evidence=f"{path}: mode={oct(mode)}, uid={st.st_uid}",
                )
            )
        except OSError:
            continue

    passwd_path = Path("/etc/passwd")
    if passwd_path.exists():
        try:
            uid0_users = [
                parts[0]
                for line in passwd_path.read_text(encoding="utf-8", errors="replace").splitlines()
                if len(parts := line.split(":")) >= 3 and parts[2] == "0"
            ]
            ok = uid0_users == ["root"]
            results.append(
                CheckResult(
                    id="acct-uid-zero",
                    category="PAM & Account",
                    title="Unico account con UID 0 (root)",
                    status="pass" if ok else "fail",
                    severity="high",
                    benchmark="CIS 6.2.7",
                    details=f"Account con UID 0 trovati: {', '.join(uid0_users) or 'nessuno'}.",
                    remediation="" if ok else "Rimuovi o riconfigura gli account non-root con UID 0.",
                    evidence=f"UID 0: {', '.join(uid0_users)}",
                )
            )
        except OSError:
            pass

    return results


def _classify_bind_address(addr: str) -> str:
    clean = addr.strip("[]")
    if clean in ("*", "0.0.0.0", "::"):
        return "public"
    if clean in ("127.0.0.1", "::1") or clean.startswith("127."):
        return "local"
    try:
        ip = ipaddress.ip_address(clean.split("%", 1)[0])
        if ip.is_loopback:
            return "local"
        if ip.is_private or ip.is_link_local:
            return "vpn_or_private"
    except ValueError:
        pass
    return "public"


def collect_listening_ports() -> list[ListeningPort]:
    """Collect locally listening TCP/UDP sockets using `ss -tulnp`."""
    rc, out, _ = _run_cmd(["ss", "-tulnp"])
    if rc != 0:
        rc, out, _ = _run_cmd(["ss", "-tuln"])
    if rc != 0 or not out.strip():
        return []

    ports: list[ListeningPort] = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local_addr = parts[4]
        process_col = " ".join(parts[6:]) if len(parts) > 6 else ""

        if local_addr.startswith("[") and "]:" in local_addr:
            addr, port = local_addr.rsplit("]:", 1)
            addr = addr.lstrip("[")
        elif ":" in local_addr:
            addr, port = local_addr.rsplit(":", 1)
        else:
            addr, port = local_addr, "?"

        proc_match = re.search(r'"([^"]+)"', process_col)
        proc_name = proc_match.group(1) if proc_match else (process_col or "n/d (richiede sudo)")

        ports.append(
            ListeningPort(
                protocol=proto,
                bind_address=addr,
                port=port,
                process=proc_name,
                exposure=_classify_bind_address(addr),
            )
        )

    return ports


def _read_os_info() -> str:
    os_release = Path("/etc/os-release")
    if os_release.exists():
        try:
            for line in os_release.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
    return f"{platform.system()} {platform.release()}"


def run_audit() -> AuditReport:
    """Execute all read-only Ubuntu hardening and log checks."""
    is_linux = platform.system().lower() == "linux"
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0

    checks: list[CheckResult] = []
    if not is_linux:
        checks.append(
            CheckResult(
                id="platform-non-linux",
                category="Sistema",
                title="Ambiente non Linux rilevato",
                status="warn",
                severity="info",
                details=(
                    f"Lo strumento sta girando su {platform.system()} ({platform.release()}). "
                    "Avvia con --demo sul Mac per l'anteprima oppure copia il progetto sul VPS Ubuntu."
                ),
                remediation="Esegui 'python3 server.py --demo' sul Mac o 'sudo python3 server.py' su Ubuntu.",
            )
        )
    else:
        checks.extend(check_ssh_hardening())
        checks.extend(check_firewall())
        checks.append(check_fail2ban())
        checks.append(check_apparmor())
        checks.extend(check_pam_password_policy())
        checks.extend(check_apt_and_reboot())
        checks.extend(check_cron_and_suid())
        checks.extend(check_sysctl_hardening())
        checks.extend(check_permissions_and_accounts())
        checks.extend(check_docker_hardening())
        checks.extend(check_nginx_hardening())

    ports = collect_listening_ports() if is_linux else []
    logs = analyze_system_logs() if is_linux else analyze_system_logs(max_lines=100)

    if is_linux:
        public_ports = [p for p in ports if p.exposure == "public"]
        checks.append(
            CheckResult(
                id="net-public-ports",
                category="Servizi in Ascolto",
                title=(
                    "Numero elevato di socket su tutte le interfacce"
                    if len(public_ports) > 5
                    else "Superficie di esposizione locale contenuta"
                ),
                status="warn" if len(public_ports) > 5 else "pass",
                severity="medium",
                benchmark="CIS 2.2",
                details=f"Rilevati {len(public_ports)} socket in ascolto su 0.0.0.0 o ::.",
                remediation="" if len(public_ports) <= 5 else "Lega i servizi interni (DB, Redis, admin UI) a 127.0.0.1 o all'IP della VPN.",
            )
        )

    score, summary = compute_score(checks)

    return AuditReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        hostname=socket.gethostname(),
        os_info=_read_os_info(),
        kernel=platform.release(),
        is_root=is_root,
        is_linux=is_linux,
        demo_mode=False,
        score=score,
        summary=summary,
        checks=checks,
        listening_ports=ports,
        logs=logs,
    )
