"""Sample Ubuntu 24.04 LTS report and historical snapshots for macOS preview."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .history import HistoryStore
from .models import AuditReport, CheckResult, ListeningPort, LogSummary, compute_score
from .tools import build_demo_security_tools


def build_demo_report(generated_at: str | None = None) -> AuditReport:
    """Return a realistic Ubuntu hardening report with CIS/Lynis checks."""
    checks = [
        CheckResult(
            id="ssh-permit-root",
            category="SSH",
            title="Accesso SSH diretto come root disabilitato",
            status="pass",
            severity="high",
            benchmark="CIS 5.2.8",
            details="PermitRootLogin è impostato su 'no'.",
            evidence="sshd -T: PermitRootLogin no",
        ),
        CheckResult(
            id="ssh-password-auth",
            category="SSH",
            title="Autenticazione SSH con password abilitata",
            status="fail",
            severity="high",
            benchmark="CIS 5.2.10",
            details="PasswordAuthentication è 'yes'. Il server è esposto a brute-force sulle password.",
            remediation="Configura le chiavi SSH, poi disabilita PasswordAuthentication in /etc/ssh/sshd_config.d/00-hardening.conf.",
            remediation_cmd="printf 'PasswordAuthentication no\\nKbdInteractiveAuthentication no\\n' | sudo tee -a /etc/ssh/sshd_config.d/00-hardening.conf && sudo sshd -t && (sudo systemctl reload ssh || sudo systemctl restart ssh)",
            evidence="sshd -T: PasswordAuthentication yes",
        ),
        CheckResult(
            id="ssh-max-auth-tries",
            category="SSH",
            title="Limite tentativi autenticazione SSH (MaxAuthTries)",
            status="warn",
            severity="medium",
            benchmark="CIS 5.2.5",
            details="MaxAuthTries è 6 (consigliato <= 4).",
            remediation="Imposta 'MaxAuthTries 3' in /etc/ssh/sshd_config.d/00-hardening.conf (letto per primo da OpenSSH).",
            remediation_cmd="echo 'MaxAuthTries 3' | sudo tee -a /etc/ssh/sshd_config.d/00-hardening.conf && sudo sshd -t && (sudo systemctl reload ssh || sudo systemctl restart ssh)",
            evidence="sshd -T: MaxAuthTries 6",
        ),
        CheckResult(
            id="fw-ufw-status",
            category="Firewall",
            title="Firewall UFW attivo",
            status="pass",
            severity="high",
            benchmark="CIS 3.5.1",
            details="UFW è attivo con policy predefinita in ingresso deny (incoming).",
            evidence="Status: active | Default: deny (incoming), allow (outgoing)",
        ),
        CheckResult(
            id="ips-fail2ban",
            category="Protezione Intrusioni",
            title="Fail2ban non attivo",
            status="warn",
            severity="medium",
            benchmark="Lynis TOOL-5002",
            details="Il servizio fail2ban non risulta attivo (inactive).",
            remediation="Installa e abilita fail2ban con jail sshd attiva.",
            remediation_cmd="sudo apt update && sudo apt install -y fail2ban && sudo systemctl enable --now fail2ban",
        ),
        CheckResult(
            id="mac-apparmor",
            category="MAC & Kernel",
            title="AppArmor abilitato",
            status="pass",
            severity="high",
            benchmark="CIS 1.6.1",
            details="AppArmor è attivo nel kernel (28 profili in enforce).",
            evidence="/sys/module/apparmor/parameters/enabled = Y",
        ),
        CheckResult(
            id="sysctl-syncookies",
            category="MAC & Kernel",
            title="Protezione SYN Flood (tcp_syncookies)",
            status="pass",
            severity="medium",
            benchmark="CIS 3.3.8",
            details="net.ipv4.tcp_syncookies = 1 (atteso: 1).",
            evidence="net.ipv4.tcp_syncookies = 1",
        ),
        CheckResult(
            id="sysctl-accept-redirects",
            category="MAC & Kernel",
            title="ICMP Redirect in ingresso disabilitati",
            status="warn",
            severity="medium",
            benchmark="CIS 3.3.2",
            details="net.ipv4.conf.all.accept_redirects = 1 (atteso: 0).",
            remediation="Imposta net.ipv4.conf.all.accept_redirects = 0 in /etc/sysctl.d/99-hardening.conf.",
            remediation_cmd="echo 'net.ipv4.conf.all.accept_redirects = 0' | sudo tee -a /etc/sysctl.d/99-hardening.conf && sudo sysctl --system",
            evidence="net.ipv4.conf.all.accept_redirects = 1",
        ),
        CheckResult(
            id="updates-apt-pending",
            category="Aggiornamenti",
            title="Patch di sicurezza APT pendenti",
            status="fail",
            severity="high",
            benchmark="CIS 1.9",
            details="Aggiornamenti disponibili: 7 totali, di cui 3 di sicurezza (openssl, linux-image).",
            remediation="Applica gli aggiornamenti di sicurezza pendenti con apt upgrade.",
            remediation_cmd="sudo apt update && sudo apt upgrade -y",
            evidence="apt-check: 7 totali / 3 sicurezza",
        ),
        CheckResult(
            id="updates-unattended",
            category="Aggiornamenti",
            title="Aggiornamenti automatici (unattended-upgrades)",
            status="pass",
            severity="medium",
            benchmark="Lynis PKGS-7392",
            details="Gli aggiornamenti di sicurezza automatici sono abilitati.",
            evidence='APT::Periodic::Unattended-Upgrade "1";',
        ),
        CheckResult(
            id="pam-pwquality",
            category="PAM & Account",
            title="Modulo PAM complessità password (pam_pwquality)",
            status="warn",
            severity="medium",
            benchmark="CIS 5.4.1",
            details="pam_pwquality.so non rilevato in /etc/pam.d/common-password.",
            remediation="Installa libpam-pwquality per imporre complessità minima alle password locali.",
            remediation_cmd="sudo apt install -y libpam-pwquality",
        ),
        CheckResult(
            id="acct-uid-zero",
            category="PAM & Account",
            title="Unico account con UID 0 (root)",
            status="pass",
            severity="high",
            benchmark="CIS 6.2.7",
            details="Account con UID 0 trovati: root.",
            evidence="UID 0: root",
        ),
        CheckResult(
            id="cron-allow-restricted",
            category="Cron & Permessi",
            title="Restrizione utenti Cron (/etc/cron.allow)",
            status="warn",
            severity="low",
            benchmark="CIS 5.1.8",
            details="/etc/cron.allow assente: qualsiasi utente locale può pianificare job cron.",
            remediation="Crea /etc/cron.allow con i soli utenti autorizzati e rimuovi /etc/cron.deny.",
            remediation_cmd="sudo touch /etc/cron.allow && sudo chmod 640 /etc/cron.allow && sudo rm -f /etc/cron.deny",
        ),
        CheckResult(
            id="docker-sock-perms",
            category="Docker",
            title="Permessi socket Docker (/var/run/docker.sock)",
            status="pass",
            severity="high",
            benchmark="CIS Docker 3.15",
            details="/var/run/docker.sock ha permessi 0o660 (non accessibile a 'other').",
            evidence="mode=0o660, uid=0",
        ),
        CheckResult(
            id="nginx-server-tokens",
            category="Web Server",
            title="Nginx server_tokens disabilitato",
            status="warn",
            severity="low",
            benchmark="CIS Nginx 2.5.1",
            details="server_tokens off non rilevato in /etc/nginx/nginx.conf (espone la versione Nginx).",
            remediation="Aggiungi 'server_tokens off;' nel blocco http {} di /etc/nginx/nginx.conf e ricarica Nginx.",
            remediation_cmd="sudo nginx -t && sudo systemctl reload nginx",
        ),
    ]

    ports = [
        ListeningPort("tcp", "0.0.0.0", "22", "sshd", "public"),
        ListeningPort("tcp", "0.0.0.0", "80", "nginx", "public"),
        ListeningPort("tcp", "0.0.0.0", "443", "nginx", "public"),
        ListeningPort("tcp", "127.0.0.1", "5432", "postgres", "local"),
        ListeningPort("tcp", "10.8.0.1", "8080", "python3", "vpn_or_private"),
        ListeningPort("udp", "0.0.0.0", "51820", "wireguard", "public"),
    ]

    logs = LogSummary(
        sources_checked=["/var/log/auth.log (demo)", "/var/log/ufw.log (demo)"],
        failed_ssh_attempts=142,
        invalid_user_attempts=87,
        accepted_ssh_logins=6,
        sudo_commands=14,
        ufw_blocks=318,
        top_failed_ips=[
            {"ip": "203.0.113.45", "count": 94},
            {"ip": "198.51.100.12", "count": 61},
            {"ip": "192.0.2.88", "count": 39},
        ],
        top_targeted_users=[
            {"user": "root", "count": 112},
            {"user": "admin", "count": 48},
            {"user": "ubuntu", "count": 29},
        ],
        top_blocked_ports=[
            {"port": "23/tcp", "count": 124},
            {"port": "3389/tcp", "count": 78},
            {"port": "6379/tcp", "count": 52},
        ],
        recent_events=[
            {
                "timestamp": "2026-11-18T21:58:12Z",
                "type": "ssh_failed",
                "source": "203.0.113.45",
                "summary": "Password errata per utente 'root' da 203.0.113.45",
            },
            {
                "timestamp": "2026-11-18T21:55:04Z",
                "type": "ssh_invalid_user",
                "source": "198.51.100.12",
                "summary": "Tentativo con utente inesistente 'deploy' da 198.51.100.12",
            },
            {
                "timestamp": "2026-11-18T21:40:19Z",
                "type": "ssh_accepted",
                "source": "10.8.0.2",
                "summary": "Accesso SSH riuscito (publickey) per 'marco' da 10.8.0.2",
            },
            {
                "timestamp": "2026-11-18T21:41:02Z",
                "type": "sudo",
                "source": "marco",
                "summary": "sudo eseguito da 'marco': /usr/sbin/ufw status verbose",
            },
        ],
        warnings=["Modalità DEMO attiva: report Ubuntu 24.04 LTS di esempio con controlli CIS & Lynis."],
    )

    score, summary = compute_score(checks)

    return AuditReport(
        generated_at=generated_at or datetime.now(timezone.utc).isoformat(),
        hostname="ubuntu-vps-demo",
        os_info="Ubuntu 24.04.1 LTS (Demo)",
        kernel="6.8.0-49-generic",
        is_root=True,
        is_linux=True,
        demo_mode=True,
        score=score,
        summary=summary,
        checks=checks,
        listening_ports=ports,
        logs=logs,
        security_tools=build_demo_security_tools(),
    )


def seed_demo_history(store: HistoryStore) -> None:
    """Populate 2 older demo scans if no demo history exists yet."""
    if store.list_scans(limit=1, demo_only=True):
        return
    now = datetime.now(timezone.utc)
    older_1 = build_demo_report((now - timedelta(days=3)).isoformat()).to_dict()
    older_1["score"] = 58
    older_1["summary"] = {"pass": 6, "warn": 5, "fail": 4, "info": 0}
    store.save_scan(older_1)

    older_2 = build_demo_report((now - timedelta(days=1)).isoformat()).to_dict()
    older_2["score"] = 64
    older_2["summary"] = {"pass": 7, "warn": 5, "fail": 3, "info": 0}
    store.save_scan(older_2)
