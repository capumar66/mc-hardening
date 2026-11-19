"""Detailed Italian security explanations for CIS Benchmark & Lynis checks."""

from __future__ import annotations

CHECK_EXPLANATIONS: dict[str, dict[str, str]] = {
    "ssh-permit-root": {
        "why": "L'account root esiste su ogni sistema Linux ed è il primo bersaglio di attacchi automatici. Disabilitarne l'accesso SSH diretto obbliga gli amministratori ad accedere con un utente nominativo e usare sudo, migliorando tracciabilità e sicurezza.",
        "impact": "Prima di disabilitarlo, verifica di avere un utente non-root nel gruppo sudo con accesso SSH funzionante.",
    },
    "ssh-password-auth": {
        "why": "L'autenticazione via password è vulnerabile a brute-force, credential stuffing e password deboli. Le chiavi SSH (es. Ed25519) eliminano quasi totalmente questa superficie d'attacco.",
        "impact": "Verifica sempre in una seconda sessione SSH che la tua chiave pubblica funzioni prima di disabilitare le password.",
    },
    "ssh-empty-passwords": {
        "why": "Consentire password vuote permette l'accesso senza credenziali a qualsiasi account privo di password configurata.",
        "impact": "Nessun impatto operativo negativo; deve rimanere sempre su 'no'.",
    },
    "ssh-max-auth-tries": {
        "why": "Limita il numero di tentativi di autenticazione falliti per singola connessione TCP, rallentando attacchi brute-force e attivando più rapidamente Fail2ban.",
        "impact": "Se usi molte chiavi SSH nell'agent locale, imposta 'IdentitiesOnly yes' nel tuo ~/.ssh/config per evitare errori 'Too many authentication failures'.",
    },
    "ssh-x11-forwarding": {
        "why": "L'inoltro grafico X11 amplia la superficie d'attacco del server SSH ed è inutile su VPS server headless.",
        "impact": "Nessun impatto su server privi di ambiente grafico.",
    },
    "ssh-loglevel": {
        "why": "LogLevel VERBOSE registra anche il fingerprint della chiave SSH usata in ogni accesso, fondamentale in caso di audit o incident response.",
        "impact": "Leggero incremento del volume di /var/log/auth.log, trascurabile su VPS moderni.",
    },
    "fw-ufw-status": {
        "why": "Un firewall host-based con policy 'default deny incoming' impedisce che nuovi servizi avviati per errore (database, pannelli admin, container Docker) vengano esposti su Internet.",
        "impact": "Consenti sempre prima SSH e la porta VPN (es. WireGuard) prima di eseguire 'ufw enable'.",
    },
    "fw-nftables": {
        "why": "nftables è il framework firewall nativo del kernel Linux moderno; un ruleset restrittivo limita il traffico in ingresso alle sole porte autorizzate.",
        "impact": "Verifica periodicamente che le regole vengano persistite al riavvio.",
    },
    "ips-fail2ban": {
        "why": "Fail2ban analizza i log (SSH, Nginx, ecc.) e blocca temporaneamente nel firewall gli IP che eseguono ripetuti tentativi di accesso falliti o scansioni.",
        "impact": "Aggiungi l'IP della tua VPN o rete fidata a 'ignoreip' in /etc/fail2ban/jail.local per evitare auto-ban.",
    },
    "mac-apparmor": {
        "why": "AppArmor (Mandatory Access Control) confina i processi di sistema (Nginx, MySQL, systemd, ecc.) limitando i file e le risorse a cui possono accedere anche in caso di compromissione.",
        "impact": "Attivo di default su Ubuntu; alcuni servizi personalizzati possono richiedere un profilo dedicato.",
    },
    "pam-pwquality": {
        "why": "pam_pwquality impone lunghezza minima e complessità alle password degli account locali, prevenendo credenziali banali per utenti con privilegi sudo.",
        "impact": "Si applica solo alle nuove password o ai cambi password, senza interrompere gli account esistenti.",
    },
    "pam-pass-max-days": {
        "why": "Definisce la validità massima delle password locali in /etc/login.defs, riducendo la finestra di rischio in caso di compromissione silenziosa.",
        "impact": "Imposta un valore realistico (es. 90-365 giorni) per evitare scadenze impreviste su account di servizio.",
    },
    "updates-unattended": {
        "why": "Gli aggiornamenti automatici applicano tempestivamente le patch di sicurezza critiche del repository Ubuntu security, riducendo l'esposizione a CVE note.",
        "impact": "Configura le notifiche o controlla /var/run/reboot-required per i riavvii kernel.",
    },
    "updates-apt-pending": {
        "why": "Pacchetti con patch di sicurezza pendenti (es. OpenSSL, OpenSSH, kernel) lasciano vulnerabilità pubblicamente sfruttabili sul server.",
        "impact": "Esegui 'apt upgrade' in una finestra di manutenzione; alcuni aggiornamenti riavviano i servizi interessati.",
    },
    "updates-reboot-required": {
        "why": "Gli aggiornamenti del kernel Linux o di libc diventano effettivi solo dopo il riavvio del sistema.",
        "impact": "Pianifica un riavvio controllato per evitare downtime imprevisto.",
    },
    "cron-permissions": {
        "why": "Se utenti non privilegiati possono modificare /etc/crontab o /etc/cron.d, possono ottenere facilmente una privilege escalation a root.",
        "impact": "Nessun impatto sui job legittimi eseguiti da root.",
    },
    "cron-allow-restricted": {
        "why": "La presenza di /etc/cron.allow abilita una whitelist esplicita: solo gli utenti elencati possono creare crontab, impedendo meccanismi di persistenza da account di servizio compromessi.",
        "impact": "Aggiungi in /etc/cron.allow gli eventuali utenti applicativi che usano crontab.",
    },
    "sysctl-syncookies": {
        "why": "tcp_syncookies protegge lo stack TCP da attacchi SYN flood evitando l'esaurimento della coda di connessioni half-open.",
        "impact": "Nessun impatto negativo; standard sui server esposti in rete.",
    },
    "sysctl-accept-redirects": {
        "why": "Disabilitare gli ICMP redirect impedisce ad attaccanti sulla stessa rete di alterare le tabelle di routing del server (attacchi MITM).",
        "impact": "Nessun impatto sui normali VPS single-homed.",
    },
    "sysctl-rp-filter": {
        "why": "Reverse Path Filtering scarta i pacchetti con indirizzo sorgente spoofato non coerente con la tabella di routing.",
        "impact": "Su server con routing asimmetrico complesso o multi-VPN potrebbe richiedere valore '2' (loose mode) anziché '1'.",
    },
    "sysctl-dmesg-restrict": {
        "why": "Limita la lettura del ring buffer del kernel (dmesg) al solo utente root, evitando che utenti locali raccolgano indirizzi di memoria utili a exploit kernel.",
        "impact": "Solo root (o utenti con CAP_SYSLOG) potranno eseguire dmesg.",
    },
    "perm-shadow": {
        "why": "/etc/shadow contiene gli hash delle password di sistema: deve essere leggibile solo da root (e gruppo shadow) per impedire cracking offline.",
        "impact": "Permessi standard Ubuntu: 640 root:shadow (o 600 root:root).",
    },
    "perm-passwd": {
        "why": "/etc/passwd deve essere scrivibile esclusivamente da root; permessi di scrittura errati consentono di creare utenti privilegiati.",
        "impact": "Permessi standard: 644 root:root.",
    },
    "perm-sshd": {
        "why": "Proteggere /etc/ssh/sshd_config da modifiche non autorizzate garantisce che le policy di accesso SSH non vengano indebolite.",
        "impact": "Permessi consigliati: 600 o 644 di proprietà root:root.",
    },
    "acct-uid-zero": {
        "why": "Qualsiasi account con UID 0 possiede pieni privilegi di superutente equivalenti a root. Solo 'root' dovrebbe avere UID 0.",
        "impact": "Verifica subito eventuali altri utenti con UID 0: possono indicare configurazioni errate o backdoor.",
    },
    "docker-sock-perms": {
        "why": "L'accesso a /var/run/docker.sock equivale a privilegi root completi sull'host (è possibile montare '/' in un container).",
        "impact": "Mantieni permessi 660 root:docker e limita al minimo gli utenti nel gruppo docker.",
    },
    "docker-no-new-priv": {
        "why": "Impedisce ai processi dentro i container di acquisire nuovi privilegi tramite binari SUID/SGID o capabilities.",
        "impact": "Alcuni container legacy potrebbero richiedere eccezioni mirate.",
    },
    "nginx-server-tokens": {
        "why": "Nasconde la versione esatta di Nginx negli header HTTP e nelle pagine di errore, riducendo il fingerprinting automatico.",
        "impact": "Nessun impatto funzionale sulle applicazioni web.",
    },
    "nginx-tls-protocols": {
        "why": "TLS 1.0 e TLS 1.1 sono protocolli deprecati e vulnerabili; consentire solo TLS 1.2 e TLS 1.3 protegge il traffico HTTPS.",
        "impact": "Tutti i browser e client moderni supportano TLS 1.2/1.3.",
    },
    "net-public-ports": {
        "why": "Ogni socket in ascolto su 0.0.0.0 o :: accetta connessioni da tutte le interfacce di rete. Ridurre i servizi esposti limita la superficie d'attacco.",
        "impact": "Configura database, cache e pannelli interni per ascoltare solo su 127.0.0.1 o sull'IP della VPN.",
    },
}


def get_explanation(check_id: str) -> dict[str, str]:
    """Return structured Italian explanation for a check id if available."""
    return CHECK_EXPLANATIONS.get(check_id, {})
