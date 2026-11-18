# Ubuntu Hardening & Log Auditor (Web UI locale / VPN)

Strumento **in sola lettura** scritto in Python puro (zero dipendenze esterne, solo libreria standard Python 3.8+) con interfaccia Web per verificare lo stato di hardening e analizzare i log di un server **Ubuntu Linux**.

## Cosa controlla
- **OpenSSH** (`sshd -T` o `/etc/ssh/sshd_config` + `sshd_config.d/*.conf`): `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `X11Forwarding`, `MaxAuthTries`, `Port`.
- **Firewall**: stato e policy di default di `ufw` (con fallback su `nftables`).
- **Protezione intrusioni**: stato servizio `fail2ban`.
- **Aggiornamenti automatici**: configurazione `unattended-upgrades`.
- **Kernel & Rete (`sysctl`)**: `tcp_syncookies`, `accept_redirects`, `send_redirects`, `rp_filter`, `dmesg_restrict`.
- **Permessi & Account**: permessi di `/etc/shadow`, `/etc/passwd`, `/etc/ssh/sshd_config` e verifica di eventuali account extra con UID 0.
- **Servizi in ascolto (`ss -tulnp`)**: elenco socket TCP/UDP locali con indicazione di esposizione (`0.0.0.0` / `::` vs `127.0.0.1` vs rete privata/VPN).
- **Analisi Log**: `/var/log/auth.log` (o `journalctl -u ssh`), `/var/log/ufw.log` / `/var/log/kern.log` per tentativi SSH falliti, utenti inesistenti, accessi riusciti, comandi `sudo` e porte bloccate da UFW.

## 1. Anteprima sul tuo Mac (modalità Demo)
Puoi provare subito la Web UI sul Mac con dati realistici Ubuntu 24.04 LTS:

```bash
python3 server.py --demo --host 127.0.0.1 --port 8080
```

Poi apri nel browser: `http://127.0.0.1:8080`

## 2. Deploy e avvio sul server Ubuntu

Copia la cartella sul VPS Ubuntu (es. via `scp`):

```bash
scp -r /Users/marcocapuano/Antigravity/secserverver utente@<IP_SERVER>:~/secserverver
```

### Opzione A — Solo localhost + Tunnel SSH (consigliata)
Sul server Ubuntu (con `sudo` per leggere `sshd -T`, `ufw`, `/var/log/auth.log` e i nomi dei processi in `ss`):

```bash
cd ~/secserverver
sudo python3 server.py --host 127.0.0.1 --port 8080
```

Sul tuo Mac apri un tunnel SSH:

```bash
ssh -L 8080:127.0.0.1:8080 utente@<IP_SERVER>
```

Apri `http://127.0.0.1:8080` sul tuo Mac. Il servizio non è mai esposto su Internet.

### Opzione B — Accesso via VPN (WireGuard / Tailscale) con Token
Sul server Ubuntu, lega il server solo all'IP dell'interfaccia VPN e aggiungi un token segreto:

```bash
cd ~/secserverver
sudo python3 server.py --host <IP_VPN_DEL_SERVER> --port 8080 --token "un-token-lungo-e-casuale"
```

Poi apri dal tuo Mac connesso alla VPN:
`http://<IP_VPN_DEL_SERVER>:8080/?token=un-token-lungo-e-casuale`

## Test automatici

```bash
python3 -m unittest discover -s tests -v
```
