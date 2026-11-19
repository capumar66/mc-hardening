#!/usr/bin/env python3
"""Local / VPN Web UI server for Ubuntu Hardening & Log Auditor.

Zero external dependencies (Python 3.8+ standard library only).
Binds to 127.0.0.1 by default to avoid accidental public exposure.
"""

from __future__ import annotations

import argparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
from pathlib import Path
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

from auditor.checks import run_audit
from auditor.demo import build_demo_report, seed_demo_history
from auditor.history import HistoryStore

STATIC_DIR = Path(__file__).resolve().parent / "static"

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
}


class AuditState:
    """Thread-safe container holding the latest audit report and history store."""

    def __init__(
        self,
        demo_mode: bool = False,
        auth_token: str | None = None,
        db_path: Path | None = None,
    ) -> None:
        self.demo_mode = demo_mode
        self.auth_token = auth_token
        self.history = HistoryStore(db_path=db_path)
        self._lock = threading.Lock()
        self._scan_lock = threading.Lock()
        self._latest: dict[str, Any] | None = None
        if self.demo_mode:
            seed_demo_history(self.history)

    def get_or_run(self) -> dict[str, Any]:
        with self._lock:
            if self._latest is not None:
                return self._latest
        return self.run_fresh()

    def run_fresh(self) -> dict[str, Any]:
        with self._scan_lock:
            t0 = time.monotonic()
            report = self._execute()
            elapsed = time.monotonic() - t0
            print(f"[audit] scansione completata in {elapsed:.2f}s (score={report.get('score')})")
            self.history.save_scan(report)
            with self._lock:
                self._latest = report
            return report

    def list_history(self) -> list[dict[str, Any]]:
        return self.history.list_scans(limit=30, demo_only=self.demo_mode)

    def get_history_scan(self, scan_id: int) -> dict[str, Any] | None:
        return self.history.get_scan(scan_id)

    def _execute(self) -> dict[str, Any]:
        if self.demo_mode:
            return build_demo_report().to_dict()
        return run_audit().to_dict()


class AuditHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], state: AuditState) -> None:
        self.state = state
        super().__init__(server_address, AuditRequestHandler)


class AuditRequestHandler(BaseHTTPRequestHandler):
    server: AuditHTTPServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        print(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}")

    def _send_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'",
        )

    def _check_auth(self, query_params: dict[str, list[str]]) -> bool:
        expected = self.server.state.auth_token
        if not expected:
            return True
        header_token = self.headers.get("X-Audit-Token", "")
        query_token = (query_params.get("token") or [""])[0]
        candidate = header_token or query_token
        return bool(candidate) and hmac.compare_digest(candidate, expected)

    def _send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._send_security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, rel_path: str) -> None:
        if rel_path in ("", "/"):
            rel_path = "index.html"
        else:
            rel_path = rel_path.lstrip("/")

        target = (STATIC_DIR / rel_path).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
            self._send_json({"error": "File non trovato"}, status=HTTPStatus.NOT_FOUND)
            return

        data = target.read_bytes()
        ctype = CONTENT_TYPES.get(target.suffix.lower(), "application/octet-stream")
        self.send_response(HTTPStatus.OK)
        self._send_security_headers()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/api/health":
            self._send_json({"status": "ok", "demo_mode": self.server.state.demo_mode})
            return

        if parsed.path == "/api/audit":
            if not self._check_auth(query):
                self._send_json({"error": "Token non valido o mancante"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._send_json(self.server.state.get_or_run())
            return

        if parsed.path == "/api/history":
            if not self._check_auth(query):
                self._send_json({"error": "Token non valido o mancante"}, status=HTTPStatus.UNAUTHORIZED)
                return
            self._send_json({"scans": self.server.state.list_history()})
            return

        if parsed.path.startswith("/api/history/"):
            if not self._check_auth(query):
                self._send_json({"error": "Token non valido o mancante"}, status=HTTPStatus.UNAUTHORIZED)
                return
            raw_id = parsed.path.rsplit("/", 1)[-1]
            if not raw_id.isdigit():
                self._send_json({"error": "ID scansione non valido"}, status=HTTPStatus.BAD_REQUEST)
                return
            scan = self.server.state.get_history_scan(int(raw_id))
            if not scan:
                self._send_json({"error": "Scansione non trovata"}, status=HTTPStatus.NOT_FOUND)
                return
            self._send_json(scan)
            return

        self._serve_static(parsed.path)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        # Drain any request body cleanly so clients never stall on unread bytes
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0
        if content_length > 0:
            self.rfile.read(min(content_length, 65536))

        if parsed.path == "/api/audit/run":
            if not self._check_auth(query):
                self._send_json({"error": "Token non valido o mancante"}, status=HTTPStatus.UNAUTHORIZED)
                return
            try:
                self._send_json(self.server.state.run_fresh())
            except Exception as exc:  # noqa: BLE001
                self._send_json(
                    {"error": f"Errore durante la scansione: {exc}"},
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            return

        self._send_json({"error": "Endpoint non trovato"}, status=HTTPStatus.NOT_FOUND)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ubuntu Server Hardening & Log Auditor (Web UI locale / VPN)"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Indirizzo di bind (default: 127.0.0.1; usa l'IP VPN es. 10.8.0.1 per accesso via VPN)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Porta HTTP di ascolto (default: 8080)",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Token segreto opzionale per proteggere le API (passabile via ?token=... o header X-Audit-Token)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Usa un report Ubuntu 24.04 di esempio (utile per testare la Web UI su macOS)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    state = AuditState(demo_mode=args.demo, auth_token=args.token)
    httpd = AuditHTTPServer((args.host, args.port), state)

    mode_label = "DEMO" if args.demo else "LIVE"
    print(f"Ubuntu Hardening Auditor [{mode_label}] in ascolto su http://{args.host}:{args.port}")
    if args.host == "0.0.0.0":
        print("ATTENZIONE: bind su 0.0.0.0! Usa 127.0.0.1 + tunnel SSH oppure l'IP della VPN.")
    if args.token:
        print(f"Autenticazione token attiva: apri http://{args.host}:{args.port}/?token=<IL_TUO_TOKEN>")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nArresto server...")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
