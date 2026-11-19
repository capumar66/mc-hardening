"""Unit tests for Ubuntu Hardening & Log Auditor."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from auditor.checks import _classify_bind_address, parse_sshd_config_text
from auditor.demo import build_demo_report
from auditor.history import HistoryStore
from auditor.logs import parse_auth_lines, parse_ufw_lines
from auditor.models import CheckResult, LogSummary, compute_score
from server import AuditHTTPServer, AuditState


class TestSshdParser(unittest.TestCase):
    def test_first_match_wins_and_ignores_match_block(self) -> None:
        lines = [
            "# Comment line",
            "PermitRootLogin no",
            "PasswordAuthentication no # inline comment",
            "PermitRootLogin yes",  # Must be ignored (OpenSSH first-match-wins)
            "MaxAuthTries 3",
            "Match User backup",
            "    PasswordAuthentication yes",
        ]
        cfg = parse_sshd_config_text(lines)
        self.assertEqual(cfg["permitrootlogin"], "no")
        self.assertEqual(cfg["passwordauthentication"], "no")
        self.assertEqual(cfg["maxauthtries"], "3")


class TestLogParsers(unittest.TestCase):
    def test_parse_auth_lines(self) -> None:
        sample = [
            "2026-11-18T10:00:01Z vps sshd[101]: Failed password for root from 203.0.113.10 port 51234 ssh2",
            "2026-11-18T10:00:05Z vps sshd[102]: Invalid user admin from 203.0.113.10 port 51235",
            "2026-11-18T10:01:00Z vps sshd[103]: Accepted publickey for marco from 10.8.0.2 port 55000 ssh2",
            "2026-11-18T10:02:10Z vps sudo:   marco : TTY=pts/0 ; PWD=/home/marco ; USER=root ; COMMAND=/usr/sbin/ufw status",
        ]
        summary = LogSummary()
        parse_auth_lines(sample, summary)

        self.assertEqual(summary.failed_ssh_attempts, 1)
        self.assertEqual(summary.invalid_user_attempts, 1)
        self.assertEqual(summary.accepted_ssh_logins, 1)
        self.assertEqual(summary.sudo_commands, 1)
        self.assertEqual(summary.top_failed_ips[0], {"ip": "203.0.113.10", "count": 2})
        self.assertEqual(len(summary.recent_events), 4)

    def test_parse_ufw_lines(self) -> None:
        sample = [
            "Nov 18 10:00:00 vps kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.5 DST=1.2.3.4 PROTO=TCP SPT=44444 DPT=23",
            "Nov 18 10:00:01 vps kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.6 DST=1.2.3.4 PROTO=TCP SPT=44445 DPT=23",
            "Nov 18 10:00:02 vps kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.7 DST=1.2.3.4 PROTO=UDP SPT=5353 DPT=53",
        ]
        summary = LogSummary()
        parse_ufw_lines(sample, summary)
        self.assertEqual(summary.ufw_blocks, 3)
        self.assertEqual(summary.top_blocked_ports[0], {"port": "23/tcp", "count": 2})


class TestScoringAndBindClassification(unittest.TestCase):
    def test_compute_score(self) -> None:
        checks = [
            CheckResult("1", "SSH", "t1", "pass", "high", "ok"),
            CheckResult("2", "SSH", "t2", "fail", "high", "bad"),
            CheckResult("3", "SSH", "t3", "info", "info", "info"),
        ]
        score, counts = compute_score(checks)
        self.assertEqual(score, 50)
        self.assertEqual(counts, {"pass": 1, "warn": 0, "fail": 1, "info": 1})

    def test_classify_bind_address(self) -> None:
        self.assertEqual(_classify_bind_address("0.0.0.0"), "public")
        self.assertEqual(_classify_bind_address("::"), "public")
        self.assertEqual(_classify_bind_address("127.0.0.1"), "local")
        self.assertEqual(_classify_bind_address("::1"), "local")
        self.assertEqual(_classify_bind_address("10.8.0.1"), "vpn_or_private")

    def test_demo_report(self) -> None:
        report = build_demo_report()
        self.assertTrue(report.demo_mode)
        self.assertGreater(len(report.checks), 5)
        self.assertGreater(report.score, 0)


class TestHistoryStore(unittest.TestCase):
    def test_save_list_and_delta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = HistoryStore(db_path=Path(tmp) / "history.db")
            r1 = build_demo_report().to_dict()
            r1["score"] = 60
            r2 = build_demo_report().to_dict()
            r2["score"] = 72
            id1 = store.save_scan(r1)
            id2 = store.save_scan(r2)

            scans = store.list_scans(limit=10)
            self.assertEqual(len(scans), 2)
            self.assertEqual(scans[0]["id"], id2)
            self.assertEqual(scans[0]["delta"], 12)
            self.assertEqual(scans[1]["id"], id1)
            self.assertEqual(store.get_scan(id1)["score"], 60)


class TestHTTPServer(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        db_path = Path(self._tmp.name) / "test_history.db"
        self.state = AuditState(demo_mode=True, auth_token="secret-test-token", db_path=db_path)
        self.httpd = AuditHTTPServer(("127.0.0.1", 0), self.state)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        self._tmp.cleanup()

    def test_token_required_and_valid_audit_response(self) -> None:
        base = f"http://127.0.0.1:{self.port}"

        with self.assertRaises(HTTPError) as ctx:
            urlopen(f"{base}/api/audit")
        self.assertEqual(ctx.exception.code, 401)

        req = Request(f"{base}/api/audit", headers={"X-Audit-Token": "secret-test-token"})
        with urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
            payload = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(payload["demo_mode"])
            self.assertIn("checks", payload)
            self.assertIn("logs", payload)

        hist_req = Request(f"{base}/api/history", headers={"X-Audit-Token": "secret-test-token"})
        with urlopen(hist_req) as resp:
            self.assertEqual(resp.status, 200)
            hist = json.loads(resp.read().decode("utf-8"))
            self.assertGreaterEqual(len(hist["scans"]), 3)

        post_req = Request(
            f"{base}/api/audit/run",
            data=b"",
            method="POST",
            headers={"X-Audit-Token": "secret-test-token"},
        )
        with urlopen(post_req) as resp:
            self.assertEqual(resp.status, 200)
            fresh = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(fresh["demo_mode"])

    def test_serves_index_html(self) -> None:
        base = f"http://127.0.0.1:{self.port}"
        with urlopen(f"{base}/") as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read().decode("utf-8")
            self.assertIn("SecServer", body)


if __name__ == "__main__":
    unittest.main()
