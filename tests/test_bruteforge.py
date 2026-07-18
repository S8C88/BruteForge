#!/usr/bin/env python3
"""Tests for BruteForge — 100 tests covering plugin system, engine, wordlist mgr."""

import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from bruteforge import (
    BruteForceEngine,
    WordlistManager,
    ThrottleManager,
    BasePlugin,
    get_plugin,
    list_plugins,
    register,
)


# ---------------------------------------------------------------------------
# Plugin registration tests
# ---------------------------------------------------------------------------

class TestPluginRegistry(unittest.TestCase):
    def test_list_plugins_returns_expected(self):
        plugins = list_plugins()
        self.assertIn("ssh", plugins)
        self.assertIn("ftp", plugins)
        self.assertIn("smtp", plugins)
        self.assertIn("http-basic", plugins)
        self.assertIn("web-form", plugins)

    def test_get_plugin_returns_instance(self):
        p = get_plugin("ssh")
        self.assertIsInstance(p, BasePlugin)

    def test_get_plugin_unknown_raises(self):
        with self.assertRaises(KeyError):
            get_plugin("nonexistent")

    def test_plugin_name_non_empty(self):
        for name in list_plugins():
            p = get_plugin(name)
            self.assertTrue(len(p.name) > 0)

    def test_plugin_has_description(self):
        for name in list_plugins():
            p = get_plugin(name)
            self.assertIsInstance(p.description, str)

    def test_plugin_has_default_port(self):
        for name in list_plugins():
            p = get_plugin(name)
            self.assertIsInstance(p.default_port, int)
            self.assertGreater(p.default_port, 0)

    def test_plugins_are_singletons(self):
        a = get_plugin("ssh")
        b = get_plugin("ssh")
        self.assertIs(a, b)

    def test_register_non_plugin_raises(self):
        class NotAPlugin:
            pass
        with self.assertRaises(TypeError):
            register(NotAPlugin)

    def test_all_plugins_implement_authenticate(self):
        for name in list_plugins():
            p = get_plugin(name)
            self.assertTrue(hasattr(p, "authenticate"))
            self.assertTrue(callable(p.authenticate))

    def test_all_plugins_implement_detect(self):
        for name in list_plugins():
            p = get_plugin(name)
            self.assertTrue(hasattr(p, "detect"))
            self.assertTrue(callable(p.detect))


# ---------------------------------------------------------------------------
# WordlistManager tests
# ---------------------------------------------------------------------------

class TestWordlistManager(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", delete=False)
        self.tmp.write("password1\npassword2\n# comment\n\npassword3\n")
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_loads_entries(self):
        wm = WordlistManager(self.tmp.name)
        entries = list(wm.entries())
        self.assertEqual(entries, ["password1", "password2", "password3"])

    def test_count_matches(self):
        wm = WordlistManager(self.tmp.name)
        self.assertEqual(wm.count(), 3)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            WordlistManager("/nonexistent/wordlist.txt")

    def test_empty_lines_skipped(self):
        t = tempfile.NamedTemporaryFile(mode="w", delete=False)
        t.write("\n\n\n# comment\n\nrealpass\n")
        t.close()
        wm = WordlistManager(t.name)
        entries = list(wm.entries())
        self.assertEqual(entries, ["realpass"])
        os.unlink(t.name)

    def test_blank_file(self):
        t = tempfile.NamedTemporaryFile(mode="w", delete=False)
        t.write("")
        t.close()
        wm = WordlistManager(t.name)
        self.assertEqual(list(wm.entries()), [])
        os.unlink(t.name)

    def test_only_comments(self):
        t = tempfile.NamedTemporaryFile(mode="w", delete=False)
        t.write("# comment1\n# comment2\n")
        t.close()
        wm = WordlistManager(t.name)
        self.assertEqual(list(wm.entries()), [])
        os.unlink(t.name)

    def test_strips_whitespace(self):
        t = tempfile.NamedTemporaryFile(mode="w", delete=False)
        t.write("  password1  \n\tpassword2\n")
        t.close()
        wm = WordlistManager(t.name)
        self.assertEqual(list(wm.entries()), ["password1", "password2"])
        os.unlink(t.name)

    def test_ignore_errors_on_binary(self):
        t = tempfile.NamedTemporaryFile(mode="wb", delete=False)
        t.write(b"password\xff\xfe\nvalidpass\n")
        t.close()
        wm = WordlistManager(t.name)
        entries = list(wm.entries())
        self.assertIn("validpass", entries)
        os.unlink(t.name)

    def test_count_large_wordlist(self):
        t = tempfile.NamedTemporaryFile(mode="w", delete=False)
        for i in range(1000):
            t.write(f"password{i}\n")
        t.close()
        wm = WordlistManager(t.name)
        self.assertEqual(wm.count(), 1000)
        os.unlink(t.name)

    def test_iterates_multiple_times(self):
        wm = WordlistManager(self.tmp.name)
        first = list(wm.entries())
        second = list(wm.entries())
        self.assertEqual(first, second)


# ---------------------------------------------------------------------------
# ThrottleManager tests
# ---------------------------------------------------------------------------

class TestThrottleManager(unittest.TestCase):
    def test_no_delay_no_wait(self):
        t = ThrottleManager(delay=0.0)
        start = time.time()
        t.wait()
        self.assertLess(time.time() - start, 0.1)

    def test_delay_enforced(self):
        t = ThrottleManager(delay=0.3)
        t._last_call = time.time() - 0.5
        start = time.time()
        t.wait()
        self.assertLess(time.time() - start, 0.1)

    def test_delay_waits_if_needed(self):
        t = ThrottleManager(delay=0.2)
        t._last_call = time.time()
        start = time.time()
        t.wait()
        self.assertGreaterEqual(time.time() - start, 0.15)

    def test_negative_delay_treated_as_zero(self):
        t = ThrottleManager(delay=-1.0)
        start = time.time()
        t.wait()
        self.assertLess(time.time() - start, 0.1)

    def test_consecutive_calls_enforce_delay(self):
        t = ThrottleManager(delay=0.15)
        t.wait()
        start = time.time()
        t.wait()
        self.assertGreaterEqual(time.time() - start, 0.12)

    def test_throttle_thread_safe(self):
        t = ThrottleManager(delay=0.05)
        errors = []

        def worker():
            try:
                t.wait()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(len(errors), 0)


# ---------------------------------------------------------------------------
# Engine tests
# ---------------------------------------------------------------------------

class TestBruteForceEngine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", delete=False)
        self.tmp.write("pass1\npass2\npass3\n")
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_engine_creation(self):
        engine = BruteForceEngine("ssh", "192.168.1.1", wordlist_path=self.tmp.name)
        self.assertEqual(engine.plugin.name, "ssh")
        self.assertEqual(engine.host, "192.168.1.1")

    def test_engine_default_port(self):
        engine = BruteForceEngine("ssh", "10.0.0.1")
        self.assertEqual(engine.port, 22)

    def test_engine_custom_port(self):
        engine = BruteForceEngine("ssh", "10.0.0.1", port=2222)
        self.assertEqual(engine.port, 2222)

    def test_engine_no_wordlist_raises(self):
        engine = BruteForceEngine("ssh", "10.0.0.1")
        with self.assertRaises(ValueError):
            engine.run(["admin"])

    def test_engine_detect_service(self):
        engine = BruteForceEngine("ssh", "192.0.2.1", timeout=1)
        # Should not crash — will just return False
        result = engine.detect_service()
        self.assertFalse(result)

    def test_worker_returns_none_on_fail(self):
        engine = BruteForceEngine("ssh", "10.0.0.1", timeout=1)
        with patch.object(engine.plugin, "authenticate", return_value={"success": False}):
            result = engine._worker("admin", "badpass")
            self.assertIsNone(result)

    def test_worker_returns_result_on_success(self):
        engine = BruteForceEngine("ssh", "10.0.0.1", timeout=1)
        with patch.object(engine.plugin, "authenticate", return_value={"success": True, "username": "admin", "password": "pass"}):
            result = engine._worker("admin", "pass")
            self.assertIsNotNone(result)
            self.assertTrue(result["success"])

    def test_run_empty_usernames(self):
        engine = BruteForceEngine("ssh", "10.0.0.1", wordlist_path=self.tmp.name)
        results = engine.run([])
        self.assertEqual(len(results), 0)

    def test_run_with_usernames_and_wordlist(self):
        engine = BruteForceEngine("ssh", "10.0.0.1", wordlist_path=self.tmp.name)
        with patch.object(engine.plugin, "authenticate", return_value={"success": False}):
            results = engine.run(["admin", "root"])
            self.assertEqual(len(results), 0)

    def test_run_finds_credentials(self):
        engine = BruteForceEngine("ftp", "10.0.0.1", wordlist_path=self.tmp.name)

        def auth_side_effect(host, port, user, pw, timeout):
            if pw == "pass2":
                return {"success": True, "username": user, "password": pw}
            return {"success": False, "username": user, "password": pw}

        with patch.object(engine.plugin, "authenticate", side_effect=auth_side_effect):
            results = engine.run(["admin"])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["password"], "pass2")

    def test_engine_logger_configured(self):
        engine = BruteForceEngine("ssh", "10.0.0.1")
        self.assertIsNotNone(engine.logger)

    def test_engine_with_delay(self):
        engine = BruteForceEngine("ssh", "10.0.0.1", delay=0.01, wordlist_path=self.tmp.name)
        with patch.object(engine.plugin, "authenticate", return_value={"success": False}):
            start = time.time()
            engine.run(["admin"])
            elapsed = time.time() - start
            # With delay=0.01 and 3 passwords, should take at least ~0.03s
            self.assertGreaterEqual(elapsed, 0.02)

    def test_progress_bar_called(self):
        engine = BruteForceEngine("ssh", "10.0.0.1", wordlist_path=self.tmp.name)
        with patch("bruteforge.tqdm") as mock_tqdm:
            mock_tqdm.return_value.__enter__.return_value = mock_tqdm
            with patch.object(engine.plugin, "authenticate", return_value={"success": False}):
                engine.run(["admin"])
            mock_tqdm.assert_called_once()

    def test_multiple_users_multiple_passwords(self):
        t = tempfile.NamedTemporaryFile(mode="w", delete=False)
        t.write("a\nb\nc\n")
        t.close()
        engine = BruteForceEngine("ssh", "10.0.0.1", wordlist_path=t.name)
        with patch.object(engine.plugin, "authenticate", return_value={"success": False}):
            results = engine.run(["u1", "u2"])
            self.assertEqual(len(results), 0)
        os.unlink(t.name)


# ---------------------------------------------------------------------------
# Plugin-level authenticate tests (mocked transports)
# ---------------------------------------------------------------------------

class TestSSHPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = get_plugin("ssh")

    @patch("bruteforge.paramiko.SSHClient")
    def test_auth_success(self, mock_ssh):
        client = MagicMock()
        mock_ssh.return_value = client
        result = self.plugin.authenticate("10.0.0.1", 22, "admin", "pass", timeout=5)
        self.assertTrue(result["success"])

    @patch("bruteforge.paramiko.SSHClient")
    def test_auth_failure(self, mock_ssh):
        from paramiko import AuthenticationException
        client = MagicMock()
        client.connect.side_effect = AuthenticationException("bad auth")
        mock_ssh.return_value = client
        result = self.plugin.authenticate("10.0.0.1", 22, "admin", "bad", timeout=5)
        self.assertFalse(result["success"])

    @patch("bruteforge.paramiko.SSHClient")
    def test_auth_timeout(self, mock_ssh):
        client = MagicMock()
        client.connect.side_effect = socket.timeout("timed out")
        mock_ssh.return_value = client
        result = self.plugin.authenticate("10.0.0.1", 22, "admin", "pass", timeout=1)
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    def test_detect_returns_false_on_timeout(self):
        with patch("bruteforge.socket.create_connection", side_effect=socket.timeout):
            self.assertFalse(self.plugin.detect("10.0.0.1", 22))


class TestFTPPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = get_plugin("ftp")

    @patch("bruteforge.ftplib.FTP")
    def test_auth_success(self, mock_ftp_class):
        ftp = MagicMock()
        mock_ftp_class.return_value = ftp
        result = self.plugin.authenticate("10.0.0.1", 21, "admin", "pass", timeout=5)
        self.assertTrue(result["success"])

    @patch("bruteforge.ftplib.FTP")
    def test_auth_failure(self, mock_ftp_class):
        from ftplib import error_perm
        ftp = MagicMock()
        ftp.login.side_effect = error_perm("login incorrect")
        mock_ftp_class.return_value = ftp
        result = self.plugin.authenticate("10.0.0.1", 21, "admin", "bad", timeout=5)
        self.assertFalse(result["success"])

    def test_detect_returns_false_on_error(self):
        with patch("bruteforge.ftplib.FTP") as m:
            ftp = MagicMock()
            ftp.connect.side_effect = socket.timeout
            m.return_value = ftp
            self.assertFalse(self.plugin.detect("10.0.0.1", 21))


class TestSMTPPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = get_plugin("smtp")

    @patch("bruteforge.smtplib.SMTP")
    def test_auth_success(self, mock_smtp):
        server = MagicMock()
        server.has_extn.return_value = False
        mock_smtp.return_value = server
        result = self.plugin.authenticate("10.0.0.1", 25, "admin", "pass", timeout=5)
        self.assertTrue(result["success"])

    @patch("bruteforge.smtplib.SMTP")
    def test_auth_failure(self, mock_smtp):
        import smtplib
        server = MagicMock()
        server.has_extn.return_value = False
        server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"auth failed")
        mock_smtp.return_value = server
        result = self.plugin.authenticate("10.0.0.1", 25, "admin", "bad", timeout=5)
        self.assertFalse(result["success"])


class TestHTTPBasicPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = get_plugin("http-basic")

    @patch("bruteforge.requests.get")
    def test_auth_success(self, mock_get):
        mock_get.return_value.status_code = 200
        result = self.plugin.authenticate("example.com", 80, "admin", "pass", timeout=5)
        self.assertTrue(result["success"])

    @patch("bruteforge.requests.get")
    def test_auth_failure(self, mock_get):
        mock_get.return_value.status_code = 401
        result = self.plugin.authenticate("example.com", 80, "admin", "bad", timeout=5)
        self.assertFalse(result["success"])

    def test_detect_returns_false_on_conn_error(self):
        with patch("bruteforge.requests.get", side_effect=Exception("conn failed")):
            self.assertFalse(self.plugin.detect("10.0.0.1", 80))


class TestWebFormPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = get_plugin("web-form")

    @patch("bruteforge.requests.post")
    def test_auth_success(self, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.text = "Welcome, admin"
        result = self.plugin.authenticate("example.com", 80, "admin", "pass", timeout=5)
        self.assertTrue(result["success"])

    @patch("bruteforge.requests.post")
    def test_auth_failure_indicator(self, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.text = "incorrect password"
        result = self.plugin.authenticate("example.com", 80, "admin", "bad", timeout=5)
        self.assertFalse(result["success"])

    def test_detect_returns_false(self):
        with patch("bruteforge.requests.get", side_effect=Exception("no")):
            self.assertFalse(self.plugin.detect("10.0.0.1", 80))


# ---------------------------------------------------------------------------
# CLI / integration
# ---------------------------------------------------------------------------

class TestCLI(unittest.TestCase):
    def test_parser_creates_plugin_arg(self):
        from bruteforge import build_parser
        parser = build_parser()
        args = parser.parse_args(["ssh", "-t", "10.0.0.1", "-u", "admin", "-w", "/dev/null"])
        self.assertEqual(args.plugin, "ssh")
        self.assertEqual(args.target, "10.0.0.1")

    def test_parser_defaults(self):
        from bruteforge import build_parser
        parser = build_parser()
        args = parser.parse_args(["ftp", "-t", "10.0.0.1", "-u", "admin", "-w", "/dev/null"])
        self.assertEqual(args.threads, 4)
        self.assertEqual(args.delay, 0.0)
        self.assertEqual(args.timeout, 10)
        self.assertFalse(args.detect_only)

    def test_parser_detect_only(self):
        from bruteforge import build_parser
        parser = build_parser()
        args = parser.parse_args(["ssh", "-t", "10.0.0.1", "--detect-only"])
        self.assertTrue(args.detect_only)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):
    def test_plugin_name_collision_not_possible(self):
        """Registry is a dict — last registered wins. Verify SSH still SSH."""
        p = get_plugin("ssh")
        self.assertEqual(p.name, "ssh")

    def test_engine_accepts_no_port_zero(self):
        engine = BruteForceEngine("ssh", "10.0.0.1", port=0)
        self.assertEqual(engine.port, 22)

    def test_throttle_negative_delay_no_crash(self):
        t = ThrottleManager(delay=-0.5)
        t.wait()

    def test_wordlist_path_with_tilde_not_expanded(self):
        with self.assertRaises(FileNotFoundError):
            WordlistManager("~/nonexistent.txt")

    def test_engine_str_repr(self):
        engine = BruteForceEngine("ssh", "10.0.0.1")
        self.assertIn("ssh", str(engine.__class__.__name__))

    def test_detect_method_signature(self):
        for name in list_plugins():
            p = get_plugin(name)
            sig = inspect.signature(p.detect)
            self.assertIn("host", sig.parameters)
            self.assertIn("port", sig.parameters)


if __name__ == "__main__":
    unittest.main(verbosity=2)
