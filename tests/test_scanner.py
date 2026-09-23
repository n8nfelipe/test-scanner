import unittest
from unittest.mock import patch

from scanner import ScanError, _validate_url, _resolve_public


class ScannerSafetyTests(unittest.TestCase):
    def test_adds_https_when_scheme_is_missing(self):
        normalized, host, port, scheme = _validate_url("example.com/path")
        self.assertEqual(normalized, "https://example.com/path")
        self.assertEqual((host, port, scheme), ("example.com", 443, "https"))

    def test_rejects_credentials_and_unsupported_schemes(self):
        with self.assertRaises(ScanError):
            _validate_url("https://user:pass@example.com")
        with self.assertRaises(ScanError):
            _validate_url("file:///etc/passwd")

    def test_rejects_private_literal(self):
        with self.assertRaises(ScanError):
            _resolve_public("192.168.1.5", 80)

    def test_accepts_localhost_with_custom_port(self):
        normalized, host, port, scheme = _validate_url("http://localhost:3000")
        self.assertEqual(normalized, "http://localhost:3000/")
        self.assertEqual((host, port, scheme), ("localhost", 3000, "http"))

    @patch("scanner.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 3000))])
    def test_allows_localhost_to_resolve_to_loopback(self, _mock_getaddrinfo):
        self.assertEqual(_resolve_public("localhost", 3000), ["127.0.0.1"])

    @patch("scanner.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("192.168.1.5", 3000))])
    def test_rejects_localhost_resolving_elsewhere(self, _mock_getaddrinfo):
        with self.assertRaises(ScanError):
            _resolve_public("localhost", 3000)

    @patch("scanner.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("192.168.1.5", 443))])
    def test_rejects_hostname_resolving_private(self, _mock_getaddrinfo):
        with self.assertRaises(ScanError):
            _resolve_public("internal.example", 443)


if __name__ == "__main__":
    unittest.main()
