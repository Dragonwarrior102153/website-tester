import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parent.parent))

from findings import Findings
from httpClient import HttpClient


class FakeCookie:
    name = "session"
    secure = True
    domain = "example.test"
    path = "/"
    expires = None

    def has_nonstandard_attr(self, name):
        return name == "HttpOnly"

    def get_nonstandard_attr(self, name):
        return {"SameSite": "Lax"}.get(name)


class FakeResponse:
    def __init__(self, headers=None, cookies=None):
        self.headers = headers or {}
        self.cookies = cookies or []
        self.closed = False

    def close(self):
        self.closed = True


class HttpClientFindingsTests(unittest.TestCase):
    def setUp(self):
        self.client = HttpClient("https://example.test", 1)

    def assert_findings(self, findings):
        self.assertIsInstance(findings, list)
        self.assertTrue(all(isinstance(finding, Findings) for finding in findings))

    def test_security_headers_return_findings_and_close_response(self):
        response = FakeResponse()
        with patch.object(self.client, "getMsg", return_value=(response, b"")):
            findings = self.client.checkSecHeaders("https://example.test")

        self.assert_findings(findings)
        self.assertEqual(len(findings), 4)
        self.assertEqual(findings[0].status, "MISSING")
        self.assertTrue(response.closed)

    def test_cookies_return_findings_and_close_response(self):
        response = FakeResponse(cookies=[FakeCookie()])
        with patch.object(self.client, "getMsg", return_value=(response, b"")):
            findings = self.client.checkCookies("https://example.test")

        self.assert_findings(findings)
        self.assertEqual(findings[0].status, "OBSERVED")
        assert isinstance(findings[0].evidence, dict)
        self.assertEqual(findings[0].evidence["Name"], "session")
        self.assertTrue(response.closed)

    def test_form_security_returns_findings(self):
        with patch.object(
            self.client,
            "findForms",
            return_value=(
                [{"action": "/login", "method": "post"}],
                [[{"type": "password"}]],
            ),
        ):
            findings = self.client.checkFormSecurity("https://example.test")

        self.assert_findings(findings)
        self.assertEqual(findings[0].status, "PASS")
        assert isinstance(findings[0].evidence, dict)
        self.assertTrue(findings[0].evidence["password_exists"])

    def test_failed_request_returns_explicit_error_finding(self):
        with patch.object(self.client, "getMsg", return_value="connection failed"):
            findings = self.client.checkCookies("https://example.test")

        self.assert_findings(findings)
        self.assertEqual(findings[0].status, "ERROR")
        self.assertIn("connection failed", findings[0].description)


if __name__ == "__main__":
    unittest.main()
