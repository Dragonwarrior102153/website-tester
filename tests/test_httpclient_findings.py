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

    def test_max_pages_defaults_to_ten(self):
        self.assertEqual(self.client.maxPages, 10)

    def test_max_pages_uses_custom_limit(self):
        client = HttpClient("https://example.test", 1, "2 MB", 3)
        visited = []

        def find_page_links(url):
            visited.append(url)
            if url == "https://example.test":
                return {
                    "https://example.test/page-1",
                    "https://example.test/page-2",
                }
            return set()

        with patch.object(client, "findPagesFromPage", side_effect=find_page_links):
            pages = client.findAllPages()

        self.assertEqual(client.maxPages, 3)
        self.assertEqual(len(visited), 3)
        self.assertEqual(
            pages,
            {
                "https://example.test",
                "https://example.test/page-1",
                "https://example.test/page-2",
            },
        )

    def assert_findings(self, findings):
        self.assertIsInstance(findings, list)
        self.assertTrue(all(isinstance(finding, Findings) for finding in findings))

    def test_security_headers_return_findings_and_close_response(self):
        response = FakeResponse()
        with patch.object(self.client, "getMsg", return_value=(response, b"")):
            findings = self.client.checkSecHeaders("https://example.test")

        self.assert_findings(findings)
        self.assertEqual(len(findings), 5)
        self.assertEqual(findings[0].status, "MISSING")
        self.assertTrue(response.closed)

    def test_content_security_policy_passes_restricted_policy(self):
        response = FakeResponse({
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
        })
        with patch.object(self.client, "getMsg", return_value=(response, b"")):
            findings = self.client.checkSecHeaders("https://example.test")

        cspFinding = next(finding for finding in findings if finding.name.endswith("Content-Security-Policy"))
        self.assertEqual(cspFinding.status, "PASS")
        self.assertTrue(response.closed)

    def test_content_security_policy_marks_unsafe_sources_weak(self):
        response = FakeResponse({
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'",
        })
        with patch.object(self.client, "getMsg", return_value=(response, b"")):
            findings = self.client.checkSecHeaders("https://example.test")

        cspFinding = next(finding for finding in findings if finding.name.endswith("Content-Security-Policy"))
        self.assertEqual(cspFinding.status, "WEAK")

    def test_content_security_policy_marks_missing_sources_misconfigured(self):
        response = FakeResponse({"Content-Security-Policy": "default-src"})
        with patch.object(self.client, "getMsg", return_value=(response, b"")):
            findings = self.client.checkSecHeaders("https://example.test")

        cspFinding = next(finding for finding in findings if finding.name.endswith("Content-Security-Policy"))
        self.assertEqual(cspFinding.status, "MISCONFIGURED")

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
