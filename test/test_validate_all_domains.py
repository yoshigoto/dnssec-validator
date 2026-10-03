import contextlib
import io
import json
import unittest
import urllib.error
from email.message import Message
from unittest.mock import MagicMock, patch

import validate_all_domains as validator


class ValidateAllDomainsTests(unittest.TestCase):
    def http_error(self, status=429, retry_after="43", body=None):
        headers = Message()
        if retry_after is not None:
            headers["Retry-After"] = retry_after
        if body is None:
            body = json.dumps({"error": "request limited"}).encode()
        return urllib.error.HTTPError(
            "http://localhost/api/validate", status, "HTTP error", headers, io.BytesIO(body)
        )

    def response(self, success=True):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = json.dumps({"success": success, "logs": []}).encode()
        return response

    def test_retry_after_then_success_preserves_request(self):
        with patch.object(validator.urllib.request, "urlopen", side_effect=[
            self.http_error(), self.response()
        ]) as urlopen, patch.object(validator.time, "sleep") as sleep, \
                patch.object(validator.time, "monotonic", side_effect=[100, 143.25]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            result = validator.validate_domain("http://localhost:3002/", "example.test", timeout=12)
        self.assertEqual(result["status"], 200)
        self.assertTrue(result["success"])
        self.assertEqual(result["elapsed"], 43250)
        sleep.assert_called_once_with(43)
        self.assertIn("HTTP 429", output.getvalue())
        self.assertEqual(urlopen.call_count, 2)
        for call in urlopen.call_args_list:
            request = call.args[0]
            self.assertEqual(request.full_url, "http://localhost:3002/api/validate")
            self.assertEqual(json.loads(request.data), {"domain": "example.test"})
            self.assertEqual(call.kwargs["timeout"], 12)

    def test_missing_or_invalid_retry_after_falls_back_to_60_seconds(self):
        for header in (None, "", "invalid", "-1"):
            with self.subTest(header=header), \
                    patch.object(validator.urllib.request, "urlopen", side_effect=[
                        self.http_error(retry_after=header), self.response(False)
                    ]), patch.object(validator.time, "sleep") as sleep, \
                    contextlib.redirect_stdout(io.StringIO()):
                result = validator.validate_domain("http://localhost", "example.test")
                self.assertFalse(result["success"])
                self.assertEqual(result["status"], 200)
                sleep.assert_called_once_with(60)

    def test_non_json_429_is_also_retried(self):
        with patch.object(validator.urllib.request, "urlopen", side_effect=[
            self.http_error(retry_after="0", body=b"Too many requests"), self.response()
        ]), patch.object(validator.time, "sleep") as sleep, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(validator.validate_domain("http://localhost", "example.test")["status"], 200)
        sleep.assert_called_once_with(1)

    def test_retries_are_bounded_and_can_be_disabled(self):
        for retries in (0, 3):
            with self.subTest(retries=retries), \
                    patch.object(validator.urllib.request, "urlopen", side_effect=[
                        self.http_error() for _ in range(retries + 1)
                    ]) as urlopen, patch.object(validator.time, "sleep") as sleep, \
                    contextlib.redirect_stdout(io.StringIO()):
                result = validator.validate_domain(
                    "http://localhost", "example.test", rate_limit_retries=retries
                )
                self.assertEqual(result["status"], 429)
                self.assertEqual(result["error"], "request limited")
                self.assertEqual(urlopen.call_count, retries + 1)
                self.assertEqual(sleep.call_count, retries)

    def test_other_http_errors_are_not_retried(self):
        with patch.object(validator.urllib.request, "urlopen", side_effect=self.http_error(status=500)) as urlopen, \
                patch.object(validator.time, "sleep") as sleep:
            self.assertEqual(validator.validate_domain("http://localhost", "example.test")["status"], 500)
        self.assertEqual(urlopen.call_count, 1)
        sleep.assert_not_called()

    def test_http_error_does_not_match_expected_dnssec_failure(self):
        for status, error, expected_exit in ((429, "request limited", 1), (500, "error", 1), (200, None, 0)):
            with self.subTest(status=status), \
                    patch.object(validator.sys, "argv", ["validate_all_domains.py", "--url", "http://localhost"]), \
                    patch.object(validator, "fetch_published_domains", return_value=["sign.ds.error.example.test"]), \
                    patch.object(validator, "validate_domain", return_value={
                        "status": status, "success": False, "error": error, "logs": [], "elapsed": 0
                    }), contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaises(SystemExit) as exit_result:
                validator.main()
            self.assertEqual(exit_result.exception.code, expected_exit)

    def test_negative_retry_count_is_rejected_before_network_access(self):
        with patch.object(validator.sys, "argv", ["validate_all_domains.py", "--rate-limit-retries", "-1"]), \
                patch.object(validator, "fetch_published_domains") as fetch, \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exit_result:
            validator.main()
        self.assertEqual(exit_result.exception.code, 2)
        fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
