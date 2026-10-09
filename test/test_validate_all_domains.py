import contextlib
import io
import json
import unittest
import urllib.error
from email.message import Message
from unittest.mock import MagicMock, patch

import validate_all_domains as validator


class ValidateAllDomainsTests(unittest.TestCase):
    def new_domains(self):
        return [
            f"type.{record_type}.mismatch.{proof}.rsasha256.dnssec-check.jp"
            for proof in ("nsec", "nsec3")
            for record_type in ("mx", "txt")
        ] + [
            f"{kind}.mismatch.nsec3.{parameters}.rsasha256.dnssec-check.jp"
            for parameters in ("iter0.saltA1B2", "iter1.nosalt", "iter1.saltA1B2")
            for kind in ("cover", "type", "optout")
        ]

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

    def test_fallback_includes_all_new_domains_without_duplicates(self):
        with patch.object(validator.urllib.request, "urlopen", side_effect=urllib.error.URLError("offline")), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            domains = validator.fetch_published_domains()
        self.assertIn("フォールバック", output.getvalue())
        self.assertEqual(len(domains), len(set(domains)))
        for domain in self.new_domains():
            self.assertIn(domain, domains)

    def test_published_page_extracts_new_domains_and_preserves_order(self):
        expected = self.new_domains()
        response = self.response()
        response.read.return_value = "".join(
            f'<a href="https://validator.test/?domain={domain}">検証</a>'
            for domain in expected + expected[:1]
        ).encode()
        with patch.object(validator.urllib.request, "urlopen", return_value=response), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(validator.fetch_published_domains(), expected)

    def test_record_type_selection(self):
        for domain in self.new_domains():
            expected = "MX" if domain.startswith("type.mx.") else (
                "TXT" if domain.startswith("type.txt.") else "A"
            )
            for name in (domain, domain.upper() + "."):
                with self.subTest(domain=name):
                    self.assertEqual(validator.record_type_for_domain(name), expected)
        for domain in ("success.rsasha256.dnssec-check.jp", "type.mx.example.test"):
            self.assertEqual(validator.record_type_for_domain(domain), "A")

    def test_mx_and_txt_requests_preserve_record_type_during_retry(self):
        for record_type in ("MX", "TXT"):
            with self.subTest(record_type=record_type), \
                    patch.object(validator.urllib.request, "urlopen", side_effect=[
                        self.http_error(), self.response(False)
                    ]) as urlopen, patch.object(validator.time, "sleep"), \
                    contextlib.redirect_stdout(io.StringIO()):
                result = validator.validate_domain(
                    "http://localhost", "example.test", record_type=record_type
                )
            self.assertEqual(result["status"], 200)
            for call in urlopen.call_args_list:
                self.assertEqual(json.loads(call.args[0].data), {
                    "domain": "example.test", "recordType": record_type
                })

    def test_isolated_validation_passes_payload_as_data(self):
        for record_type in ("A", "MX", "TXT"):
            with self.subTest(record_type=record_type), \
                    patch.object(validator.subprocess, "run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = json.dumps({
                    "status": 200, "data": {"success": False, "logs": []}
                })
                domain = "example'test"
                result = validator.run_isolated_validation(
                    domain, "/project", record_type=record_type
                )
            command = run.call_args.args[0]
            self.assertEqual(command[:3], ["node", "--input-type=module", "-e"])
            self.assertIn("import { app }", command[3])
            self.assertNotIn(domain, command[3])
            expected = {"domain": domain}
            if record_type != "A":
                expected["recordType"] = record_type
            self.assertEqual(json.loads(command[4]), expected)
            self.assertEqual(result["status"], 200)

    def test_main_routes_new_domains_with_correct_record_types(self):
        domains = self.new_domains()
        for use_url in (False, True):
            argv = ["validate_all_domains.py"]
            if use_url:
                argv += ["--url", "http://localhost"]
            with self.subTest(use_url=use_url), \
                    patch.object(validator.sys, "argv", argv), \
                    patch.object(validator, "fetch_published_domains", return_value=domains), \
                    patch.object(validator, "validate_domain") as remote, \
                    patch.object(validator, "run_isolated_validation") as isolated, \
                    contextlib.redirect_stdout(io.StringIO()) as output, \
                    self.assertRaises(SystemExit) as exit_result:
                runner = remote if use_url else isolated
                runner.return_value = {
                    "status": 200, "success": False, "error": None, "logs": [], "elapsed": 0
                }
                validator.main()
            self.assertEqual(exit_result.exception.code, 0)
            self.assertEqual(runner.call_count, 13)
            (isolated if use_url else remote).assert_not_called()
            for domain, call in zip(domains, runner.call_args_list):
                self.assertEqual(
                    call.kwargs["record_type"], validator.record_type_for_domain(domain)
                )
            self.assertIn(" | MX | ", output.getvalue())
            self.assertIn(" | TXT | ", output.getvalue())

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
