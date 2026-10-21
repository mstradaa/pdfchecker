import contextlib
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pdfchecker.core import bulk_processor, config_manager
from pdfchecker.core.report_html import build_report_html
from pdfchecker.core.report_generator import _collect_report_data
from pdfchecker.core.urlhaus import (
    PAYLOAD_QUERY_ENDPOINT,
    URL_QUERY_ENDPOINT,
    URLhausClient,
    summarize_payload_result,
    summarize_url_result,
)
from pdfchecker.core.virustotal import VirusTotalClient


def _chosen(*clients):
    """Stand-in for threat_intel.selected_providers that skips the prompts."""
    return lambda subject, *unused: contextlib.nullcontext(list(clients))


class URLhausClientTests(unittest.TestCase):
    def test_url_lookup_uses_documented_endpoint_header_and_post_field(self):
        response = {"query_status": "no_results"}
        with patch("pdfchecker.core.urlhaus.http_request_json",
                   return_value=response) as request:
            client = URLhausClient("secret-key", api_limit=3)
            result = client.check_url("https://example.test/path", silent=True)

        self.assertEqual(result, response)
        request.assert_called_once_with(
            URL_QUERY_ENDPOINT,
            headers={"Auth-Key": "secret-key"},
            data={"url": "https://example.test/path"},
            timeout=30,
        )
        self.assertEqual(client.api_calls_made, 1)

    def test_payload_lookup_uses_sha256_field_and_normalizes_hash(self):
        sha256 = "A" * 64
        with patch("pdfchecker.core.urlhaus.http_request_json",
                   return_value={"query_status": "no_results"}) as request:
            client = URLhausClient("secret-key")
            client.check_file(sha256, silent=True)

        request.assert_called_once_with(
            PAYLOAD_QUERY_ENDPOINT,
            headers={"Auth-Key": "secret-key"},
            data={"sha256_hash": sha256.lower()},
            timeout=30,
        )

    def test_duplicate_and_over_budget_queries_do_not_make_requests(self):
        with patch("pdfchecker.core.urlhaus.http_request_json",
                   return_value={"query_status": "no_results"}) as request:
            client = URLhausClient("secret-key", api_limit=1)
            client.check_url("https://example.test", silent=True)
            duplicate = client.check_url("https://example.test", silent=True)
            over_budget = client.check_url("https://other.test", silent=True)

        self.assertIsNone(duplicate)
        self.assertIsNone(over_budget)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(client.api_calls_made, 1)

    def test_documented_query_statuses_are_mapped(self):
        self.assertEqual(summarize_url_result({"query_status": "no_results"}),
                         {"status": "not_found"})
        self.assertEqual(summarize_payload_result({"query_status": "no_results"}),
                         {"status": "not_found"})
        self.assertEqual(
            summarize_url_result({"query_status": "invalid_url"}),
            {"status": "invalid", "query_status": "invalid_url"},
        )
        self.assertEqual(
            summarize_payload_result({"query_status": "invalid_sha256"}),
            {"status": "invalid", "query_status": "invalid_sha256"},
        )
        self.assertEqual(
            summarize_url_result({
                "query_status": "ok",
                "url_status": "online",
                "host": "malware.test",
                "threat": "malware_download",
                "payloads": [{"response_sha256": "a" * 64}],
                "tags": ["test-family"],
            }),
            {
                "status": "ok",
                "url_status": "online",
                "host": "malware.test",
                "threat": "malware_download",
                "date_added": None,
                "last_online": None,
                "tags": ["test-family"],
                "blacklists": {},
                "payload_count": 1,
                "reference": None,
            },
        )


class URLhausConfigurationTests(unittest.TestCase):
    def tearDown(self):
        config_manager.reset_backend_cache()

    def test_environment_key_is_supported_without_keyring(self):
        with patch.dict(os.environ,
                        {"PDFCHECKER_URLHAUS_AUTH_KEY": "urlhaus-secret"},
                        clear=False):
            success, key = config_manager.get_urlhaus_auth_key()
        self.assertTrue(success)
        self.assertEqual(key, "urlhaus-secret")

    def test_header_injection_is_rejected(self):
        with patch.dict(os.environ,
                        {"PDFCHECKER_URLHAUS_AUTH_KEY": "bad\r\nInjected: yes"},
                        clear=False):
            with self.assertRaises(config_manager.ConfigError):
                config_manager.get_urlhaus_auth_key()

    def test_auth_key_is_stored_in_the_dedicated_keyring_account(self):
        with patch("pdfchecker.core.config_manager._verify_secure_backend",
                   return_value=True), patch(
                       "pdfchecker.core.config_manager.keyring.set_password") as store:
            success, _ = config_manager.set_urlhaus_auth_key_secure("urlhaus-secret")

        self.assertTrue(success)
        store.assert_called_once_with(
            config_manager.SERVICE_NAME,
            config_manager.URLHAUS_ACCOUNT_NAME,
            "urlhaus-secret",
        )


class DualProviderReportTests(unittest.TestCase):
    def test_duplicate_payload_hash_is_reported_as_skipped(self):
        analysis = SimpleNamespace(
            hashes={"SHA-256": "A" * 64},
            links=[],
            qr=None,
            risk=None,
            metadata=None,
            javascript=None,
            embedded=None,
            structure=None,
            errors=[],
        )
        client = URLhausClient("urlhaus-secret", api_limit=10)
        with patch("pdfchecker.core.urlhaus.http_request_json",
                   return_value={"query_status": "no_results"}) as request:
            first = _collect_report_data("first.pdf", analysis, False, None, [client])
            duplicate = _collect_report_data("duplicate.pdf", analysis, False, None, [client])

        self.assertEqual(first["urlhaus_file"]["status"], "not_found")
        self.assertEqual(duplicate["urlhaus_file"], {
            "status": "skipped",
            "message": "File hash already checked in this operation.",
        })
        self.assertEqual(request.call_count, 1)

    def test_urlhaus_collection_does_not_require_virustotal(self):
        analysis = SimpleNamespace(
            hashes={"SHA-256": "b" * 64},
            links=["https://urlhaus-only.test/payload"],
            qr=None,
            risk=None,
            metadata=None,
            javascript=None,
            embedded=None,
            structure=None,
            errors=[],
        )
        client = URLhausClient("urlhaus-secret", api_limit=10)
        with patch("pdfchecker.core.urlhaus.http_request_json", side_effect=[
            {"query_status": "no_results"},
            {"query_status": "no_results"},
        ]):
            result = _collect_report_data("sample.pdf", analysis, False, None, [client])

        self.assertFalse(result["meta"]["vt_enabled"])
        self.assertTrue(result["meta"]["urlhaus_enabled"])
        self.assertIsNone(result["links"][0]["vt"])
        self.assertEqual(result["links"][0]["urlhaus"]["status"], "not_found")

    def test_collection_runs_both_providers_for_hashes_and_urls(self):
        analysis = SimpleNamespace(
            hashes={"SHA-256": "a" * 64},
            links=["https://malware.test/payload"],
            qr=None,
            risk=None,
            metadata=None,
            javascript=None,
            embedded=None,
            structure=None,
            errors=[],
        )
        vt_client = VirusTotalClient("vt-secret", api_limit=10)
        urlhaus_client = URLhausClient("urlhaus-secret", api_limit=10)
        vt_responses = [
            {"data": {"attributes": {
                "last_analysis_stats": {"malicious": 1, "undetected": 4},
                "last_analysis_results": {},
            }}},
            {"data": {"id": "analysis-id"}},
            {"data": {"attributes": {"status": "completed", "stats": {
                "malicious": 1, "suspicious": 0, "harmless": 2, "undetected": 3,
            }}}},
        ]
        urlhaus_responses = [
            {"query_status": "ok", "signature": "ExampleMalware",
             "url_count": "1", "urls": []},
            {"query_status": "ok", "url_status": "online",
             "threat": "malware_download", "payloads": []},
        ]

        with patch("pdfchecker.core.virustotal.http_request_json",
                   side_effect=vt_responses), patch(
                       "pdfchecker.core.urlhaus.http_request_json",
                       side_effect=urlhaus_responses):
            result = _collect_report_data(
                "sample.pdf", analysis, False, None, [vt_client, urlhaus_client],
                include_logo=False,
            )

        self.assertEqual(result["vt_file"]["status"], "ok")
        self.assertEqual(result["urlhaus_file"]["status"], "ok")
        self.assertEqual(result["links"][0]["vt"]["status"], "ok")
        self.assertEqual(result["links"][0]["urlhaus"]["status"], "ok")
        self.assertTrue(result["meta"]["vt_enabled"])
        self.assertTrue(result["meta"]["urlhaus_enabled"])

    def test_report_renders_virustotal_and_urlhaus_results_together(self):
        data = {
            "meta": {
                "scanned_path": "/tmp/sample.pdf",
                "version": "1.0",
                "timestamp": "2026-07-17 10:00:00",
                "operator": None,
                "vt_enabled": True,
                "urlhaus_enabled": True,
                "defang": False,
                "include_logo": False,
            },
            "risk": None,
            "hashes": {"SHA-256": "a" * 64},
            "vt_file": {"status": "not_found"},
            "urlhaus_file": {
                "status": "ok",
                "signature": "ExampleMalware",
                "file_type": "pdf",
                "file_size": "123",
                "first_seen": "2026-01-01",
                "last_seen": "2026-01-02",
                "url_count": "2",
                "known_urls": 2,
            },
            "links": [{
                "display": "https://malware.test/a",
                "vt": {"status": "not_found"},
                "urlhaus": {
                    "status": "ok",
                    "url_status": "online",
                    "threat": "malware_download",
                    "tags": ["ExampleMalware"],
                    "date_added": "2026-01-01 UTC",
                },
            }],
            "metadata": None,
            "javascript": None,
            "embedded": None,
            "structure": None,
            "qr": None,
            "errors": [],
        }

        report = build_report_html(data)

        self.assertIn("VirusTotal File Reputation", report)
        self.assertIn("URLhaus Payload Reputation", report)
        self.assertIn("VirusTotal</th><th", report)
        self.assertIn("URLhaus</th>", report)
        self.assertIn("Known malware URL (online)", report)
        self.assertIn("ExampleMalware", report)


class BulkURLhausTests(unittest.TestCase):
    def test_virustotal_limit_does_not_skip_urlhaus(self):
        files = ["first.pdf", "second.pdf"]
        results = {
            "first.pdf": (True, {"SHA-256": "a" * 64}),
            "second.pdf": (True, {"SHA-256": "b" * 64}),
        }
        chosen = _chosen(VirusTotalClient("vt-key", api_limit=1),
                         URLhausClient("urlhaus-key", api_limit=2))
        with patch.object(bulk_processor, "selected_providers", chosen), patch.object(
                bulk_processor, "_run_parallel", return_value=results), patch(
                    "pdfchecker.core.virustotal.http_request_json",
                    return_value=None) as vt_request, patch(
                        "pdfchecker.core.urlhaus.http_request_json",
                        return_value={"query_status": "no_results"}) as request, patch(
                            "builtins.print"):
            bulk_processor.bulk_hash_check(files)

        self.assertEqual(vt_request.call_count, 1)
        self.assertEqual(request.call_count, 2)

    def test_duplicate_payload_hash_is_not_reported_as_failure(self):
        files = ["first.pdf", "duplicate.pdf"]
        sha256 = "a" * 64
        results = {
            "first.pdf": (True, {"SHA-256": sha256}),
            "duplicate.pdf": (True, {"SHA-256": sha256.upper()}),
        }
        chosen = _chosen(URLhausClient("urlhaus-key", api_limit=2))
        with patch.object(bulk_processor, "selected_providers", chosen), patch.object(
                bulk_processor, "_run_parallel", return_value=results), patch(
                    "pdfchecker.core.urlhaus.http_request_json",
                    return_value={"query_status": "no_results"}) as request, patch(
                        "builtins.print") as output:
            bulk_processor.bulk_hash_check(files)

        self.assertEqual(request.call_count, 1)
        output.assert_any_call(
            "URLhaus check skipped: File hash already checked in this operation.")


if __name__ == "__main__":
    unittest.main()
