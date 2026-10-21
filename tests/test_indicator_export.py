import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import fitz

from pdfchecker.core.indicator_export import (
    _normalized_domain,
    build_json_export,
    build_stix_export,
    run_indicator_export,
)


GENERATED_AT = "2026-07-17T12:00:00Z"


class IndicatorAggregationTests(unittest.TestCase):
    def test_domains_are_normalized_and_ip_addresses_are_excluded(self):
        self.assertEqual(
            _normalized_domain("https://User@BÜCHER.Example.:8443/path"),
            "xn--bcher-kva.example",
        )
        self.assertEqual(_normalized_domain("www.Example.COM/path"), "www.example.com")
        self.assertIsNone(_normalized_domain("https://192.0.2.1/path"))
        self.assertIsNone(_normalized_domain("mailto:analyst@example.com"))

    def test_json_export_deduplicates_values_and_keeps_all_sources(self):
        url = "https://Example.COM/path"
        script = "app.launchURL('https://example.com')"
        results = [
            {
                "path": "one.pdf",
                "urls": [
                    {"value": url,
                     "source": {"path": "one.pdf", "origin": "pdf-link"}},
                    {"value": url,
                     "source": {"path": "one.pdf", "origin": "qr-code", "page": 1}},
                ],
                "javascript": [
                    {"value": script, "truncated": False,
                     "source": {"path": "one.pdf", "origin": "javascript"}},
                ],
                "warnings": [],
            },
            {
                "path": "two.pdf",
                "urls": [],
                "javascript": [
                    {"value": script, "truncated": False,
                     "source": {"path": "two.pdf", "origin": "javascript"}},
                ],
                "warnings": ["recoverable scan warning"],
            },
        ]

        exported = build_json_export(
            "samples", results, generated_at=GENERATED_AT)

        self.assertEqual(exported["summary"]["urls"], 1)
        self.assertEqual(exported["summary"]["domains"], 1)
        self.assertEqual(exported["summary"]["javascript"], 1)
        self.assertEqual(len(exported["indicators"]["urls"][0]["sources"]), 2)
        self.assertEqual(exported["indicators"]["domains"][0]["value"], "example.com")
        self.assertEqual(
            len(exported["indicators"]["javascript"][0]["sources"]), 2)
        self.assertEqual(exported["warnings"][0]["path"], "two.pdf")

    def test_stix_uses_native_observable_patterns(self):
        native = build_json_export(
            "sample.pdf",
            [{
                "path": "sample.pdf",
                "urls": [{
                    "value": "https://example.com/a'b",
                    "source": {"path": "sample.pdf", "origin": "pdf-link"},
                }],
                "javascript": [{
                    "value": "app.alert('hello')",
                    "truncated": False,
                    "source": {"path": "sample.pdf", "origin": "javascript"},
                }],
                "warnings": [],
            }],
            generated_at=GENERATED_AT,
        )

        bundle = build_stix_export(native)

        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(len(bundle["objects"]), 3)
        by_label = {obj["labels"][1]: obj for obj in bundle["objects"]}
        self.assertEqual(by_label["url"]["spec_version"], "2.1")
        self.assertIn("[url:value = 'https://example.com/a\\'b']",
                      by_label["url"]["pattern"])
        self.assertEqual(
            by_label["domain"]["pattern"],
            "[domain-name:value = 'example.com']",
        )
        js_pattern = by_label["javascript"]["pattern"]
        prefix = "[artifact:payload_bin = b'"
        encoded = js_pattern[len(prefix):-2]
        self.assertEqual(base64.b64decode(encoded).decode(), "app.alert('hello')")

    def test_stix_falls_back_to_binary_for_control_characters(self):
        native = build_json_export(
            "sample.pdf",
            [{
                "path": "sample.pdf",
                "urls": [{
                    "value": "https://example.com/line\nbreak",
                    "source": {"path": "sample.pdf", "origin": "pdf-link"},
                }],
                "javascript": [],
                "warnings": [],
            }],
            generated_at=GENERATED_AT,
        )

        indicator = build_stix_export(native)["objects"][0]

        self.assertTrue(indicator["pattern"].startswith("[artifact:payload_bin = b'"))
        self.assertEqual(indicator["x_pdfchecker_observable_type"], "url")


class IndicatorExportIntegrationTests(unittest.TestCase):
    def test_json_cli_export_finds_a_pdf_link_and_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            pdf_path = Path(directory) / "linked.pdf"
            doc = fitz.open()
            page = doc.new_page()
            page.insert_link({
                "kind": fitz.LINK_URI,
                "from": fitz.Rect(20, 20, 120, 40),
                "uri": "https://Example.org/download",
            })
            doc.save(pdf_path)
            doc.close()

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = run_indicator_export(str(pdf_path))
            exported = json.loads(output.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            exported["indicators"]["urls"][0]["value"],
            "https://Example.org/download",
        )
        self.assertEqual(exported["indicators"]["domains"][0]["value"],
                         "example.org")


if __name__ == "__main__":
    unittest.main()
