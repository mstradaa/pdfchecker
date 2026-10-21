import hashlib
import os
import tempfile
import unittest

from pdfchecker.core.hash_checker import CHUNK_SIZE, calculate_file_hashes
from pdfchecker.core.javascript_detector import (
    JSFindings,
    _scan_document_javascript,
)
from pdfchecker.core.structure_analyzer import StructureFindings, _scan_raw_file


class _EmptyPage:
    def get_contents(self):
        return []

    def widgets(self):
        return None

    def annots(self):
        return None


class _CountingDocument:
    def __init__(self, page_count):
        self.pages = [_EmptyPage() for _ in range(page_count)]
        self.iteration_count = 0

    def __iter__(self):
        self.iteration_count += 1
        return iter(self.pages)


class _Widget:
    def __init__(self, page_number):
        self.xref = 300 + page_number
        self.field_name = f"field-{page_number}"
        self.script = f"form-{page_number}"


class _Annotation:
    def __init__(self, xref):
        self.xref = xref


class _FeaturePage:
    def __init__(self, page_number):
        self.page_number = page_number

    def get_contents(self):
        return [100 + self.page_number]

    def widgets(self):
        return [_Widget(self.page_number)]

    def annots(self):
        return [_Annotation(200 + self.page_number)]


class _FeatureDocument(_CountingDocument):
    def __init__(self, page_count):
        super().__init__(0)
        self.pages = [_FeaturePage(number) for number in range(page_count)]

    def xref_stream(self, xref):
        return f"/JS eval(page-{xref - 100})".encode()


class OptimizationTests(unittest.TestCase):
    def test_javascript_page_features_use_one_document_traversal(self):
        doc = _CountingDocument(5)
        findings = JSFindings()

        _scan_document_javascript(doc, findings, xref_cache={})

        self.assertEqual(doc.iteration_count, 1)

    def test_javascript_finding_categories_keep_their_original_order(self):
        doc = _FeatureDocument(2)
        findings = JSFindings()
        xref_cache = {
            200: ("<< /JS (annotation-0) >>", None),
            201: ("<< /JS (annotation-1) >>", None),
        }

        _scan_document_javascript(doc, findings, xref_cache=xref_cache)

        self.assertEqual(doc.iteration_count, 1)
        self.assertEqual(
            [entry["source"] for entry in findings.javascript_sources],
            [
                "Page Content", "Page Content",
                "Form Field", "Form Field",
                "Annotation", "Annotation",
            ],
        )

    def test_hashes_are_correct_with_larger_chunks(self):
        payload = (b"pdfchecker\x00" * 100_000) + b"tail"
        with tempfile.NamedTemporaryFile() as test_file:
            test_file.write(payload)
            test_file.flush()

            hashes = calculate_file_hashes(test_file.name)

        self.assertGreaterEqual(CHUNK_SIZE, 64 * 1024)
        self.assertEqual(hashes["MD5"], hashlib.md5(payload).hexdigest())
        self.assertEqual(hashes["SHA-1"], hashlib.sha1(payload).hexdigest())
        self.assertEqual(hashes["SHA-256"], hashlib.sha256(payload).hexdigest())

    def test_raw_obfuscation_scan_still_finds_hex_escaped_names(self):
        with tempfile.NamedTemporaryFile(delete=False) as test_file:
            test_file.write(b"%PDF-1.7\n1 0 obj << /J#61vaScript true >> endobj\n")
            path = test_file.name

        try:
            findings = StructureFindings()
            _scan_raw_file(path, findings)
            result = findings.to_dict()
        finally:
            os.unlink(path)

        self.assertEqual(result["anomaly_count"], 1)
        self.assertEqual(result["anomalies"][0]["type"], "Obfuscated Name")
        self.assertEqual(result["errors"], [])

    def test_raw_obfuscation_scan_accepts_empty_files(self):
        with tempfile.NamedTemporaryFile() as test_file:
            findings = StructureFindings()
            _scan_raw_file(test_file.name, findings)

        self.assertEqual(findings.to_dict()["errors"], [])


if __name__ == "__main__":
    unittest.main()
