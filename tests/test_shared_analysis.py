"""Regression tests for the shared analysis plumbing: one finding per script,
one parse per document, preserved timestamps, link text, and reputation
budgets and keys."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fitz

from pdfchecker.core import config_manager, pdf_access, pdf_objects, qr_detector
from pdfchecker.core.indicator_export import _normalized_domain
from pdfchecker.core.javascript_detector import extract_javascript_from_pdf
from pdfchecker.core.metadata_analyzer import analyze_pdf_metadata
from pdfchecker.core.pipeline import analyze_pdf_once
from pdfchecker.core.risk_scorer import compute_risk_score
from pdfchecker.core.structure_analyzer import analyze_structure
from pdfchecker.core.threat_intel import check_url, selected_providers
from pdfchecker.core.url_discovery import discover_urls, hostname
from pdfchecker.core.urlhaus import URLhausClient
from pdfchecker.core.virustotal import VirusTotalClient

_OLD_TIME = 1_000_000_000


def url_findings(*urls):
    return {'urls': [{'url': url, 'sources': []} for url in urls], 'errors': []}


class SharedAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.qr = patch.multiple(qr_detector, QR_SUPPORT=False, cv2=None, np=None)
        self.qr.start()
        self.addCleanup(self.qr.stop)

    # `configure` may return a reloaded document to save instead
    def pdf(self, configure, name='sample.pdf'):
        path = self.folder / name
        with fitz.open() as doc:
            doc.new_page()
            reloaded = configure(doc)
            (reloaded if isinstance(reloaded, fitz.Document) else doc).save(path)
        return str(path)

    def test_each_script_is_reported_once_with_its_specific_label(self):
        def configure(doc):
            page = doc[0]
            annot = page.add_text_annot((300, 300), 'note')
            doc.xref_set_key(annot.xref, 'A', "<< /S /JavaScript /JS (app.alert('annotation')) >>")
            widget = fitz.Widget()
            widget.field_type = fitz.PDF_WIDGET_TYPE_TEXT
            widget.field_name = 'amount'
            widget.rect = fitz.Rect(50, 50, 200, 70)
            widget.script_change = "app.alert('form')"
            page.add_widget(widget)
            doc.xref_set_key(doc.pdf_catalog(), 'OpenAction',
                             "<< /S /JavaScript /JS (app.alert('open')) >>")

        js = extract_javascript_from_pdf(self.pdf(configure))
        self.assertEqual(js['extraction_errors'], [])
        self.assertEqual(sorted((source['source'], source['full_content'])
                                for source in js['javascript_sources']),
                         [('Annotation', "app.alert('annotation')"),
                          ('Form Field', "app.alert('form')"),
                          ('Open Action', "app.alert('open')")])

    def test_scripts_outside_page_features_are_still_found(self):
        def configure(doc):
            doc[0].insert_link({'kind': fitz.LINK_URI, 'uri': 'https://x.example',
                                'from': fitz.Rect(10, 10, 90, 30)})
            # Reload so the new link annotation is listed with its xref
            doc = fitz.open('pdf', doc.tobytes())
            link = doc[0].get_links()[0]['xref']
            doc.xref_set_key(link, 'A', "<< /S /JavaScript /JS (app.alert('link')) >>")
            return doc

        js = extract_javascript_from_pdf(self.pdf(configure))
        self.assertEqual([(source['source'], source['full_content'])
                          for source in js['javascript_sources']],
                         [('Document Object', "app.alert('link')")])

    def test_overlapping_rules_report_each_construct_once(self):
        def configure(doc):
            doc.xref_set_key(doc.pdf_catalog(), 'OpenAction',
                             "<< /S /JavaScript /JS (eval\\(unescape\\('%41'\\)\\)) >>")

        js = extract_javascript_from_pdf(self.pdf(configure))
        self.assertEqual([(p['pattern'], p['severity']) for p in js['suspicious_patterns']],
                         [('eval', 'High'), ('unescape', 'Medium'), ('%[0-9a-fA-F]{2}', 'High')])

    def test_full_analysis_parses_the_document_once(self):
        def configure(doc):
            doc.xref_set_key(doc.pdf_catalog(), 'OpenAction', '<< /S /JavaScript /JS (app.alert) >>')

        path = self.pdf(configure)
        with patch.object(pdf_objects, '_parse_objects', wraps=pdf_objects._parse_objects) as parse:
            result = analyze_pdf_once(path)
        self.assertEqual(result.errors, [])
        self.assertEqual(parse.call_count, 1)

    def test_metadata_reports_outline_once(self):
        structure = analyze_pdf_metadata(self.pdf(lambda doc: None))['document_structure']
        self.assertEqual(set(structure), {'has_outline', 'has_form_fields'})

    def test_standalone_analyzers_restore_file_timestamps(self):
        path = self.pdf(lambda doc: doc[0].insert_text((30, 30), 'https://example.com'))
        original_open = pdf_access.open_pdf

        def touching_open(target):
            # Reads do not update atime on every filesystem; force a change
            os.utime(target)
            return original_open(target)

        for analyze in (analyze_pdf_metadata, analyze_structure, discover_urls,
                        extract_javascript_from_pdf):
            with self.subTest(analyzer=analyze.__name__):
                os.utime(path, (_OLD_TIME, _OLD_TIME))
                with patch.object(pdf_access, 'open_pdf', touching_open):
                    analyze(path)
                stats = os.stat(path)
                self.assertEqual((stats.st_atime, stats.st_mtime), (_OLD_TIME, _OLD_TIME))

    def test_link_text_is_read_whole_and_without_neighbours(self):
        def configure(doc):
            page = doc[0]
            page.insert_text((30, 30), 'https://bank.example https://neighbour.example')
            bank = page.search_for('https://bank.example')[0]
            # The link covers only most of the visible URL
            page.insert_link({'kind': fitz.LINK_URI, 'uri': 'https://other.example',
                              'from': fitz.Rect(bank.x0 + 3, bank.y0, bank.x1 - 3, bank.y1)})

        findings = discover_urls(self.pdf(configure))
        entry = next(row for row in findings['urls'] if row['url'] == 'https://other.example')
        self.assertEqual(entry['sources'][0]['displayed_urls'], ['https://bank.example'])
        self.assertTrue(entry['sources'][0]['mismatch'])

    def test_host_normalization_is_shared(self):
        self.assertEqual(hostname('www.Example.COM./path'), 'www.example.com')
        self.assertEqual(hostname('https://BÜCHER.example/'), 'xn--bcher-kva.example')
        self.assertEqual(hostname('not a url'), '')
        self.assertEqual(_normalized_domain('https://www.example.com/'), 'www.example.com')
        # Risk scoring ignores 'www.' and accepts scheme-less links
        self.assertEqual(compute_risk_score(link_findings=url_findings('www.bit.ly/x'))['score'], 3)
        self.assertEqual(compute_risk_score(link_findings=url_findings('bit.ly/x'))['score'], 3)

    def test_broken_optional_qr_install_is_seen_by_callers(self):
        with patch.multiple(qr_detector, QR_SUPPORT=True, cv2=None, np=None), \
                patch.dict(sys.modules, {'cv2': None}):
            self.assertFalse(qr_detector.qr_supported())
            self.assertFalse(qr_detector.QR_SUPPORT)


class ReputationServiceTests(unittest.TestCase):
    def tearDown(self):
        config_manager.reset_backend_cache()

    def test_url_checks_share_budget_and_skip_duplicates(self):
        client = URLhausClient('secret', api_limit=1)
        with patch('pdfchecker.core.urlhaus.http_request_json',
                   return_value={'query_status': 'no_results'}) as request, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            for url in ('https://one.example', 'https://one.example', 'https://two.example'):
                check_url([client], url)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(client.skipped, 2)
        self.assertIn('URL already checked in this operation.', output.getvalue())
        self.assertIn('API call limit reached.', output.getvalue())

    def test_selected_providers_forgets_every_key(self):
        clients = [VirusTotalClient('a' * 64), URLhausClient('secret')]
        with patch('pdfchecker.core.threat_intel.get_confirmation', side_effect=[True, False]):
            with selected_providers('this file', *clients) as chosen:
                self.assertEqual(chosen, clients[:1])
        self.assertTrue(all(client.key is None for client in clients))

    def test_key_validation_messages_name_each_service(self):
        with patch('pdfchecker.core.config_manager._verify_secure_backend', return_value=True):
            self.assertEqual(config_manager.set_api_key_secure('short'),
                             (False, 'Invalid VirusTotal API key format. '
                                     'Expected 64 hexadecimal characters.'))
            self.assertEqual(config_manager.set_urlhaus_auth_key_secure('has space'),
                             (False, 'Invalid URLhaus Auth-Key format. '
                                     'Expected a printable value without whitespace.'))
        with patch.dict(os.environ, {'PDFCHECKER_VT_API_KEY': 'f' * 63 + '\n'}):
            with self.assertRaisesRegex(config_manager.ConfigError, 'not a valid VirusTotal API key'):
                config_manager.get_api_key()


if __name__ == '__main__':
    unittest.main()
