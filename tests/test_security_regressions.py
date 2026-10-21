"""Regression fixtures for security, reporting, and bulk-processing failures."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

import fitz
from keyring.backends.chainer import ChainerBackend

from pdfchecker.core import (bulk_processor, config_manager, indicator_export,
                             json_output, pipeline, qr_detector,
                             report_generator, report_html, virustotal)
from pdfchecker.core.embedded_file_detector import detect_embedded_files
from pdfchecker.core.javascript_detector import extract_javascript_from_pdf
from pdfchecker.core.metadata_analyzer import analyze_pdf_metadata
from pdfchecker.core.pipeline import analyze_pdf_for_risk
from pdfchecker.core.risk_scorer import compute_risk_score
from pdfchecker.core.structure_analyzer import analyze_structure
from pdfchecker.core.urlhaus import URLhausClient
from pdfchecker.core.utils import HTTPStatusError
from pdfchecker.core.virustotal import VirusTotalClient


def _crash_or_return(path):
    if path == 'crash':
        os._exit(7)
    return path


def url_findings(*urls):
    return {'urls': [{'url': url, 'sources': []} for url in urls], 'errors': []}


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        # These fixtures do not require image decoding.
        self.qr_patch = patch.multiple(qr_detector, QR_SUPPORT=False, cv2=None, np=None)
        self.qr_patch.start()
        self.addCleanup(self.qr_patch.stop)

    def pdf(self, name='sample.pdf', configure=None):
        path = self.folder / name
        with fitz.open() as doc:
            doc.new_page()
            if configure:
                configure(doc)
            doc.save(path)
        return str(path)

    def script_pdf(self, content, stream=False, direct=False, name='script.pdf'):
        def configure(doc):
            if stream:
                xref = doc.get_new_xref()
                doc.update_object(xref, '<<>>')
                doc.update_stream(xref, content.encode('utf-8'))
                value = f'{xref} 0 R'
            else:
                value = fitz.get_pdf_str(content)
            action = f'<< /S /JavaScript /JS {value} >>'
            if not direct:
                xref = doc.get_new_xref()
                doc.update_object(xref, action)
                action = f'{xref} 0 R'
            doc.xref_set_key(doc.pdf_catalog(), 'OpenAction', action)
        return self.pdf(name, configure)

    def test_invalid_pdf_fails_json_modes_and_report_does_not_claim_minimal(self):
        path = self.folder / 'invalid.pdf'
        path.write_bytes(b'not a PDF')
        for mode in ('risk_score', 'links', 'javascript', 'structure', 'embedded_files', 'report'):
            with self.subTest(mode=mode), contextlib.redirect_stdout(io.StringIO()) as output:
                code = json_output.run_json_analysis(mode, str(path))
                result = json.loads(output.getvalue())
                self.assertEqual(code, 1)
                self.assertFalse(result['ok'])
                self.assertIsNone(result['result'])
        analysis = pipeline.analyze_pdf_once(str(path))
        self.assertIsNone(analysis.risk)
        self.assertTrue(analysis.errors)
        data = report_generator._collect_report_data(str(path), analysis, False, None)
        html = report_html.build_report_html(data)
        self.assertIn('Analysis Errors', html)
        self.assertNotIn('MINIMAL RISK', html)

    def test_analysis_errors_cannot_be_scored_as_clean(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete analysis'):
            compute_risk_score(js_findings={'extraction_errors': ['broken action']})

    def test_stream_javascript_and_indirect_open_action(self):
        script = 'app.alert(1); eval("hidden")'
        path = self.script_pdf(script, stream=True)
        js = extract_javascript_from_pdf(path)
        self.assertTrue(js['has_javascript'])
        self.assertEqual(js['javascript_sources'][0]['full_content'], script)
        self.assertEqual(js['javascript_sources'][0]['source'], 'Open Action')
        self.assertTrue(any(p['pattern'] == 'eval' for p in js['suspicious_patterns']))
        self.assertTrue(any(a['type'] == 'OpenAction with JavaScript' and a['severity'] == 'High'
                            for a in analyze_structure(path)['anomalies']))

    def test_literal_and_unicode_javascript_export_is_complete(self):
        for number, script in enumerate(['app.alert(1); eval("hidden")',
                                         'app.alert("héllo 世界 (test) \\"); eval("x")']):
            with self.subTest(script=script):
                path = self.script_pdf(script, name=f'js{number}.pdf')
                findings = indicator_export.collect_pdf_indicators(path)
                self.assertEqual(findings['javascript'][0]['value'], script)
                self.assertFalse(findings['javascript'][0]['truncated'])

    def test_oversized_script_is_explicitly_truncated(self):
        path = self.script_pdf('x' * 50001)
        findings = indicator_export.collect_pdf_indicators(path)
        self.assertTrue(findings['javascript'][0]['truncated'])

    def test_open_action_next_cycle_terminates_and_marks_script_automatic(self):
        def configure(doc):
            first = doc.get_new_xref()
            second = doc.get_new_xref()
            doc.update_object(first, f'<< /S /Named /N /NextPage /Next {second} 0 R >>')
            doc.update_object(second, f'<< /S /JavaScript /JS (eval) /Next {first} 0 R >>')
            doc.xref_set_key(doc.pdf_catalog(), 'OpenAction', f'{first} 0 R')
        js = extract_javascript_from_pdf(self.pdf(configure=configure))
        self.assertEqual(js['javascript_sources'][0]['source'], 'Open Action')

    def test_unlisted_filespec_does_not_hide_executable(self):
        def configure(doc):
            stream = doc.get_new_xref()
            doc.update_object(stream, '<< /Type /EmbeddedFile >>')
            doc.update_stream(stream, b'MZ' + b'x' * 20)
            spec = doc.get_new_xref()
            doc.update_object(spec, f'<< /Type /Filespec /F (hidden.exe) /EF << /F {stream} 0 R >> >>')
        path = self.pdf(configure=configure)
        findings = detect_embedded_files(path)
        self.assertEqual(findings['hidden_stream_count'], 1)
        self.assertEqual(findings['hidden_streams'][0]['risk'], 'High')
        self.assertGreaterEqual(analyze_pdf_for_risk(path)['score'], 40)

    def test_regular_attachment_is_not_counted_as_hidden(self):
        path = self.pdf(configure=lambda d: d.embfile_add('sample.txt', b'hello'))
        result = detect_embedded_files(path)
        self.assertEqual(result['embedded_count'], 1)
        self.assertEqual(result['hidden_stream_count'], 0)

    def test_annotation_attachment_is_not_counted_as_hidden(self):
        def configure(doc):
            doc[0].add_file_annot(fitz.Point(30, 30), b'hello', 'sample.txt')
        result = detect_embedded_files(self.pdf(configure=configure))
        self.assertEqual(result['embedded_count'], 1)
        self.assertEqual(result['hidden_stream_count'], 0)

    def test_identical_unlisted_stream_still_has_provenance(self):
        def configure(doc):
            doc.embfile_add('sample.txt', b'hello')
            stream = doc.get_new_xref()
            doc.update_object(stream, '<< /Type /EmbeddedFile >>')
            doc.update_stream(stream, b'hello')
        result = detect_embedded_files(self.pdf(configure=configure))
        self.assertEqual(result['embedded_count'], 1)
        self.assertEqual(result['hidden_stream_count'], 1)

    def test_bulk_json_stdout_and_failure_counts(self):
        self.pdf('healthy.pdf')
        (self.folder / 'invalid.pdf').write_bytes(b'not a PDF')
        completed = subprocess.run(
            [sys.executable, '-m', 'pdfchecker', '-rs', str(self.folder), '--json'],
            cwd=str(Path(__file__).resolve().parents[1]),
            text=True, capture_output=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result['summary']['failed'], 1)
        self.assertEqual(result['summary']['succeeded'], 1)
        self.assertTrue(result['files'][0]['ok'])
        self.assertFalse(result['files'][1]['ok'])

    def test_threat_intel_raises_risk_without_mutating_local_assessment(self):
        path = self.pdf()
        analysis = pipeline.analyze_pdf_once(path)
        with patch('pdfchecker.core.virustotal.http_request_json', return_value={
                'data': {'attributes': {'last_analysis_stats': {'malicious': 60}}}}):
            result = report_generator._collect_report_data(path, analysis, False, None,
                                                           [VirusTotalClient('test')])
        self.assertEqual(result['risk']['level'], 'Critical')
        self.assertEqual(analysis.risk['score'], 0)
        with patch('pdfchecker.core.urlhaus.http_request_json', return_value={'query_status': 'ok'}):
            result = report_generator._collect_report_data(path, analysis, False, None,
                                                           [URLhausClient('test')])
        self.assertEqual(result['risk']['level'], 'Critical')

    def test_indicator_output_cannot_overwrite_any_input_or_hardlink(self):
        path = self.pdf()
        original = Path(path).read_bytes()
        alias = self.folder / 'alias.json'
        os.link(path, alias)
        for target, output in [(path, path), (str(self.folder), path), (path, str(alias))]:
            with self.subTest(target=target, output=output):
                self.assertEqual(indicator_export.run_indicator_export(target, output_path=output), 1)
                self.assertEqual(Path(path).read_bytes(), original)

    def test_chained_plaintext_backend_is_rejected(self):
        class Plain:
            __module__ = 'keyrings.alt.file'
        with patch.object(ChainerBackend, 'backends', [Plain()]), patch(
                'keyring.get_keyring', return_value=ChainerBackend()), patch('keyring.set_password') as store:
            config_manager.reset_backend_cache()
            try:
                self.assertFalse(config_manager.set_api_key_secure('0' * 64)[0])
                self.assertFalse(config_manager.set_urlhaus_auth_key_secure('test')[0])
                store.assert_not_called()
            finally:
                config_manager.reset_backend_cache()

    def test_colliding_report_names_have_distinct_files(self):
        paths = [self.pdf('a!.pdf'), self.pdf('a?.pdf')]
        results = bulk_processor._run_parallel(paths, _make_report, True)
        outputs = [results[path][1] for path in paths]
        self.assertTrue(all(results[path][0] for path in paths))
        self.assertEqual(len(set(outputs)), 2)
        for original, output in zip(paths, outputs):
            with fitz.open(output) as report:
                text = ''.join(page.get_text() for page in report)
            self.assertIn(Path(original).name, text)

    def test_worker_crash_does_not_lose_healthy_files(self):
        result = bulk_processor._run_parallel(['crash', 'healthy1', 'healthy2'], _crash_or_return, True)
        self.assertFalse(result['crash'][0])
        self.assertEqual(result['healthy1'], (True, 'healthy1'))
        self.assertEqual(result['healthy2'], (True, 'healthy2'))

    def test_metadata_strings_do_not_create_actions(self):
        path = self.pdf(configure=lambda d: d.set_metadata({'title': 'Documentation /Launch /OpenAction /JS command'}))
        self.assertEqual(analyze_structure(path)['anomalies'], [])
        self.assertEqual(analyze_pdf_for_risk(path)['score'], 0)
        dangerous = self.pdf('launch.pdf', lambda d: d.xref_set_key(d.pdf_catalog(), 'OpenAction', '<< /S /Launch /F (test.exe) >>'))
        self.assertGreaterEqual(analyze_pdf_for_risk(dangerous)['score'], 55)

    def test_virustotal_errors_remain_distinct_from_not_found(self):
        self.assertEqual(virustotal.summarize_file_result(None)['status'], 'error')
        self.assertIn('API call failed', report_html._vt_file_html({'status': 'error'}))
        for status, expected in [(404, 'not_found'), (401, 'error'), (429, 'error')]:
            with patch('pdfchecker.core.virustotal.http_request_json', side_effect=HTTPStatusError(status)):
                response = VirusTotalClient('test').check_file('0'*64, silent=True)
                self.assertEqual(virustotal.summarize_file_result(response)['status'], expected)

    def test_failed_submissions_consume_budget(self):
        client = VirusTotalClient('test', api_limit=1)
        with patch('pdfchecker.core.virustotal.http_request_json', side_effect=HTTPStatusError(429)) as request:
            client.check_url('https://example.com/one', silent=True)
            client.check_url('https://example.com/two', silent=True)
            self.assertEqual(request.call_count, 1)
        self.assertEqual(client.api_calls_made, 1)

    def test_url_ports_credentials_and_ipv6_do_not_evade_checks(self):
        for url in ['https://bit.ly/x', 'https://bit.ly:443/x', 'https://user@bit.ly/x']:
            self.assertEqual(compute_risk_score(link_findings=url_findings(url))['score'], 3)
        self.assertEqual(compute_risk_score(link_findings=url_findings('https://user@xn--bcher-kva.example/x'))['score'], 4)
        self.assertEqual(compute_risk_score(link_findings=url_findings('https://user@[::1]/x'))['score'], 5)

    def test_metadata_javascript_agrees_with_detector(self):
        for direct in (True, False):
            path = self.script_pdf('app.alert(1)', direct=direct, name=f'{direct}.pdf')
            self.assertTrue(analyze_pdf_metadata(path)['content_info']['has_javascript'])

    def test_duplicate_qr_payloads_keep_both_pages_in_export(self):
        findings = {'pages_scanned': 0, 'pages_skipped': 0, 'qr_codes': [], 'errors': [], 'undecoded_count': 0}
        with patch.object(qr_detector, 'cv2', MagicMock()), patch.object(qr_detector, '_decode_page', return_value=['https://example.com']):
            qr_detector._scan_document_qr([object(), object()], findings)
        self.assertEqual([q['page'] for q in findings['qr_codes']], [1, 2])
        path = self.pdf()
        with patch.object(pipeline, 'detect_qr_codes', return_value=findings):
            collected = indicator_export.collect_pdf_indicators(path)
        native = indicator_export.build_json_export(path, [collected])
        self.assertEqual([s['page'] for s in native['indicators']['urls'][0]['sources']], [1, 2])


def _make_report(path):
    # Runs in an isolated worker; no network or image decoding is needed.
    qr_detector.QR_SUPPORT = False
    result = report_generator.create_report(path, include_logo=False)
    if not result:
        raise ValueError('Report generation failed')
    return result


if __name__ == '__main__':
    unittest.main()
