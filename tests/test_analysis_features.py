import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import fitz

from pdfchecker.core.analysis import scan_file, run_analysis
from pdfchecker.core.campaigns import group_campaigns
from pdfchecker.core.coverage import check_coverage
from pdfchecker.core.pdf_access import (DEFAULT_MAX_FILE_SIZE_MB, get_max_file_size_mb,
                                        set_max_file_size_mb, set_password, validate_pdf)
from pdfchecker.core.policies import load_policy, evaluate_policy
from pdfchecker.core.structure_analyzer import analyze_structure
from pdfchecker.core.url_discovery import discover_urls, has_mismatch
from pdfchecker.core.yara_scanner import compile_rules

ROOT = Path(__file__).resolve().parents[1]
HAS_YARA = importlib.util.find_spec('yara') is not None


class AnalysisFeatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.addCleanup(set_password, None)
        self.addCleanup(set_max_file_size_mb, DEFAULT_MAX_FILE_SIZE_MB)
        self.qr = patch.multiple('pdfchecker.core.qr_detector', QR_SUPPORT=False, cv2=None, np=None)
        self.qr.start()
        self.addCleanup(self.qr.stop)

    def pdf(self, name='sample.pdf', password=None, configure=None):
        path = self.folder / name
        with fitz.open() as doc:
            doc.new_page()
            if configure:
                configure(doc)
            options = {'encryption': fitz.PDF_ENCRYPT_AES_256, 'user_pw': password,
                       'owner_pw': 'owner-secret'} if password is not None else {}
            doc.save(path, **options)
        return str(path)

    def cli(self, *args, env=None):
        return subprocess.run([sys.executable, '-m', 'pdfchecker', *args], cwd=ROOT,
                              capture_output=True, text=True, timeout=40,
                              env=dict(os.environ, **(env or {})))

    def test_usage_reference_documents_every_cli_option(self):
        from pdfchecker.main import create_argument_parser
        reference = (ROOT / 'docs' / 'usage.md').read_text()
        for action in create_argument_parser()._actions:
            if action.help == argparse.SUPPRESS or '--help' in action.option_strings:
                continue
            # Table cells name every spelling of the option, e.g. `-a, --analyze`
            spelling = ', '.join(action.option_strings)
            self.assertTrue('`' + spelling in reference, f'{spelling} is missing from docs/usage.md')

    def test_help_explains_main_path_policy_password_and_exit_codes(self):
        result = self.cli('-h')
        self.assertEqual(result.returncode, 0)
        for text in ['--analyze', '--policy', '--yara', '--campaigns', '--ask-password',
                     '--password-env', '3 policy rejected', 'risk_threshold']:
            self.assertIn(text, result.stdout)
        self.assertNotIn('__main__.py', result.stdout)

    def test_conflicting_actions_and_misplaced_options_are_usage_errors(self):
        for args in [('-a','a.pdf','-l','a.pdf'), ('-l','a.pdf','--policy','x.json'),
                     ('-a','a.pdf','--fail-on-risk','101'), ('-a','a.pdf','--campaigns'),
                     ('-a','a.pdf','--set-api-key'), ('--ask-password',)]:
            with self.subTest(args=args):
                self.assertEqual(self.cli(*args).returncode, 2)

    def test_coverage_states(self):
        self.assertEqual(check_coverage('urls', {'urls': []})['status'], 'completed')
        self.assertEqual(check_coverage('qr', {'supported': False})['status'], 'unavailable')
        self.assertEqual(check_coverage('urls', {'errors': ['failed']})['status'], 'failed')
        self.assertEqual(check_coverage('qr', {'pages_skipped': 3})['status'], 'limited')
        self.assertEqual(check_coverage('urls', {'limits': ['bounded']})['status'], 'limited')

    def test_full_scan_reports_unavailable_and_not_requested(self):
        result = scan_file(self.pdf())
        self.assertEqual(result['coverage']['qr']['status'], 'unavailable')
        self.assertEqual(result['coverage']['yara']['status'], 'not_requested')
        self.assertEqual(result['coverage']['urls']['status'], 'completed')
        self.assertEqual(result['risk']['score'], 0)

    def test_full_scan_opens_document_once(self):
        path = self.pdf()
        with patch('pdfchecker.core.pdf_access.fitz.open', wraps=fitz.open) as opened:
            scan_file(path)
        self.assertEqual(opened.call_count, 1)

    def test_policy_validation_and_override(self):
        path = self.folder / 'policy.json'
        path.write_text(json.dumps({'risk_threshold': 60, 'reject_javascript': True}))
        self.assertEqual(load_policy(path, 20)['risk_threshold'], 20)
        for invalid in [{'reject_javascript': 'false'}, {'risk_threshold': True},
                        {'risk_threshold': -1}, {'unknown_key': True}, []]:
            path.write_text(json.dumps(invalid))
            with self.assertRaises(ValueError):
                load_policy(path)

    def test_strict_coverage_policy_cannot_pass_unavailable_checks(self):
        result = scan_file(self.pdf())
        decision = evaluate_policy(result, {'require_complete': True})
        self.assertEqual(decision['status'], 'unknown')
        self.assertTrue(any('qr' in item for item in decision['unknown']))

    def test_terminal_policy_exit_codes(self):
        path = self.pdf()
        for threshold, expected in [(0, 3), (100, 0)]:
            result = self.cli('-a', path, '--fail-on-risk', str(threshold))
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertIn('Coverage:', result.stdout)
            self.assertIn('Policy:', result.stdout)
        bad = self.folder / 'bad.pdf'
        bad.write_text('invalid')
        self.assertEqual(self.cli('-a', str(bad)).returncode, 1)

    def test_javascript_attachment_policies(self):
        def configure(doc):
            doc.xref_set_key(doc.pdf_catalog(), 'OpenAction', '<< /S /JavaScript /JS (app.alert) >>')
            doc.embfile_add('note.txt', b'note')
        result = scan_file(self.pdf(configure=configure))
        decision = evaluate_policy(result, {'reject_javascript': True, 'reject_attachments': True})
        self.assertEqual(decision['status'], 'fail')
        self.assertEqual(len(decision['violations']), 2)

    def test_encrypted_single_and_bulk_password_not_disclosed(self):
        secret = ' unusual password! '
        paths = [self.pdf(f'{n}.pdf', password=secret) for n in range(2)]
        for target in [paths[0], str(self.folder)]:
            result = self.cli('-a', target, '--password-env', 'PDF_TEST_PASSWORD', '--json',
                              env={'PDF_TEST_PASSWORD': secret})
            self.assertEqual(result.returncode, 0, result.stderr)
            parsed = json.loads(result.stdout)
            self.assertTrue(all(row['ok'] for row in parsed['files']))
            self.assertNotIn(secret, result.stdout + result.stderr)
        result = self.cli('-a', paths[0], '--password-env', 'PDF_TEST_PASSWORD', '--json',
                          env={'PDF_TEST_PASSWORD': 'wrong'})
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(json.loads(result.stdout)['files'][0]['risk'])

    def test_password_support_in_existing_commands_and_export(self):
        path = self.pdf(password='secret', configure=lambda d: d[0].insert_text((30,30), 'https://example.com'))
        for action in ['-js', '-m', '-sa', '-ef', '-rs', '-l', '-i']:
            result = self.cli(action, path, '--json', '--password-env', 'PDF_TEST_PASSWORD',
                              env={'PDF_TEST_PASSWORD': 'secret'})
            self.assertEqual(result.returncode, 0, result.stderr)
            json.loads(result.stdout)

    def test_broader_urls_include_text_action_script_and_provenance(self):
        def configure(doc):
            doc[0].insert_text((30,30), 'Visit https://text.example/path.')
            doc.xref_set_key(doc.pdf_catalog(), 'OpenAction',
                             '<< /S /URI /URI (https://action.example/path) >>')
            action = doc.get_new_xref()
            doc.update_object(action, '<< /S /JavaScript /JS (app.launchURL\\("https://script.example/path"\\)) >>')
        result = discover_urls(self.pdf(configure=configure))
        values = {entry['url']: entry['sources'] for entry in result['urls']}
        self.assertEqual(values['https://text.example/path'][0]['origin'], 'text')
        self.assertEqual(values['https://text.example/path'][0]['page'], 1)
        self.assertEqual(values['https://action.example/path'][0]['origin'], 'action')
        self.assertEqual(values['https://script.example/path'][0]['origin'], 'javascript')

    def test_mismatched_visible_url_is_flagged(self):
        def configure(doc):
            page = doc[0]
            page.insert_text((30,30), 'https://bank.example')
            page.insert_link({'kind': fitz.LINK_URI, 'uri': 'https://other.example',
                              'from': fitz.Rect(28,15,200,35)})
        findings = discover_urls(self.pdf(configure=configure))
        entry = next(row for row in findings['urls'] if row['url'] == 'https://other.example')
        self.assertTrue(any(source.get('mismatch') for source in entry['sources']))

    def test_url_limits_are_reported(self):
        path = self.pdf(configure=lambda d: d[0].insert_text((30,30), 'https://one.example https://two.example'))
        with patch('pdfchecker.core.url_discovery.MAX_URLS', 1):
            result = discover_urls(path)
        self.assertEqual(len(result['urls']), 1)
        self.assertEqual(check_coverage('urls', result)['status'], 'limited')

    def test_campaigns_group_transitively_and_do_not_group_by_domain_only(self):
        results = []
        for name, urls in [('a', ['https://Example.com/a']), ('b', ['https://example.com:443/a', 'https://x.example/b']),
                           ('c', ['https://x.example/b']), ('d', ['https://example.com/d'])]:
            results.append({'path': name, 'link_findings': {'urls': [{'url': u} for u in urls]}})
        groups = group_campaigns(results)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]['files'], ['a', 'b', 'c'])
        self.assertEqual(len(groups[0]['shared_indicators']), 2)

    def test_recursive_campaign_cli(self):
        def configure(doc):
            doc[0].insert_text((30,30), 'https://common.example/campaign')
        self.pdf('first.pdf', configure=configure)
        (self.folder / 'nested').mkdir()
        self.pdf('nested/second.pdf', configure=configure)
        self.pdf('unrelated.pdf')
        result = self.cli('-a', str(self.folder), '--recursive', '--campaigns', '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed['summary']['total'], 3)
        self.assertEqual(len(parsed['campaigns']), 1)
        self.assertEqual(len(parsed['campaigns'][0]['files']), 2)

    def test_missing_yara_support_is_actionable(self):
        with patch.dict(sys.modules, {'yara': None}):
            with self.assertRaisesRegex(ValueError, 'pdfchecker\\[yara\\]'):
                compile_rules(['ignored.yar'])

    @unittest.skipUnless(HAS_YARA, 'optional yara-python not installed')
    def test_real_yara_matches_pdf_script_attachment_and_exit_policy(self):
        rules = self.folder / 'rules.yar'
        rules.write_text('''rule pdf_header { strings: $a = "%PDF" condition: $a }
rule payload_marker { strings: $a = "feature_test_marker" condition: $a }''')
        def configure(doc):
            script = doc.get_new_xref()
            doc.update_object(script, '<<>>')
            doc.update_stream(script, b'app.alert("feature_test_marker")')
            doc.xref_set_key(doc.pdf_catalog(), 'OpenAction', f'<< /S /JavaScript /JS {script} 0 R >>')
            doc.embfile_add('attachment.txt', b'feature_test_marker')
        path = self.pdf(password='secret', configure=configure)
        set_password('secret')
        scanned = scan_file(path, compile_rules([str(rules)]))
        self.assertEqual(scanned['coverage']['yara']['status'], 'completed')
        sources = {match['source'] for match in scanned['yara']['matches']}
        self.assertEqual(sources, {'pdf', 'javascript', 'attachment'})
        self.assertNotIn('data', scanned['embedded']['embedded_files'][0])
        policy = self.folder / 'policy.json'
        policy.write_text('{"reject_yara": true}')
        result = self.cli('-a', path, '--yara', str(rules), '--policy', str(policy),
                          '--password-env', 'PDF_TEST_PASSWORD', '--json', env={'PDF_TEST_PASSWORD':'secret'})
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(result.stdout)['files'][0]['policy']['status'], 'fail')

    @unittest.skipUnless(HAS_YARA, 'optional yara-python not installed')
    def test_yara_timeout_and_byte_limits_mark_coverage_limited(self):
        rules = self.folder / 'rules.yar'
        rules.write_text('rule any_file { condition: true }')
        with patch('pdfchecker.core.yara_scanner.MAX_TARGET_BYTES', 1):
            result = scan_file(self.pdf(), compile_rules([str(rules)]))
        self.assertEqual(result['coverage']['yara']['status'], 'limited')
        self.assertEqual(evaluate_policy(result, {'reject_yara': True})['status'], 'unknown')

    def test_skipped_inputs_override_policy_rejection_exit_code(self):
        self.pdf()
        oversized = self.folder / 'oversized.pdf'
        with oversized.open('wb') as output:
            output.truncate(101 * 1024 * 1024)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = run_analysis(str(self.folder), {'risk_threshold': 0}, json_mode=True)
        result = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(result['summary']['policy_failed'], 1)
        self.assertEqual(len(result['summary']['skipped']), 1)

    def padded_pdf(self, name, size_mb):
        # A valid PDF followed by sparse zero padding, so it costs no disk space
        path = self.pdf(name)
        with open(path, 'r+b') as output:
            output.truncate(size_mb * 1024 * 1024)
        return path

    def test_max_size_setting_validates_range_and_controls_input_checks(self):
        path = self.padded_pdf('large.pdf', 101)
        self.assertIn('too large', validate_pdf(path))
        set_max_file_size_mb(150)
        self.assertIsNone(validate_pdf(path))
        for invalid in (0, -1, 2049):
            with self.assertRaises(ValueError):
                set_max_file_size_mb(invalid)
        self.assertEqual(get_max_file_size_mb(), 150)

    def test_cli_max_size_reaches_isolated_folder_workers(self):
        self.padded_pdf('large.pdf', 101)
        result = self.cli('-a', str(self.folder), '--json')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)['summary']['skipped']), 1)
        # Workers re-validate each file, so the raised limit must reach them
        result = self.cli('-a', str(self.folder), '--json', '--max-size', '150')
        self.assertEqual(result.returncode, 0, result.stderr)
        files = json.loads(result.stdout)['files']
        self.assertEqual(len(files), 1)
        self.assertIsNotNone(files[0]['risk'])

    def test_cli_rejects_invalid_or_misplaced_max_size(self):
        for value in ('0', '2049', 'abc'):
            result = self.cli('-a', self.pdf(), '--max-size', value)
            self.assertEqual(result.returncode, 2)
            self.assertIn('--max-size', result.stderr)
        self.assertEqual(self.cli('--max-size', '200').returncode, 2)
        self.assertEqual(self.cli('--show-api-key', '--max-size', '200').returncode, 2)

    def test_campaigns_use_complete_script_and_attachment_evidence(self):
        results = [{'path': path, 'javascript': {'javascript_sources': [{'full_content': 'shared-script'}]},
                    'embedded': {'embedded_files': [{'hashes': {'SHA-256': 'a'*64}}]}}
                   for path in ['first', 'second']]
        groups = group_campaigns(results)
        self.assertEqual({row['type'] for row in groups[0]['shared_indicators']},
                         {'javascript-sha256', 'attachment-sha256'})
        for result in results:
            result.pop('embedded')
            result['javascript']['javascript_sources'][0]['full_content'] = 'partial... [Content truncated for security]'
        self.assertEqual(group_campaigns(results), [])

    @unittest.skipUnless(HAS_YARA, 'optional yara-python not installed')
    def test_bulk_yara_uses_compiled_rules_and_keeps_json_clean(self):
        rules = self.folder / 'console.yar'
        rules.write_text('import "console" rule matched { condition: console.log("RULE_OUTPUT") }')
        for number in range(2):
            self.pdf(f'{number}.pdf')
        result = self.cli('-a', str(self.folder), '--yara', str(rules), '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(len(parsed['files']), 2)
        self.assertTrue(all(row['yara']['matches'] for row in parsed['files']))
        self.assertNotIn('RULE_OUTPUT', result.stdout)

    @unittest.skipUnless(HAS_YARA, 'optional yara-python not installed')
    def test_yara_timeout_is_not_reported_as_clean(self):
        import yara
        from types import SimpleNamespace
        path = self.pdf()
        engine = SimpleNamespace(match=lambda **kwargs: (_ for _ in ()).throw(yara.TimeoutError('timeout')))
        with patch('yara.load', return_value=engine):
            result = scan_file(path, b'compiled')
        self.assertEqual(result['coverage']['yara']['status'], 'limited')
        self.assertEqual(evaluate_policy(result, {'reject_yara': True})['status'], 'unknown')

    @unittest.skipUnless(HAS_YARA, 'optional yara-python not installed')
    def test_bad_yara_rule_is_usage_error(self):
        rules = self.folder / 'broken.yar'
        rules.write_text('this is not a yara rule')
        result = self.cli('-a', self.pdf(), '--yara', str(rules))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('Traceback', result.stderr)

    def test_link_mismatch_adds_risk_and_policy_can_reject_it(self):
        def configure(doc):
            page = doc[0]
            page.insert_text((30, 30), 'https://www.bank.example/login')
            page.insert_link({'kind': fitz.LINK_URI, 'uri': 'https://bank.example.attacker.test/x',
                              'from': page.search_for('https://www.bank.example/login')[0]})
        result = scan_file(self.pdf(configure=configure))
        links = result['risk']['categories']['links']
        self.assertEqual(links['score'], 10)
        self.assertEqual(links['reasons'],
                         ['Link text shows bank.example but opens bank.example.attacker.test'])
        policy_file = self.folder / 'policy.json'
        policy_file.write_text(json.dumps({'reject_link_mismatch': True}))
        policy = load_policy(policy_file)
        self.assertEqual(evaluate_policy(result, policy)['status'], 'fail')
        clean = scan_file(self.pdf('clean.pdf'))
        self.assertEqual(evaluate_policy(clean, policy)['status'], 'pass')
        clean['coverage']['urls'] = {'status': 'failed', 'details': []}
        self.assertEqual(evaluate_policy(clean, policy)['status'], 'unknown')

    def test_link_text_naming_the_same_site_is_not_a_mismatch(self):
        def configure(doc):
            page = doc[0]
            for y, shown, target in [(30, 'https://www.bank.example/a', 'https://bank.example/a'),
                                     (60, 'https://bank.example/b', 'https://login.bank.example/b'),
                                     (90, 'https://secure.bank.example/c', 'http://bank.example/c')]:
                page.insert_text((30, y), shown)
                page.insert_link({'kind': fitz.LINK_URI, 'uri': target, 'from': page.search_for(shown)[0]})
        result = scan_file(self.pdf(configure=configure))
        self.assertFalse(any(has_mismatch(entry) for entry in result['link_findings']['urls']))
        self.assertEqual(result['risk']['categories']['links']['score'], 0)

    @staticmethod
    def clean_pdf():
        with fitz.open() as doc:
            doc.new_page()
            return doc.tobytes()

    def layout_anomalies(self, data):
        path = self.folder / 'layout.pdf'
        path.write_bytes(data)
        return {anomaly['type']: anomaly for anomaly in analyze_structure(str(path))['anomalies']
                if anomaly['type'] in ('Missing PDF Header', 'Data Before Header', 'Data After EOF')}

    def test_data_hidden_outside_the_pdf_body_is_classified(self):
        clean = self.clean_pdf()
        script = b'<script language="VBScript">CreateObject("WScript.Shell")</script>'
        cases = [
            (b'MZ' + b'\x90' * 62 + clean, 'Data Before Header', 'Critical', 'Bytes 0-63: Windows executable (PE)'),
            (clean + _zip(b'notes'), 'Data After EOF', 'High', 'ZIP archive'),
            (clean + _zip(b'<hta:application/>' + script), 'Data After EOF', 'Critical', 'ZIP archive (or Office/JAR container) with script markup'),
            (clean + b'\n<html>' + script, 'Data After EOF', 'Critical', 'HTML or SVG document with script markup'),
            (clean + b'\r\n' + script, 'Data After EOF', 'Critical', 'HTML application or script markup'),
            (clean + b'\x1a' * 40, 'Data After EOF', 'Medium', '40 bytes, unrecognized content'),
        ]
        for data, kind, severity, label in cases:
            with self.subTest(label=label):
                anomaly = self.layout_anomalies(data)[kind]
                self.assertEqual(anomaly['severity'], severity)
                self.assertIn(label, anomaly['locations'][0])

    def test_payload_before_a_forged_final_trailer_is_found(self):
        clean = self.clean_pdf()
        trailer = clean[clean.rindex(b'startxref'):]
        forged = clean + _zip(b'notes') + b'\n' + trailer
        anomaly = self.layout_anomalies(forged)['Data After EOF']
        self.assertEqual(anomaly['severity'], 'High')
        self.assertIn('before a later %%EOF', anomaly['locations'][0])
        # Instances of one anomaly type report the worst severity
        anomaly = self.layout_anomalies(forged + b'MZ' + b'\x90' * 62)['Data After EOF']
        self.assertEqual((anomaly['count'], anomaly['severity']), (2, 'Critical'))

    def test_executable_polyglot_raises_the_risk_floor(self):
        path = self.folder / 'polyglot.pdf'
        path.write_bytes(b'MZ' + b'\x90' * 62 + self.clean_pdf())
        self.assertEqual(scan_file(str(path))['risk']['level'], 'High')

    def test_missing_header_is_reported(self):
        anomalies = self.layout_anomalies(b'x' * 2000 + self.clean_pdf())
        self.assertEqual(anomalies['Missing PDF Header']['severity'], 'Medium')
        self.assertIn('Bytes 0-1999', anomalies['Data Before Header']['locations'][0])

    def test_legitimate_file_layouts_are_not_flagged(self):
        clean = self.clean_pdf()
        path = self.folder / 'incremental.pdf'
        path.write_bytes(clean)
        with fitz.open(path) as doc:
            doc[0].insert_text((30, 30), 'revised')
            doc.saveIncr()
        incremental = path.read_bytes()
        with fitz.open() as doc:
            doc.new_page()
            doc.embfile_add('inner.pdf', clean)
            xref = next(x for x in range(1, doc.xref_length())
                        if doc.xref_get_key(x, 'Type')[1] == '/EmbeddedFile')
            doc.update_stream(xref, clean, compress=False)
            embedded = doc.tobytes()
        # Revisions and uncompressed attachments put %%EOF inside the body
        self.assertEqual(incremental.count(b'%%EOF'), 2)
        self.assertIn(clean, embedded)
        for name, data in [('clean', clean), ('padded', b'\r\n' + clean + b'\r\n\x00\x00 \n'),
                           ('incremental', incremental), ('uncompressed attachment', embedded)]:
            with self.subTest(name=name):
                self.assertEqual(self.layout_anomalies(data), {})


def _zip(content):
    buffer = io.BytesIO()
    # Stored, not deflated, so the content stays visible in the raw bytes
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('payload.hta', content)
    return buffer.getvalue()


if __name__ == '__main__':
    unittest.main()
