"""Non-interactive terminal and JSON analysis with consistent bulk decisions."""
import contextlib
from functools import partial
import json
import os
from pathlib import Path
import sys

from . import bulk_processor
from .campaigns import group_campaigns
from .coverage import check_coverage, print_coverage
from .json_output import sanitize
from .pdf_access import validate_pdf
from .pipeline import analyze_pdf_once
from .policies import evaluate_policy
from .risk_scorer import ranking_key, risk_reasons
from .terminal import safe_text
from .url_discovery import has_mismatch
from .yara_scanner import scan_yara


def scan_file(path, compiled=None):
    error = validate_pdf(path)
    if error:
        return {'path': path, 'errors': [error], 'coverage': {'input': {'status': 'failed', 'details': [error]}}, 'risk': None}
    analysis = analyze_pdf_once(path, include_data=compiled is not None)
    result = vars(analysis).copy()
    result['path'] = path
    result['yara'] = None
    if compiled is not None:
        try:
            result['yara'] = scan_yara(path, analysis, compiled)
        except Exception as exc:
            result['yara'] = {'matches': [], 'errors': [str(exc)], 'limits': []}
        result['coverage']['yara'] = check_coverage('yara', result['yara'])
        # Matching truncated scripts or inaccessible attachments is partial.
        if result['coverage']['yara']['status'] == 'completed' and any(
                result['coverage'][name]['status'] != 'completed' for name in ('javascript', 'attachments')):
            result['coverage']['yara'] = {'status': 'limited', 'details': ['Recovered content was incomplete; original PDF was scanned']}
    else:
        result['coverage']['yara'] = {'status': 'not_requested', 'details': []}
    for entry in (result.get('embedded') or {}).get('embedded_files', []) + (result.get('embedded') or {}).get('hidden_streams', []):
        entry.pop('data', None)
    return result


def discover_inputs(target, recursive=False):
    root = Path(target)
    if not root.is_dir():
        return [str(root)], []
    files, skipped = [], []
    folders = []
    if recursive:
        def onerror(exc):
            skipped.append({'path': exc.filename or str(root), 'reason': str(exc)})
        for folder, _, _ in os.walk(root, followlinks=False, onerror=onerror):
            folders.append(folder)
    else:
        folders = [str(root)]
    for folder in folders:
        try:
            found, ignored = bulk_processor.discover_pdfs(folder)
        except OSError as exc:
            skipped.append({'path': folder, 'reason': str(exc)})
            continue
        files.extend(found)
        skipped.extend({'path': str(Path(folder)/name), 'reason': reason} for name, reason in ignored)
    return sorted(files), skipped


def print_file(result):
    print(f"\n{safe_text(result['path'])}")
    risk = result.get('risk')
    print(f"Risk: {risk['score']}/100 ({risk['level']})" if risk else 'Risk: unavailable')
    js = result.get('javascript') or {}
    embedded = result.get('embedded') or {}
    urls = (result.get('link_findings') or {}).get('urls', [])
    qr_count = (result.get('qr') or {}).get('qr_count', 0)
    print(f"Findings: {len(urls)} URLs; {qr_count} QR codes; {js.get('javascript_count', 0)} scripts; "
          f"{embedded.get('embedded_count', 0)} attachments; {embedded.get('hidden_stream_count', 0)} hidden streams")
    if risk:
        for reason in risk_reasons(risk)[:3]:
            print('  ' + safe_text(reason))
    mismatches = [entry for entry in urls if has_mismatch(entry)]
    for entry in mismatches[:10]:
        print(f"  Link text differs from destination: {safe_text(entry['url'])}")
    yara = result.get('yara') or {}
    for match in yara.get('matches', [])[:20]:
        print(f"  YARA {safe_text(match['namespace'])}:{safe_text(match['rule'])} — "
              f"{match['source']}: {safe_text(match['location'])}")
    if len(yara.get('matches', [])) > 20:
        print(f"  ... {len(yara['matches']) - 20} more YARA matches (use --json for all)")
    print_coverage(result['coverage'])
    policy = result.get('policy')
    if policy:
        print('Policy: ' + policy['status'].upper())
        for reason in policy['violations'] + policy['unknown']:
            print('  ' + safe_text(reason))


def run_analysis(target, policy=None, compiled=None, campaigns=False, recursive=False, json_mode=False):
    policy = policy or {}
    try:
        files, skipped = discover_inputs(target, recursive)
    except OSError as exc:
        files, skipped = [], [{'path': str(target), 'reason': str(exc)}]
    if not files and not skipped:
        skipped = [{'path': str(target), 'reason': 'No PDF files found'}]
    worker = partial(scan_file, compiled=compiled)
    with contextlib.redirect_stdout(sys.stderr):
        if len(files) == 1 and not Path(target).is_dir():
            try:
                raw = {files[0]: (True, worker(files[0]))}
            except Exception as exc:
                raw = {files[0]: (False, str(exc))}
        else:
            raw = bulk_processor._run_parallel(files, worker, True)
    results = []
    for path in files:
        ok, payload = raw[path]
        if not ok:
            payload = {'path': path, 'risk': None, 'errors': [str(payload)],
                       'coverage': {'worker': {'status': 'failed', 'details': [str(payload)]}}}
        payload['policy'] = evaluate_policy(payload, policy) if policy else None
        payload['ok'] = not payload.get('errors') and not any(item['status'] == 'failed' for item in payload['coverage'].values())
        results.append(payload)
    results.sort(key=lambda result: (ranking_key(result.get('risk')), result['path']))
    failed = sum(not result['ok'] for result in results)
    unknown = sum(bool((result.get('policy') or {}).get('unknown')) for result in results)
    rejected = sum((result.get('policy') or {}).get('status') == 'fail' for result in results)
    code = 1 if failed or skipped or unknown else (3 if rejected else 0)
    groups = group_campaigns(results) if campaigns else []
    summary = {'total': len(files), 'failed': failed, 'policy_failed': rejected,
               'policy_unknown': unknown, 'skipped': skipped}
    if json_mode:
        print(json.dumps(sanitize({'schema_version': 1, 'mode': 'analyze', 'files': results,
                                   'summary': summary, 'campaigns': groups, 'exit_code': code}), indent=2))
    else:
        for result in results:
            print_file(result)
        for item in skipped:
            print(f"Skipped: {safe_text(item['path'])} — {safe_text(item['reason'])}")
        if campaigns:
            print(f'\nRelated groups: {len(groups)} (shared evidence, not campaign attribution)')
            for group in groups:
                print(f"  Group {group['id']}: {len(group['files'])} files")
                for path in group['files']:
                    print('    ' + safe_text(path))
                for evidence in group['shared_indicators'][:10]:
                    print(f"    Shared {evidence['type']}: {safe_text(evidence['value'])}")
                if len(group['shared_indicators']) > 10:
                    print('    More shared indicators available with --json')
        print(f"\nSummary: {len(files)} files; {failed} failed; {len(skipped)} skipped; "
              f"{rejected} policy failures; {unknown} policy unknown. Exit code: {code}")
    return code
