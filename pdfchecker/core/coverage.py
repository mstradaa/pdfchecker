"""Describe what was inspected, independently of whether threats were found."""
from .terminal import safe_text
from .utils import TRUNCATION_MARKER

# (coverage name, PDFAnalysisResult attribute)
COVERAGE_CHECKS = [('hashes', 'hashes'), ('metadata', 'metadata'), ('urls', 'link_findings'),
                   ('javascript', 'javascript'), ('structure', 'structure'),
                   ('attachments', 'embedded'), ('qr', 'qr')]


def finding_errors(findings):
    """Errors that left one analysis incomplete. An optional check that could
    not run (supported=False) explains why in its errors, but did not fail."""
    if not isinstance(findings, dict) or findings.get('supported') is False:
        return []
    return findings.get('errors', []) + findings.get('extraction_errors', [])


def check_coverage(name, findings):
    details = []
    status = 'completed'
    if findings is None:
        return {'status': 'failed', 'details': ['Analysis did not produce a result']}
    if isinstance(findings, dict):
        errors = findings.get('errors', []) + findings.get('extraction_errors', [])
        details.extend(errors)
        if findings.get('supported') is False:
            status = 'unavailable'
        elif errors:
            status = 'failed'
        limits = list(findings.get('limits', []))
        if findings.get('pages_skipped'):
            limits.append(f"{findings['pages_skipped']} pages skipped")
        if findings.get('undecoded_count'):
            limits.append(f"{findings['undecoded_count']} QR codes could not be decoded")
        if name == 'javascript' and any(s.get('full_content', '').endswith(TRUNCATION_MARKER)
                                        for s in findings.get('javascript_sources', [])):
            limits.append('Recovered JavaScript was truncated')
        if limits:
            details.extend(limits)
            if status == 'completed':
                status = 'limited'
    return {'status': status, 'details': list(dict.fromkeys(details))}


def analysis_coverage(result, attributes=None):
    """Coverage of every check in `result`, or only of those in `attributes`."""
    return {name: check_coverage(name, getattr(result, attr)) for name, attr in COVERAGE_CHECKS
            if attributes is None or attr in attributes}


def print_coverage(coverage):
    print('\nCoverage:')
    for name, entry in coverage.items():
        detail = '; '.join(entry.get('details', []))
        # Terminal data is untrusted; remove control sequences and keep output brief.
        print(f"  {name:12} {entry['status'].replace('_', ' ')}" +
              (f" — {safe_text(detail, 240)}" if detail else ''))
    if any(c['status'] not in ('completed', 'not_requested') for c in coverage.values()):
        print('  Coverage is incomplete; absence of findings does not establish safety.')
