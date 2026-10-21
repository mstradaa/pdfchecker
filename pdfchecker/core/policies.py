"""Small, strictly validated JSON policies for deterministic CLI decisions."""
import json

from .url_discovery import has_mismatch

BOOLEAN_RULES = {'reject_javascript', 'reject_attachments', 'reject_link_mismatch',
                 'reject_yara', 'require_complete'}


def load_policy(path=None, risk_threshold=None):
    policy = {}
    if path:
        with open(path, encoding='utf-8') as source:
            policy = json.load(source)
        if not isinstance(policy, dict):
            raise ValueError('Policy must be a JSON object')
        unknown = set(policy) - BOOLEAN_RULES - {'risk_threshold'}
        if unknown:
            raise ValueError('Unknown policy keys: ' + ', '.join(sorted(unknown)))
    if risk_threshold is not None:
        policy['risk_threshold'] = risk_threshold
    for key, value in policy.items():
        if key in BOOLEAN_RULES and type(value) is not bool:
            raise ValueError(f'Policy {key} must be true or false')
        if key == 'risk_threshold' and (type(value) is not int or not 0 <= value <= 100):
            raise ValueError('risk_threshold must be an integer from 0 to 100')
    return policy


def evaluate_policy(result, policy):
    violations = []
    unknown = []
    coverage = result['coverage']
    required = set()
    if 'risk_threshold' in policy:
        if result.get('risk') is None:
            unknown.append('Risk threshold could not be evaluated')
        elif result['risk']['score'] >= policy['risk_threshold']:
            violations.append(f"Risk {result['risk']['score']} >= {policy['risk_threshold']}")
    if policy.get('reject_javascript'):
        required.add('javascript')
        if (result.get('javascript') or {}).get('has_javascript'):
            violations.append('JavaScript is prohibited')
    if policy.get('reject_attachments'):
        required.add('attachments')
        findings = result.get('embedded') or {}
        if findings.get('embedded_count') or findings.get('hidden_stream_count'):
            violations.append('Embedded files are prohibited')
    if policy.get('reject_link_mismatch'):
        required.add('urls')
        if any(has_mismatch(entry) for entry in (result.get('link_findings') or {}).get('urls', [])):
            violations.append('Link text names a different site than its destination')
    if policy.get('reject_yara'):
        required.add('yara')
        if (result.get('yara') or {}).get('matches'):
            violations.append('YARA rule matched')
    if policy.get('require_complete'):
        required.update(key for key, item in coverage.items() if item['status'] != 'not_requested')
    for key in sorted(required):
        if coverage.get(key, {}).get('status') != 'completed':
            unknown.append(f"{key}: required check did not complete")
    return {'status': 'fail' if violations else ('unknown' if unknown else 'pass'),
            'violations': violations, 'unknown': unknown}
