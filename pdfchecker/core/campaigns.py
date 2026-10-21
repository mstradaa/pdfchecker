"""Explainable grouping by exact shared indicators, without attribution claims."""
import hashlib
from collections import defaultdict
from urllib.parse import urlsplit, urlunsplit

from .url_discovery import hostname
from .utils import TRUNCATION_MARKER


def canonical_url(value):
    try:
        candidate = 'http://' + value if value.lower().startswith('www.') else value
        parsed = urlsplit(candidate)
        if not parsed.hostname or parsed.scheme.lower() not in ('http', 'https', 'ftp'):
            return value
        host = hostname(candidate)
        if not host:
            return value
        if ':' in host:
            host = '[' + host + ']'
        port = parsed.port
        if port and (parsed.scheme.lower(), port) not in (('http', 80), ('https', 443), ('ftp', 21)):
            host += ':' + str(port)
        if '@' in parsed.netloc:
            host = parsed.netloc.rsplit('@', 1)[0] + '@' + host
        return urlunsplit((parsed.scheme.lower(), host, parsed.path or '/', parsed.query, parsed.fragment))
    except (ValueError, UnicodeError):
        return value


def group_campaigns(results):
    index = defaultdict(set)
    for result in results:
        path = result['path']
        for entry in (result.get('link_findings') or {}).get('urls', []):
            index[('url', canonical_url(entry['url']))].add(path)
        for entry in (result.get('qr') or {}).get('qr_codes', []):
            if entry.get('type') == 'URL':
                index[('url', canonical_url(entry['payload']))].add(path)
        for entry in (result.get('javascript') or {}).get('javascript_sources', []):
            content = entry.get('full_content', '')
            if content and not content.endswith(TRUNCATION_MARKER):
                index[('javascript-sha256', hashlib.sha256(content.encode('utf-8')).hexdigest())].add(path)
        embedded = result.get('embedded') or {}
        for entry in embedded.get('embedded_files', []) + embedded.get('hidden_streams', []):
            digest = entry.get('hashes', {}).get('SHA-256')
            if digest:
                index[('attachment-sha256', digest)].add(path)
    shared = {key: sorted(paths) for key, paths in index.items() if len(paths) > 1}
    parent = {}

    def find(path):
        parent.setdefault(path, path)
        root = path
        while parent[root] != root:
            root = parent[root]
        while parent[path] != path:
            next_path = parent[path]
            parent[path] = root
            path = next_path
        return root

    for paths in shared.values():
        for path in paths[1:]:
            parent[find(path)] = find(paths[0])
    groups = defaultdict(list)
    for path in sorted(parent):
        groups[find(path)].append(path)
    evidence_by_group = defaultdict(list)
    for (kind, value), files in sorted(shared.items()):
        evidence_by_group[find(files[0])].append({'type': kind, 'value': value, 'files': files})
    output = []
    for paths in sorted(groups.values()):
        evidence = evidence_by_group[find(paths[0])]
        output.append({'id': len(output)+1, 'files': paths, 'shared_indicators': evidence})
    return output
