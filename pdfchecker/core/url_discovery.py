"""Static URL discovery with provenance; never follows or executes URLs."""
import re
from urllib.parse import urlsplit

from .javascript_detector import extract_javascript_from_pdf
from .pdf_access import document
from .pdf_objects import object_map, walk, PDFString, resolve
from .utils import TRUNCATION_MARKER, build_xref_object_cache

URL_PATTERN = re.compile(r'''(?:https?://|ftp://|www\.)[^\s<>"'\\\x00-\x1f]+''', re.I)
MAX_TEXT_PAGES = 1000
MAX_TEXT_CHARS = 2_000_000
MAX_URLS = 10000


def text_urls(text):
    for match in URL_PATTERN.finditer(text):
        url = match.group().rstrip('.,;!')
        # Remove prose's closing delimiters while preserving balanced URL paths.
        for closing, opening in [(')', '('), (']', '['), ('}', '{')]:
            while url.endswith(closing) and url.count(closing) > url.count(opening):
                url = url[:-1]
        yield url


def hostname(url):
    """Lower-case IDNA host of a URL ('www.' links count as http), or '' when
    there is none. Callers add their own rules (e.g. dropping 'www.')."""
    candidate = url.strip()
    if candidate.lower().startswith('www.'):
        candidate = 'http://' + candidate
    try:
        return (urlsplit(candidate).hostname or '').rstrip('.').lower().encode('idna').decode('ascii')
    except (ValueError, UnicodeError):
        return ''


def site_host(url):
    """hostname() without a leading 'www.', which names the same site."""
    host = hostname(url)
    return host[4:] if host.startswith('www.') else host


# A displayed host names the destination when it is the same site or one is a
# subdomain of the other (a site linking to its own subdomain is not deceptive)
def _names_destination(shown, destination):
    return (not shown or shown == destination or shown.endswith('.' + destination)
            or destination.endswith('.' + shown))


def has_mismatch(entry):
    """Whether a discovered URL is the destination of a link whose visible
    text names a different site."""
    return any(source.get('mismatch') for source in entry['sources'])


# URLs shown inside a link's clickable area. A word belongs to the area when
# its centre does, so a partly covered URL is read whole and neighbouring
# words that merely touch the area are left out.
def _displayed_urls(words, area):
    label = ' '.join(word[4] for word in words
                     if area.contains(((word[0] + word[2]) / 2, (word[1] + word[3]) / 2)))
    return list(text_urls(label))


def discover_urls(path, doc=None, xref_cache=None, javascript=None):
    result = {'urls': [], 'errors': [], 'limits': [], 'pages_scanned': 0}
    index = {}

    def add(value, origin, **location):
        if not value:
            return
        if value not in index:
            if len(index) >= MAX_URLS:
                if 'URL count limit reached' not in result['limits']:
                    result['limits'].append('URL count limit reached')
                return
            index[value] = {'url': value, 'sources': []}
        source = dict(origin=origin, **location)
        if source not in index[value]['sources']:
            index[value]['sources'].append(source)

    with document(path, doc) as opened:
        if xref_cache is None:
            # Action URLs and the JavaScript search below share one object sweep
            xref_cache = build_xref_object_cache(opened)
        for page_number, page in enumerate(opened, 1):
            if page_number > MAX_TEXT_PAGES:
                result['limits'].append(f'Text/link page limit: {opened.page_count - MAX_TEXT_PAGES} pages skipped')
                break
            result['pages_scanned'] += 1
            try:
                text = page.get_text()
                # Link text can only show a URL when the page text contains one;
                # then the words are extracted once for all links on the page.
                words = page.get_text('words') if URL_PATTERN.search(text) else []
                for link in page.get_links():
                    uri = link.get('uri')
                    if uri:
                        source = {'page': page_number, 'xref': link.get('xref')}
                        destination = site_host(uri)
                        if destination and words and link.get('from'):
                            visible = _displayed_urls(words, link['from'])
                            if not all(_names_destination(site_host(label), destination)
                                       for label in visible):
                                source.update(displayed_urls=visible, mismatch=True)
                        add(uri, 'annotation', **source)
                if len(text) > MAX_TEXT_CHARS:
                    result['limits'].append(f'Page {page_number}: text character limit reached')
                for uri in text_urls(text[:MAX_TEXT_CHARS]):
                    add(uri, 'text', page=page_number)
            except Exception as exc:
                result['errors'].append(f'Page {page_number}: URL extraction failed: {exc}')
        try:
            objects = object_map(opened, xref_cache)
            for xref, obj in objects.items():
                for node in walk(obj):
                    if not isinstance(node, dict):
                        continue
                    # URI actions and submission/import targets may be direct,
                    # indirect, or file-spec dictionaries.
                    value = node.get('URI')
                    if value is None and node.get('S') in ('SubmitForm', 'ImportData', 'GoToR'):
                        value = node.get('F')
                    value = resolve(value, objects)
                    if isinstance(value, dict):
                        value = resolve(value.get('UF', value.get('F')), objects)
                    if isinstance(value, PDFString):
                        add(value.text(), 'action', xref=xref)
        except Exception as exc:
            result['errors'].append(f'Action URL extraction failed: {exc}')
        if javascript is None:
            javascript = extract_javascript_from_pdf(path, doc=opened, xref_cache=xref_cache)
    result['errors'].extend(javascript.get('extraction_errors', []))
    for source in javascript.get('javascript_sources', []):
        for uri in text_urls(source.get('full_content', '').replace('\\/', '/')):
            add(uri, 'javascript', location=source.get('location'))
        if source.get('full_content', '').endswith(TRUNCATION_MARKER):
            result['limits'].append('JavaScript text was truncated')
    result['urls'] = list(index.values())
    return result
