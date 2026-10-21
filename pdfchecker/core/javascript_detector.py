import logging
import re

from .coverage import check_coverage, print_coverage
from .pdf_access import document
from .pdf_objects import javascript_entries, object_map, resolve, script_text, walk
from .utils import TRUNCATION_MARKER


MAX_JS_CONTENT_SIZE = 50000
PREVIEW_CONTENT_SIZE = 500
MAX_EXTRACTION_ERRORS = 10

logger = logging.getLogger(__name__)


# Match lengths are bounded (not open-ended +/*) so scanning large object text
# or page streams stays linear and cannot backtrack pathologically. The bound
# matches the amount of JavaScript we would keep anyway (MAX_JS_CONTENT_SIZE).
_M = MAX_JS_CONTENT_SIZE

JS_CONTENT_PATTERNS = [
    re.compile(r'javascript:\s*([^;]{1,%d})' % _M, re.IGNORECASE | re.DOTALL),
    re.compile(r'eval\s*\(\s*([^)]{1,%d})\s*\)' % _M, re.IGNORECASE | re.DOTALL),
    re.compile(r'function\s+\w+\s*\([^)]{0,%d}\)\s*{[^}]{0,%d}}' % (_M, _M),
               re.IGNORECASE | re.DOTALL),
]

# eval, unescape and fromCharCode are keywords below, so they are not repeated
# here: each construct produces one finding.
OBFUSCATION_PATTERNS = [
    re.compile(r'\\x[0-9a-fA-F]{2}'),
    re.compile(r'\\u[0-9a-fA-F]{4}'),
    re.compile(r'%[0-9a-fA-F]{2}'),
]

LONG_STRING_PATTERN = re.compile(r'"[^"]{100,}"')


# Tuples keep the order of reported patterns stable between runs
HIGH_SEVERITY_KEYWORDS = (
    'eval', 'exploit', 'shellcode', 'ActiveXObject', 'Shell.Application',
    'this.exportDataObject', 'this.mailDoc', 'Collab.collectEmailInfo'
)
MEDIUM_SEVERITY_KEYWORDS = (
    'unescape', 'fromCharCode', 'document.write', 'WScript.Shell',
    'payload', 'CVE-', 'overflow', 'heap', 'spray', 'ROP', 'gadget', 'bypass',
    'app.launchURL', 'app.execMenuItem', 'Collab.storeData'
)

def extract_javascript_from_pdf(pdf_path, doc=None, xref_cache=None):
    js_findings = JSFindings()

    try:
        with document(pdf_path, doc) as opened:
            _scan_document_javascript(opened, js_findings, xref_cache)
    except Exception as e:
        logger.error(f"Error extracting JavaScript from PDF: {str(e)}")
        js_findings.add_error(f"General extraction error: {str(e)}")

    return js_findings.to_dict()


def _scan_document_javascript(doc, js_findings, xref_cache=None):
    try:
        objects = object_map(doc, xref_cache)
    except Exception as e:
        js_findings.add_error(f"Document JavaScript check error: {e}")
        objects = {}

    # Page features run first so the document sweep can skip the scripts they
    # already report; the results keep the historical order.
    page_categories, reported = _check_page_features(doc, objects)
    document_findings = JSFindings()
    _check_document_javascript(doc, objects, document_findings, reported)
    for category_findings in (document_findings, *page_categories):
        js_findings.javascript_sources.extend(category_findings.javascript_sources)
        for error in category_findings.extraction_errors:
            js_findings.add_error(error)

    if js_findings.javascript_sources:
        js_findings.suspicious_patterns = _analyze_suspicious_patterns(js_findings.javascript_sources)


class JSFindings:

    def __init__(self):
        self.javascript_sources = []
        self.suspicious_patterns = []
        self.extraction_errors = []

    def add_javascript(self, source, location, content, full_content=None):
        if full_content is None:
            full_content = content

        if len(full_content) > MAX_JS_CONTENT_SIZE:
            full_content = full_content[:MAX_JS_CONTENT_SIZE] + TRUNCATION_MARKER

        preview = full_content[:PREVIEW_CONTENT_SIZE]
        if len(full_content) > PREVIEW_CONTENT_SIZE:
            preview += "..."

        self.javascript_sources.append({
            "source": source,
            "location": location,
            "content": preview,
            "full_content": full_content
        })

    def add_error(self, error_msg):
        if len(self.extraction_errors) < MAX_EXTRACTION_ERRORS:
            self.extraction_errors.append(error_msg)

    @property
    def javascript_count(self):
        return len(self.javascript_sources)

    @property
    def has_javascript(self):
        return self.javascript_count > 0

    def to_dict(self):
        return {
            "has_javascript": self.has_javascript,
            "javascript_count": self.javascript_count,
            "javascript_sources": self.javascript_sources,
            "suspicious_patterns": self.suspicious_patterns,
            "extraction_errors": self.extraction_errors
        }

# Search every document object for JavaScript, labeling open actions
# separately. `reported` holds the action dictionaries that the page passes
# already list under a more specific label (form field, annotation).
def _check_document_javascript(doc, objects, findings, reported):
    if not objects:
        return
    try:
        for xref, node, automatic, content in javascript_entries(doc, objects):
            if id(node) in reported and not automatic:
                continue
            source = "Open Action" if automatic else "Document Object"
            findings.add_javascript(source, f"XRef {xref}", content)
    except Exception as e:
        findings.add_error(f"Document JavaScript check error: {e}")


# Search page content, form fields and annotations in one document traversal.
# Results are buffered by category so they can be merged in the historical
# order; the action dictionaries they report are returned as well.
def _check_page_features(doc, objects):
    page_findings = JSFindings()
    form_findings = JSFindings()
    annotation_findings = JSFindings()
    reported = set()

    try:
        for page_num, page in enumerate(doc):
            _check_page_content(page_num, page, doc, page_findings)
            _check_page_forms(page_num, page, objects, form_findings, reported)
            _check_page_annotations(
                page_num, page, doc, objects, annotation_findings, reported)
    except Exception as e:
        page_findings.add_error(f"Page JavaScript check error: {str(e)}")
        form_findings.add_error(f"Form JavaScript check error: {str(e)}")
        annotation_findings.add_error(
            f"Annotation JavaScript check error: {str(e)}")

    return (page_findings, form_findings, annotation_findings), reported


def _check_page_content(page_num, page, doc, findings):
    try:
        xrefs = page.get_contents()
        if not xrefs:
            return
        for xref in xrefs:
            try:
                stream = doc.xref_stream(xref)
                if not stream:
                    continue
                content_str = stream.decode('utf-8', errors='ignore')
                if 'JavaScript' in content_str or '/JS' in content_str:
                    js_content = _extract_js_from_content(content_str)
                    if js_content:
                        findings.add_javascript(
                            "Page Content", f"Page {page_num + 1}",
                            js_content, js_content)
            except Exception as exc:
                findings.add_error(f"Page {page_num + 1}, stream {xref}: {exc}")
    except Exception as e:
        findings.add_error(f"Page {page_num + 1} content: {e}")


_SCRIPT_ATTRS = (
    # (PyMuPDF Widget attribute, description, action: /A or an /AA trigger)
    ('script', 'general script', 'A'),
    ('script_stroke', 'keystroke script', 'K'),
    ('script_format', 'format script', 'F'),
    ('script_change', 'value change script', 'V'),
    ('script_calc', 'calculation script', 'C'),
    ('script_blur', 'blur script', 'Bl'),
    ('script_focus', 'focus script', 'Fo'),
)


# The action dictionary PyMuPDF reads a widget script from: /A or /AA/<trigger>
# of the widget object itself
def _widget_action(objects, xref, trigger):
    widget = objects.get(xref)
    if not isinstance(widget, dict):
        return None
    if trigger == 'A':
        return resolve(widget.get('A'), objects)
    triggers = resolve(widget.get('AA'), objects)
    return resolve(triggers.get(trigger), objects) if isinstance(triggers, dict) else None


def _check_page_forms(page_num, page, objects, findings, reported):
    try:
        for widget in page.widgets() or []:
            try:
                field_name = getattr(widget, 'field_name', 'Unknown field')
                for attr_name, description, trigger in _SCRIPT_ATTRS:
                    script_content = getattr(widget, attr_name, None)
                    if script_content:
                        content_desc = f"{description}: {script_content}"
                        findings.add_javascript(
                            "Form Field",
                            f"Page {page_num + 1}, Field: {field_name}",
                            content_desc, script_content)
                        action = _widget_action(objects, widget.xref, trigger)
                        if isinstance(action, dict):
                            reported.add(id(action))
            except Exception as e:
                findings.add_error(f"Page {page_num + 1} form field: {e}")
    except Exception as e:
        findings.add_error(f"Page {page_num + 1} widgets: {e}")


def _check_page_annotations(page_num, page, doc, objects, findings, reported):
    try:
        for annot in page.annots() or []:
            try:
                # JavaScript lives in annotation actions, not in a dedicated
                # annotation type, so inspect the parsed annotation object.
                actions = [node for node in walk(objects.get(annot.xref))
                           if isinstance(node, dict) and 'JS' in node]
                if not actions:
                    continue
                reported.update(id(action) for action in actions)
                scripts = [script_text(doc, objects, action['JS']) for action in actions]
                js_content = '\n'.join(script for script in scripts if script)
                findings.add_javascript(
                    "Annotation", f"Page {page_num + 1}, Annotation",
                    js_content or "JavaScript reference detected in annotation")
            except Exception as e:
                findings.add_error(f"Page {page_num + 1} annotation: {e}")
    except Exception as e:
        findings.add_error(f"Page {page_num + 1} annotations: {e}")


def _extract_js_from_content(content_str):
    try:
        js_content = []

        for pattern in JS_CONTENT_PATTERNS:
            matches = pattern.findall(content_str)
            js_content.extend(matches)

        return ' | '.join(js_content) if js_content else None

    except Exception as e:
        logger.debug(f"Error extracting JS from content: {str(e)}")
        return None

# flag suspicious keywords or obfuscation
def _analyze_suspicious_patterns(js_sources):
    suspicious_patterns = []

    for js_source in js_sources:
        content = js_source.get('full_content', '')
        content_lower = content.lower()
        location = js_source.get('location', 'Unknown')

        for keywords, severity in ((HIGH_SEVERITY_KEYWORDS, "High"),
                                   (MEDIUM_SEVERITY_KEYWORDS, "Medium")):
            for keyword in keywords:
                if keyword.lower() in content_lower:
                    suspicious_patterns.append({
                        "type": "Suspicious Keyword",
                        "pattern": keyword,
                        "location": location,
                        "severity": severity
                    })

        for pattern in OBFUSCATION_PATTERNS:
            if pattern.search(content):
                suspicious_patterns.append({
                    "type": "Obfuscation Pattern",
                    "pattern": pattern.pattern,
                    "location": location,
                    "severity": "High"
                })

        long_strings = LONG_STRING_PATTERN.findall(content)
        if long_strings:
            suspicious_patterns.append({
                "type": "Long String",
                "pattern": f"String of length {len(long_strings[0])} characters",
                "location": location,
                "severity": "Medium"
            })

    return suspicious_patterns

def print_javascript_findings(js_findings):
    print_coverage({'javascript': check_coverage('javascript', js_findings)})
    if not js_findings:
        print("No JavaScript analysis results available.")
        return

    print("\n=== JavaScript Analysis Results ===")
    print(f"JavaScript Detected: {'Yes' if js_findings['has_javascript'] else 'No'}")
    print(f"JavaScript Objects Found: {js_findings['javascript_count']}")

    if js_findings['javascript_sources']:
        print("\n--- JavaScript Sources ---")
        for i, source in enumerate(js_findings['javascript_sources'], 1):
            print(f"{i}. Source: {source['source']}")
            print(f"   Location: {source['location']}")
            print(f"   Content Preview: {source['content']}")
            print()

    if js_findings['suspicious_patterns']:
        print("\n--- Suspicious Patterns Detected ---")
        for pattern in js_findings['suspicious_patterns']:
            print(f"WARNING:  {pattern['type']}: {pattern['pattern']}")
            print(f"   Location: {pattern['location']}")
            print(f"   Severity: {pattern['severity']}")
            print()

    if js_findings['extraction_errors']:
        print("\n--- Extraction Errors ---")
        for error in js_findings['extraction_errors']:
            print(f"ERROR: {error}")
