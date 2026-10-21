# Structural anomaly detection: flags dangerous PDF constructs that do not
# depend on JavaScript content, such as auto-run actions, launch actions,
# XFA forms, name obfuscation, malformed cross-reference structures and data
# hidden outside the PDF body (polyglot files).
import logging
import mmap
import os
import re

from .coverage import check_coverage, print_coverage
from .embedded_file_detector import detect_content_type
from .pdf_access import document
from .pdf_objects import Name, decode_name, object_map, open_action_nodes, walk

logger = logging.getLogger(__name__)

MAX_LOCATIONS_PER_ANOMALY = 10
MAX_ANOMALY_ERRORS = 10

# (regex on the decoded object text, anomaly type, severity, description).
# Names are alphanumeric in these keys, so a negative lookahead is enough to
# avoid prefix matches (e.g. /AA must not match Apple's /AAPL metadata keys).
_KEY_CHECKS = [
    (re.compile(r'/Launch(?![0-9A-Za-z])'), "Launch Action", "Critical",
     "Action that launches an external application or file"),
    (re.compile(r'/AA(?![0-9A-Za-z])'), "Additional Actions", "Medium",
     "Actions triggered automatically by document or page events"),
    (re.compile(r'/XFA(?![0-9A-Za-z])'), "XFA Form", "Medium",
     "XML Forms Architecture content (scriptable, historically abused)"),
    (re.compile(r'/RichMedia(?![0-9A-Za-z])'), "RichMedia", "High",
     "Embedded rich media annotation (Flash-era exploit vector)"),
    (re.compile(r'/GoToR(?![0-9A-Za-z])'), "Remote GoTo Action", "Medium",
     "Action that opens an external document"),
    (re.compile(r'/GoToE(?![0-9A-Za-z])'), "Embedded GoTo Action", "Medium",
     "Action that navigates into an embedded document"),
    (re.compile(r'/SubmitForm(?![0-9A-Za-z])'), "SubmitForm Action", "Medium",
     "Action that sends form data to an external server"),
    (re.compile(r'/ImportData(?![0-9A-Za-z])'), "ImportData Action", "Medium",
     "Action that imports external data into the document"),
    (re.compile(r'/JBIG2Decode(?![0-9A-Za-z])'), "JBIG2 Stream", "Low",
     "JBIG2-compressed stream (historical exploit vector)"),
]

# Raw-byte scan for hex-escaped name tokens (e.g. /J#61vaScript). MuPDF
# normalizes names when parsing, so evasion attempts are only visible in the
# raw file. Only names decoding to a risky keyword are flagged, which keeps
# random matches inside compressed streams out of the results.
# The token length is bounded (PDF names are <=127 bytes per the spec) so the
# scan over the whole raw file stays linear and cannot backtrack pathologically.
_OBFUSCATED_NAME_PATTERN = re.compile(
    rb'/([0-9A-Za-z#]{0,127}#[0-9A-Fa-f]{2}[0-9A-Za-z#]{0,127})')
_OBFUSCATION_TARGET_KEYWORDS = frozenset([
    'javascript', 'js', 'launch', 'openaction', 'aa', 'embeddedfile',
    'richmedia', 'xfa', 'uri', 'action', 'gotor', 'gotoe', 'names', 'filespec'
])

# Readers skip bytes before the %PDF header and after %%EOF, so those ranges
# can hold a second file (a PDF/ZIP or PDF/HTA polyglot) without changing how
# the document renders. Strict readers want the header in the first 1024 bytes.
HEADER_SEARCH_LIMIT = 1024
_PDF_HEADER = b'%PDF-'
_EOF_MARKER = b'%%EOF'
_PDF_WHITESPACE = re.compile(rb'[\x00\t\n\x0c\r ]*')
# mshta runs these wherever they appear in a file, not only at its start.
# The literal '<' prefix keeps the search a fast scan even over large ranges.
_SCRIPT_MARKUP = re.compile(rb'<(?:script|hta:application)\b', re.IGNORECASE)
_HTML_START = re.compile(rb'<(?:!doctype\s+html|html|svg)\b', re.IGNORECASE)
_MAGIC_PROBE_SIZE = 64


SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


class StructureFindings:
    def __init__(self):
        self._anomalies = {}
        self.errors = []

    def add(self, anomaly_type, severity, description, location=None):
        entry = self._anomalies.setdefault(anomaly_type, {
            "type": anomaly_type,
            "severity": severity,
            "description": description,
            "count": 0,
            "locations": []
        })
        # Instances of one type may differ in severity; report the worst
        if SEVERITIES.index(severity) < SEVERITIES.index(entry["severity"]):
            entry["severity"] = severity
        entry["count"] += 1
        if location and len(entry["locations"]) < MAX_LOCATIONS_PER_ANOMALY:
            entry["locations"].append(location)

    def add_error(self, message):
        if len(self.errors) < MAX_ANOMALY_ERRORS:
            self.errors.append(message)

    def to_dict(self):
        anomalies = sorted(self._anomalies.values(),
                           key=lambda a: SEVERITIES.index(a["severity"]))
        summary = {}
        for anomaly in anomalies:
            summary[anomaly["severity"]] = summary.get(anomaly["severity"], 0) + 1
        return {
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "severity_summary": summary,
            "errors": self.errors
        }


def _scan_xref_objects(doc, findings, xref_cache=None):
    objects = object_map(doc, xref_cache)
    automatic = open_action_nodes(doc, objects)
    for xref, obj in objects.items():
        nodes = list(walk(obj))
        # Only dictionary keys and name values are syntax; strings are data.
        names = [str(node) for node in nodes if isinstance(node, Name)]
        names.extend(key for node in nodes if isinstance(node, dict) for key in node)
        tokens = set(names)
        location = f"XRef {xref}"
        for pattern, anomaly_type, severity, description in _KEY_CHECKS:
            if any(pattern.fullmatch('/' + name) for name in tokens):
                findings.add(anomaly_type, severity, description, location)
        if 'EmbeddedFile' in tokens:
            findings.add("Embedded File Stream", "Low",
                         "Embedded file stream (see embedded file analysis for details)", location)
    catalog = objects.get(doc.pdf_catalog(), {})
    if isinstance(catalog, dict) and 'OpenAction' in catalog:
        has_js = any(isinstance(node, dict) and 'JS' in node and id(node) in automatic
                     for obj in objects.values() for node in walk(obj))
        findings.add("OpenAction with JavaScript" if has_js else "OpenAction",
                     "High" if has_js else "Low",
                     "JavaScript executed automatically when the document opens" if has_js else
                     "Action executed automatically when the document opens",
                     f"XRef {doc.pdf_catalog()}")


def _scan_raw_file(pdf_path, findings):
    try:
        with open(pdf_path, 'rb') as f:
            if os.fstat(f.fileno()).st_size == 0:
                return
            # Scan the file in place rather than allocating a second bytes
            # object as large as the PDF. A read-only mapping still presents
            # the exact same byte sequence to the compiled regexes.
            with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as raw:
                _collect_obfuscated_names(raw, findings)
                _check_file_layout(raw, findings)
    except OSError as e:
        findings.add_error(f"Raw scan error: {e}")


def _hidden_content(raw, start, end, known_only=False):
    """(severity, description, offset) of bytes in raw[start:end] that readers
    skip, where offset is the first byte after any whitespace, or None when
    they are only whitespace. With known_only, for ranges that may
    legitimately hold PDF objects, None unless they start as another
    recognizable file format."""
    start = _PDF_WHITESPACE.match(raw, start, end).end()
    if start >= end:
        return None
    head = raw[start:min(end, start + _MAGIC_PROBE_SIZE)]
    content_type, executable = detect_content_type(head)
    if content_type is None and _HTML_START.match(head):
        content_type = "HTML or SVG document"
    if known_only and content_type is None and not _SCRIPT_MARKUP.match(head):
        return None
    if executable:
        return "Critical", content_type, start
    if _SCRIPT_MARKUP.search(raw, start, end):
        return "Critical", (f"{content_type} with script markup" if content_type
                            else "HTML application or script markup"), start
    if content_type:
        return "High", content_type, start
    return "Medium", "unrecognized content", start


def _check_file_layout(raw, findings):
    header = raw.find(_PDF_HEADER)
    if not 0 <= header < HEADER_SEARCH_LIMIT:
        findings.add("Missing PDF Header", "Medium",
                     f"No %PDF header in the first {HEADER_SEARCH_LIMIT} bytes "
                     "(strict readers reject the file, lenient ones repair it)")
    hidden = _hidden_content(raw, 0, header) if header > 0 else None
    if hidden:
        severity, content, offset = hidden
        findings.add("Data Before Header", severity,
                     "Bytes before the %PDF header, which readers skip; "
                     "they can hold a second file format (polyglot)",
                     f"Bytes {offset}-{header - 1}: {content}")

    body = max(header, 0)
    last = raw.rfind(_EOF_MARKER, body)
    if last < 0:
        return
    description = ("Bytes after an %%EOF marker outside the PDF body; "
                   "they can hold a second file format (polyglot)")
    # An earlier %%EOF normally ends a revision and is followed by its
    # objects, so only a recognizable file is reported there. This catches a
    # payload appended before a forged final trailer.
    position = raw.find(_EOF_MARKER, body, last)
    while position >= 0:
        start = position + len(_EOF_MARKER)
        following = raw.find(_EOF_MARKER, start, last)
        hidden = _hidden_content(raw, start, following if following >= 0 else last,
                                 known_only=True)
        if hidden:
            severity, content, offset = hidden
            findings.add("Data After EOF", severity, description,
                         f"Offset {offset}: {content}, before a later %%EOF")
        position = following
    hidden = _hidden_content(raw, last + len(_EOF_MARKER), len(raw))
    if hidden:
        severity, content, offset = hidden
        findings.add("Data After EOF", severity, description,
                     f"Offset {offset}: {len(raw) - offset} bytes, {content}")


def _collect_obfuscated_names(raw, findings):
    seen = set()
    for match in _OBFUSCATED_NAME_PATTERN.finditer(raw):
        decoded = decode_name(match.group(1).decode('ascii', errors='ignore'))
        normalized = decoded.strip().lower()
        if normalized in _OBFUSCATION_TARGET_KEYWORDS and normalized not in seen:
            seen.add(normalized)
            findings.add("Obfuscated Name", "High",
                         "Hex-escaped PDF name hiding a risky keyword",
                         f"/{match.group(1).decode('ascii', errors='ignore')} -> /{decoded}")


def _scan_document_structure(doc, findings, xref_cache=None):
    _scan_xref_objects(doc, findings, xref_cache)

    if doc.is_encrypted:
        findings.add("Encryption", "Info", "Document is encrypted")
    if getattr(doc, 'is_repaired', False):
        findings.add("Malformed Structure", "Medium",
                     "Cross-reference structure was broken and required repair")
    version_count = getattr(doc, 'version_count', 1)
    if version_count and version_count > 1:
        findings.add("Incremental Updates", "Low",
                     f"Document contains {version_count} revisions "
                     "(content may have changed after signing/review)")
    if doc.page_count == 0:
        findings.add("No Pages", "Medium", "Document declares zero pages")


def analyze_structure(pdf_path, doc=None, xref_cache=None):
    findings = StructureFindings()
    try:
        with document(pdf_path, doc) as opened:
            _scan_document_structure(opened, findings, xref_cache)
            # Inside the block: reading the raw file must not change its timestamps
            _scan_raw_file(pdf_path, findings)
    except Exception as e:
        logger.error(f"Error analyzing PDF structure: {str(e)}")
        findings.add_error(f"General structure analysis error: {str(e)}")

    return findings.to_dict()


def print_structure_findings(findings):
    print_coverage({'structure': check_coverage('structure', findings)})
    if not findings:
        print("No structure analysis results available.")
        return

    print("\n=== Structural Anomaly Analysis ===")
    print(f"Anomalies Detected: {findings['anomaly_count']}")

    if findings['severity_summary']:
        summary = ", ".join(f"{sev}: {count}" for sev, count
                            in findings['severity_summary'].items())
        print(f"By Severity: {summary}")

    for anomaly in findings['anomalies']:
        print(f"\n[{anomaly['severity'].upper()}] {anomaly['type']} (x{anomaly['count']})")
        print(f"   {anomaly['description']}")
        if anomaly['locations']:
            shown = ", ".join(anomaly['locations'])
            suffix = ", ..." if anomaly['count'] > len(anomaly['locations']) else ""
            print(f"   Locations: {shown}{suffix}")

    if not findings['anomalies']:
        print("No structural anomalies found.")

    if findings['errors']:
        print("\n--- Analysis Errors ---")
        for error in findings['errors']:
            print(f"ERROR: {error}")
