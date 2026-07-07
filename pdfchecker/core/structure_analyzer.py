# Structural anomaly detection: flags dangerous PDF constructs that do not
# depend on JavaScript content, such as auto-run actions, launch actions,
# XFA forms, name obfuscation and malformed cross-reference structures.
import logging
import os
import re

import fitz

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

_OPEN_ACTION_PATTERN = re.compile(r'/OpenAction(?![0-9A-Za-z])')
_JS_PATTERN = re.compile(r'/(?:JavaScript|JS)(?![0-9A-Za-z])')
_EMBEDDED_FILE_PATTERN = re.compile(r'/EmbeddedFile(?![0-9A-Za-z])')

# Raw-byte scan for hex-escaped name tokens (e.g. /J#61vaScript). MuPDF
# normalizes names when parsing, so evasion attempts are only visible in the
# raw file. Only names decoding to a risky keyword are flagged, which keeps
# random matches inside compressed streams out of the results.
_OBFUSCATED_NAME_PATTERN = re.compile(rb'/([0-9A-Za-z#]*#[0-9A-Fa-f]{2}[0-9A-Za-z#]*)')
_OBFUSCATION_TARGET_KEYWORDS = frozenset([
    'javascript', 'js', 'launch', 'openaction', 'aa', 'embeddedfile',
    'richmedia', 'xfa', 'uri', 'action', 'gotor', 'gotoe', 'names', 'filespec'
])


def _decode_pdf_name(raw_name):
    try:
        text = raw_name.decode('ascii', errors='ignore')
        return re.sub(r'#([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), text)
    except Exception:
        return None


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
        entry["count"] += 1
        if location and len(entry["locations"]) < MAX_LOCATIONS_PER_ANOMALY:
            entry["locations"].append(location)

    def add_error(self, message):
        if len(self.errors) < MAX_ANOMALY_ERRORS:
            self.errors.append(message)

    def to_dict(self):
        anomalies = sorted(
            self._anomalies.values(),
            key=lambda a: ("Critical", "High", "Medium", "Low", "Info").index(a["severity"])
        )
        summary = {}
        for anomaly in anomalies:
            summary[anomaly["severity"]] = summary.get(anomaly["severity"], 0) + 1
        return {
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "severity_summary": summary,
            "errors": self.errors
        }


def _scan_xref_objects(doc, findings):
    for xref_num in range(1, doc.xref_length()):
        try:
            obj = doc.xref_object(xref_num)
        except Exception as e:
            logger.debug(f"Error reading xref {xref_num}: {str(e)}")
            continue
        if not obj:
            continue

        location = f"XRef {xref_num}"
        for pattern, anomaly_type, severity, description in _KEY_CHECKS:
            if pattern.search(obj):
                findings.add(anomaly_type, severity, description, location)

        if _OPEN_ACTION_PATTERN.search(obj):
            if _JS_PATTERN.search(obj):
                findings.add("OpenAction with JavaScript", "High",
                             "JavaScript executed automatically when the document opens",
                             location)
            else:
                findings.add("OpenAction", "Low",
                             "Action executed automatically when the document opens",
                             location)

        if _EMBEDDED_FILE_PATTERN.search(obj):
            findings.add("Embedded File Stream", "Low",
                         "Embedded file stream (see embedded file analysis for details)",
                         location)


def _scan_raw_obfuscation(pdf_path, findings):
    try:
        with open(pdf_path, 'rb') as f:
            raw = f.read()
    except OSError as e:
        findings.add_error(f"Raw scan error: {e}")
        return

    seen = set()
    for match in _OBFUSCATED_NAME_PATTERN.finditer(raw):
        decoded = _decode_pdf_name(match.group(1))
        if not decoded:
            continue
        normalized = decoded.strip().lower()
        if normalized in _OBFUSCATION_TARGET_KEYWORDS and normalized not in seen:
            seen.add(normalized)
            findings.add("Obfuscated Name", "High",
                         "Hex-escaped PDF name hiding a risky keyword",
                         f"/{match.group(1).decode('ascii', errors='ignore')} -> /{decoded}")


def analyze_structure(pdf_path, validate_pdf_file=None):
    if validate_pdf_file and not validate_pdf_file(pdf_path):
        return None

    original_stats = None
    try:
        original_stats = os.stat(pdf_path)
    except Exception:
        pass

    findings = StructureFindings()
    try:
        with fitz.open(pdf_path) as doc:
            _scan_xref_objects(doc, findings)

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

        _scan_raw_obfuscation(pdf_path, findings)

    except Exception as e:
        logger.error(f"Error analyzing PDF structure: {str(e)}")
        findings.add_error(f"General structure analysis error: {str(e)}")
    finally:
        if original_stats:
            try:
                os.utime(pdf_path, (original_stats.st_atime, original_stats.st_mtime))
            except Exception:
                pass

    return findings.to_dict()


def print_structure_findings(findings):
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
