# Embedded file detection and extraction: enumerates attachments from the
# EmbeddedFiles name tree and FileAttachment annotations, flags risky payloads
# by extension and magic bytes, and detects orphaned /EmbeddedFile streams
# that are not referenced by any file specification (hidden payloads).
import hashlib
import logging
import os
import re
from pathlib import Path

import fitz

logger = logging.getLogger(__name__)

MAX_EXTRACTION_ERRORS = 10

HIGH_RISK_EXTENSIONS = frozenset([
    'exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'msi', 'hta', 'lnk',
    'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'bat', 'cmd', 'ps1', 'psm1',
    'jar', 'apk', 'sh', 'py', 'docm', 'xlsm', 'pptm', 'dotm', 'xlam'
])
MEDIUM_RISK_EXTENSIONS = frozenset([
    'zip', 'rar', '7z', 'iso', 'img', 'gz', 'tar', 'cab', 'ace',
    'doc', 'xls', 'ppt', 'rtf', 'html', 'htm', 'svg', 'chm', 'one'
])

# (magic bytes, human readable type, high risk when embedded)
_MAGIC_SIGNATURES = [
    (b'MZ', "Windows executable (PE)", True),
    (b'\x7fELF', "Linux executable (ELF)", True),
    (b'\xcf\xfa\xed\xfe', "macOS executable (Mach-O)", True),
    (b'\xca\xfe\xba\xbe', "Java class / universal binary", True),
    (b'%PDF', "PDF document", False),
    (b'PK\x03\x04', "ZIP archive (or Office/JAR container)", False),
    (b'Rar!', "RAR archive", False),
    (b'7z\xbc\xaf', "7-Zip archive", False),
    (b'\xd0\xcf\x11\xe0', "Legacy Office / OLE container", False),
]

_INDIRECT_REF_PATTERN = re.compile(r'(\d+)\s+0\s+R')
_EF_DICT_PATTERN = re.compile(r'/EF\s*<<(.*?)>>', re.DOTALL)
_EMBEDDED_FILE_KEY_PATTERN = re.compile(r'/EmbeddedFile(?![0-9A-Za-z])')


def _hash_bytes(data):
    return {
        'MD5': hashlib.md5(data).hexdigest(),
        'SHA-256': hashlib.sha256(data).hexdigest()
    }


def _detect_content_type(data):
    if not data:
        return None, False
    for magic, description, high_risk in _MAGIC_SIGNATURES:
        if data.startswith(magic):
            return description, high_risk
    return None, False


def _assess_risk(filename, data):
    reasons = []
    risk = "Low"

    extension = Path(filename or "").suffix.lstrip('.').lower()
    if extension in HIGH_RISK_EXTENSIONS:
        risk = "High"
        reasons.append(f"High-risk file extension: .{extension}")
    elif extension in MEDIUM_RISK_EXTENSIONS:
        risk = "Medium"
        reasons.append(f"Potentially risky file extension: .{extension}")

    # Double extension like invoice.pdf.exe is a classic lure
    stem_suffixes = Path(filename or "").suffixes
    if len(stem_suffixes) > 1:
        reasons.append(f"Multiple extensions in filename: {''.join(stem_suffixes)}")
        if risk == "Low":
            risk = "Medium"

    content_type, content_high_risk = _detect_content_type(data)
    if content_high_risk:
        risk = "High"
        reasons.append(f"Executable content detected: {content_type}")
    elif content_type and extension:
        # Extension says document, magic bytes say otherwise
        expected = {
            'pdf': "PDF document",
            'zip': "ZIP archive (or Office/JAR container)",
            'docx': "ZIP archive (or Office/JAR container)",
            'xlsx': "ZIP archive (or Office/JAR container)",
            'pptx': "ZIP archive (or Office/JAR container)",
            'jar': "ZIP archive (or Office/JAR container)",
            'rar': "RAR archive",
            '7z': "7-Zip archive",
            'doc': "Legacy Office / OLE container",
            'xls': "Legacy Office / OLE container",
            'ppt': "Legacy Office / OLE container",
        }.get(extension)
        if expected and expected != content_type:
            reasons.append(f"Content ({content_type}) does not match extension .{extension}")
            if risk == "Low":
                risk = "Medium"

    return risk, reasons, content_type


class EmbeddedFindings:
    def __init__(self):
        self.embedded_files = []
        self.hidden_streams = []
        self.errors = []

    def add_error(self, message):
        if len(self.errors) < MAX_EXTRACTION_ERRORS:
            self.errors.append(message)

    def to_dict(self):
        return {
            "embedded_count": len(self.embedded_files),
            "embedded_files": self.embedded_files,
            "hidden_stream_count": len(self.hidden_streams),
            "hidden_streams": self.hidden_streams,
            "errors": self.errors
        }


def _collect_name_tree_attachments(doc, findings, include_data):
    for index in range(doc.embfile_count()):
        try:
            info = doc.embfile_info(index)
            data = doc.embfile_get(index)
        except Exception as e:
            logger.debug(f"Error reading embedded file {index}: {str(e)}")
            findings.add_error(f"Embedded file {index} read error: {str(e)}")
            continue

        filename = info.get('filename') or info.get('ufilename') or info.get('name') or f"attachment_{index}"
        risk, reasons, content_type = _assess_risk(filename, data)
        entry = {
            "source": "EmbeddedFiles name tree",
            "index": index,
            "filename": filename,
            "description": info.get('desc') or "",
            "size": len(data) if data else info.get('size', 0),
            "hashes": _hash_bytes(data) if data else {},
            "content_type": content_type,
            "risk": risk,
            "risk_reasons": reasons
        }
        if include_data:
            entry["data"] = data
        findings.embedded_files.append(entry)


def _collect_annotation_attachments(doc, findings, include_data):
    for page_num, page in enumerate(doc):
        try:
            annotations = page.annots(types=[fitz.PDF_ANNOT_FILE_ATTACHMENT])
        except Exception as e:
            logger.debug(f"Error reading annotations on page {page_num}: {str(e)}")
            continue
        for annot in (annotations or []):
            try:
                info = annot.file_info or {}
                data = annot.get_file()
            except Exception as e:
                findings.add_error(f"Page {page_num + 1} attachment read error: {str(e)}")
                continue

            filename = info.get('filename') or f"page{page_num + 1}_attachment"
            risk, reasons, content_type = _assess_risk(filename, data)
            entry = {
                "source": f"FileAttachment annotation (page {page_num + 1})",
                "index": None,
                "filename": filename,
                "description": info.get('desc') or "",
                "size": len(data) if data else info.get('size', 0),
                "hashes": _hash_bytes(data) if data else {},
                "content_type": content_type,
                "risk": risk,
                "risk_reasons": reasons
            }
            if include_data:
                entry["data"] = data
            findings.embedded_files.append(entry)


def _find_hidden_streams(doc, findings, include_data):
    # Streams referenced from any /EF dictionary are legitimate attachments;
    # /EmbeddedFile streams outside that set are hidden or orphaned payloads.
    referenced = set()
    embedded_stream_xrefs = []

    for xref_num in range(1, doc.xref_length()):
        try:
            obj = doc.xref_object(xref_num)
        except Exception:
            continue
        if not obj:
            continue
        for ef_match in _EF_DICT_PATTERN.finditer(obj):
            for ref in _INDIRECT_REF_PATTERN.findall(ef_match.group(1)):
                referenced.add(int(ref))
        if _EMBEDDED_FILE_KEY_PATTERN.search(obj) and doc.xref_is_stream(xref_num):
            embedded_stream_xrefs.append(xref_num)

    for xref_num in embedded_stream_xrefs:
        if xref_num in referenced:
            continue
        try:
            data = doc.xref_stream(xref_num)
        except Exception:
            data = None
        content_type, high_risk = _detect_content_type(data)
        entry = {
            "xref": xref_num,
            "size": len(data) if data else 0,
            "hashes": _hash_bytes(data) if data else {},
            "content_type": content_type,
            "risk": "High" if high_risk else "Medium"
        }
        if include_data:
            entry["data"] = data
        findings.hidden_streams.append(entry)


def detect_embedded_files(pdf_path, validate_pdf_file=None, include_data=False):
    if validate_pdf_file and not validate_pdf_file(pdf_path):
        return None

    original_stats = None
    try:
        original_stats = os.stat(pdf_path)
    except Exception:
        pass

    findings = EmbeddedFindings()
    try:
        with fitz.open(pdf_path) as doc:
            _collect_name_tree_attachments(doc, findings, include_data)
            _collect_annotation_attachments(doc, findings, include_data)
            _find_hidden_streams(doc, findings, include_data)
    except Exception as e:
        logger.error(f"Error detecting embedded files: {str(e)}")
        findings.add_error(f"General embedded file detection error: {str(e)}")
    finally:
        if original_stats:
            try:
                os.utime(pdf_path, (original_stats.st_atime, original_stats.st_mtime))
            except Exception:
                pass

    return findings.to_dict()


def _sanitize_filename(filename):
    # Keep only the final path component and drop characters that could
    # escape the output directory or break the filesystem
    name = Path(str(filename).replace('\\', '/')).name
    name = re.sub(r'[^0-9A-Za-z ._-]', '_', name).strip('. ')
    return name or "unnamed_attachment"


def extract_embedded_files(pdf_path, output_dir=None):
    """Extract detected attachments and hidden streams to disk.

    Returns a list of (saved_path, sha256) tuples. Files are written without
    execute permissions; handle them in an isolated environment.
    """
    findings = detect_embedded_files(pdf_path, include_data=True)
    if not findings:
        return []

    input_path = Path(pdf_path)
    if output_dir is None:
        output_dir = input_path.parent / f"{input_path.stem}_attachments"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    saved = []
    used_names = set()

    def _unique_path(name):
        candidate = name
        counter = 1
        while candidate in used_names or (output_dir / candidate).exists():
            candidate = f"{Path(name).stem}_{counter}{Path(name).suffix}"
            counter += 1
        used_names.add(candidate)
        return output_dir / candidate

    entries = list(findings['embedded_files'])
    entries += [dict(stream, filename=f"hidden_stream_xref{stream['xref']}.bin")
                for stream in findings['hidden_streams']]

    for entry in entries:
        data = entry.get('data')
        if not data:
            continue
        target = _unique_path(_sanitize_filename(entry['filename']))
        try:
            with open(target, 'wb') as f:
                f.write(data)
            os.chmod(target, 0o600)
            saved.append((str(target), entry.get('hashes', {}).get('SHA-256', '')))
        except OSError as e:
            logger.error(f"Error writing {target}: {str(e)}")

    return saved


def print_embedded_findings(findings):
    if not findings:
        print("No embedded file analysis results available.")
        return

    print("\n=== Embedded File Analysis ===")
    print(f"Embedded Files Found: {findings['embedded_count']}")
    print(f"Hidden/Orphaned Streams: {findings['hidden_stream_count']}")

    for i, entry in enumerate(findings['embedded_files'], 1):
        print(f"\n{i}. {entry['filename']}")
        print(f"   Source: {entry['source']}")
        if entry['description']:
            print(f"   Description: {entry['description']}")
        print(f"   Size: {entry['size']} bytes")
        if entry['content_type']:
            print(f"   Content Type: {entry['content_type']}")
        for hash_type, value in entry['hashes'].items():
            print(f"   {hash_type}: {value}")
        print(f"   Risk: {entry['risk']}")
        for reason in entry['risk_reasons']:
            print(f"   WARNING: {reason}")

    for stream in findings['hidden_streams']:
        print(f"\nHidden stream at XRef {stream['xref']} ({stream['size']} bytes)")
        if stream['content_type']:
            print(f"   Content Type: {stream['content_type']}")
        for hash_type, value in stream['hashes'].items():
            print(f"   {hash_type}: {value}")
        print(f"   Risk: {stream['risk']} (not referenced by any file specification)")

    if findings['errors']:
        print("\n--- Extraction Errors ---")
        for error in findings['errors']:
            print(f"ERROR: {error}")
