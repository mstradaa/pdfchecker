"""Opening PDFs for analysis: input validation, transient password handling
shared by single-file and isolated bulk scans, and timestamp preservation."""
import contextlib
import os
from pathlib import Path

import fitz

DEFAULT_MAX_FILE_SIZE_MB = 100
# Upper bound for --max-size: the Linux memory guard caps each analysis
# process at 4 GiB of address space, and the raw-byte scan maps the whole file
# into it, so larger inputs would abort with MemoryError rather than be analyzed.
MAX_FILE_SIZE_LIMIT_MB = 2048

_password = None
_max_file_size_mb = DEFAULT_MAX_FILE_SIZE_MB


def set_password(password):
    global _password
    _password = password


def get_password():
    return _password


def set_max_file_size_mb(size_mb):
    global _max_file_size_mb
    if not 1 <= size_mb <= MAX_FILE_SIZE_LIMIT_MB:
        raise ValueError(f'Maximum file size must be between 1 and {MAX_FILE_SIZE_LIMIT_MB} MB')
    _max_file_size_mb = size_mb


def get_max_file_size_mb():
    return _max_file_size_mb


def validate_pdf(path):
    """Return why `path` cannot be analyzed, or None when it is acceptable."""
    try:
        candidate = Path(path)
        if not candidate.exists():
            return f"File {path} does not exist"
        if not candidate.is_file():
            return f"{path} is not a file"
        if candidate.suffix.lower() != '.pdf':
            return f"{path} is not a PDF"
        if candidate.stat().st_size > _max_file_size_mb * 1024 * 1024:
            return (f"File {path} is too large (max {_max_file_size_mb}MB; "
                    f"raise it with --max-size)")
    except (OSError, ValueError) as exc:
        return f"Cannot validate {path}: {exc}"
    return None


def open_pdf(path):
    doc = fitz.open(path)
    try:
        if not doc.is_pdf:
            raise ValueError('Input is not a PDF document')
        # Query needs_pass only before authentication: some MuPDF versions
        # reset the decryption state when this property is read afterwards.
        doc._pdfchecker_requires_password = bool(doc.needs_pass)
        doc._pdfchecker_encrypted = doc.is_encrypted or bool((doc.metadata or {}).get('encryption'))
        if doc._pdfchecker_requires_password and not doc.authenticate(_password or ''):
            raise ValueError('PDF is locked: supply a valid password with --ask-password or --password-env')
        return doc
    except Exception:
        doc.close()
        raise


@contextlib.contextmanager
def preserved_timestamps(path):
    """Yield the file's stat result (None when unavailable) and restore its
    access and modification times afterwards, so analysis leaves no trace."""
    try:
        stats = os.stat(path)
    except (OSError, ValueError):
        stats = None
    try:
        yield stats
    finally:
        if stats is not None:
            try:
                os.utime(path, (stats.st_atime, stats.st_mtime))
            except OSError:
                pass


@contextlib.contextmanager
def document(path, doc=None):
    """Yield `doc` when the caller already opened the PDF (the caller then owns
    closing it and restoring timestamps); otherwise open `path` for the block."""
    if doc is not None:
        yield doc
        return
    with preserved_timestamps(path), open_pdf(path) as opened:
        yield opened
