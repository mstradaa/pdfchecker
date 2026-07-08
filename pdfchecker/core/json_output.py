# Machine-readable output (--json): a non-interactive pipeline that reuses the
# bulk compute workers and prints a single versioned JSON document to stdout.
# No VirusTotal lookups, prompts, or file extraction happen on this path, and
# any stray analyzer prints are diverted to stderr so stdout stays pure JSON.
import contextlib
import json
import sys
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as _package_version
from pathlib import Path

from . import bulk_processor, report_generator
from .utils import apply_memory_guard

SCHEMA_VERSION = 1

MAX_FILE_SIZE_MB = bulk_processor.MAX_FILE_SIZE_MB


def _tool_info():
    try:
        version = _package_version("pdfchecker")
    except PackageNotFoundError:
        version = report_generator.PDFCHECKER_VERSION
    return {"name": "pdfchecker", "version": version}


# Everything the analyzers return is already JSON types except fitz objects
# (e.g. page rects in metadata) and raw bytes, which must never reach stdout
def sanitize(obj):
    if isinstance(obj, dict):
        return {str(key): sanitize(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [sanitize(value) for value in obj]
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, bytes):
        return f"<{len(obj)} bytes omitted>"
    return str(obj)


# Same checks as main.validate_pdf_file, but returns the error instead of
# printing it so it can go into the JSON envelope
def _validate_pdf(file_path):
    try:
        path = Path(file_path)
        if not path.exists():
            return f"File {file_path} does not exist"
        if not path.is_file():
            return f"{file_path} is not a file"
        if path.suffix.lower() != '.pdf':
            return f"{file_path} is not a PDF"
        if path.stat().st_size > (MAX_FILE_SIZE_MB * 1024 * 1024):
            return f"File {file_path} is too large (max {MAX_FILE_SIZE_MB}MB)"
        return None
    except Exception as e:
        return f"Error validating file {file_path}: {e}"


# Workers must be module-level so ProcessPoolExecutor can pickle them

def _links_json_worker(pdf_path):
    links = bulk_processor._links_worker(pdf_path)
    return {"count": len(links), "links": links}


def _report_data_worker(pdf_path):
    result = report_generator.analyze_pdf_once(pdf_path)
    return report_generator._collect_report_data(
        pdf_path, result, check_virustotal=False, defang=False,
        operator_name=None, link_checker=None)


# Process-pool children inherit fd 1, so the parent's redirect_stdout cannot
# catch their prints; each child rebinds stdout itself
def _json_child_init():
    sys.stdout = sys.stderr
    apply_memory_guard()


# argparse dest -> (mode name, per-file worker, run in processes vs threads)
_COLLECTORS = {
    'hash_checker': ('hash-checker', bulk_processor._hash_worker, False),
    'links': ('links', _links_json_worker, True),
    'metadata': ('metadata', bulk_processor._metadata_worker, True),
    'javascript': ('javascript', bulk_processor._javascript_worker, True),
    'embedded_files': ('embedded-files', bulk_processor._embedded_worker, True),
    'structure': ('structure', bulk_processor._structure_worker, True),
    'qr_codes': ('qr-codes', bulk_processor._qr_worker, True),
    'risk_score': ('risk-score', bulk_processor._risk_worker, True),
    'report': ('report', _report_data_worker, True),
}


def _envelope(mode, target, target_type):
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": _tool_info(),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mode": mode,
        "target": str(target),
        "target_type": target_type,
        "ok": True,
    }


def _emit(doc):
    print(json.dumps(sanitize(doc), indent=2, default=str))


def _run_json_single(mode, worker, target):
    doc = _envelope(mode, target, "file")
    error = _validate_pdf(target)
    result = None
    if error is None:
        try:
            with contextlib.redirect_stdout(sys.stderr):
                result = worker(target)
        except Exception as e:
            error = str(e) or type(e).__name__
        else:
            if result is None:
                error = "Analysis failed to produce a result"
    doc["ok"] = error is None
    doc["result"] = result if error is None else None
    doc["error"] = None if error is None else {"message": error}
    _emit(doc)
    return 0 if error is None else 1


def _run_json_bulk(mode, worker, use_processes, folder, exclude_reports):
    doc = _envelope(mode, folder, "directory")
    try:
        files, skipped = bulk_processor.discover_pdfs(
            folder, exclude_reports=exclude_reports)
    except OSError as e:
        doc["ok"] = False
        doc["error"] = {"message": f"Error reading folder {folder}: {e}"}
        _emit(doc)
        return 1

    results = {}
    if files:
        with contextlib.redirect_stdout(sys.stderr):
            results = bulk_processor._run_parallel(
                files, worker, use_processes,
                process_initializer=_json_child_init)

    entries = []
    for path in files:
        ok, payload = results.get(path, (False, "no result"))
        if ok and payload is None:
            ok, payload = False, "Analysis failed to produce a result"
        entries.append({
            "path": path,
            "ok": ok,
            "result": payload if ok else None,
            "error": None if ok else {"message": str(payload)},
        })

    if mode == 'risk-score':
        # Match the human ranking: most dangerous first, failures last
        entries.sort(key=lambda e: e["result"]["score"] if e["ok"] else -1,
                     reverse=True)

    doc["summary"] = {
        "total": len(files),
        "succeeded": sum(1 for entry in entries if entry["ok"]),
        "failed": sum(1 for entry in entries if not entry["ok"]),
        "skipped": [{"name": name, "reason": reason} for name, reason in skipped],
    }
    doc["files"] = entries
    doc["error"] = None
    _emit(doc)
    return 0


# Entry point from main.handle_pdf_analysis; returns the process exit code
def run_json_analysis(arg_name, target):
    mode, worker, use_processes = _COLLECTORS[arg_name]
    if Path(target).is_dir():
        return _run_json_bulk(mode, worker, use_processes, target,
                              exclude_reports=(arg_name == 'report'))
    return _run_json_single(mode, worker, target)
