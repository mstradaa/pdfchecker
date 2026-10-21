# Machine-readable output (--json): a non-interactive pipeline that reuses the
# bulk compute workers and prints a single versioned JSON document to stdout.
# No VirusTotal lookups, prompts, or file extraction happen on this path, and
# any stray analyzer prints are diverted to stderr so stdout stays pure JSON.
import contextlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__
from . import bulk_processor
from .coverage import finding_errors
from .embedded_file_detector import detect_embedded_files
from .hash_checker import calculate_file_hashes
from .javascript_detector import extract_javascript_from_pdf
from .metadata_analyzer import analyze_pdf_metadata
from .pdf_access import validate_pdf
from .pipeline import analyze_pdf_for_risk, analyze_pdf_once
from .qr_detector import detect_qr_codes
from .report_generator import _collect_report_data
from .risk_scorer import ranking_key
from .structure_analyzer import analyze_structure
from .url_discovery import discover_urls
from .utils import apply_memory_guard

SCHEMA_VERSION = 1


def tool_info():
    return {"name": "pdfchecker", "version": __version__}


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


# Workers must be module-level functions so they can be pickled into the
# worker processes

def _links_worker(pdf_path):
    findings = discover_urls(pdf_path)
    if findings['errors']:
        raise ValueError('; '.join(findings['errors']))
    links = [entry['url'] for entry in findings['urls']]
    return {"count": len(links), "links": links}


def _report_data_worker(pdf_path):
    return _collect_report_data(pdf_path, analyze_pdf_once(pdf_path),
                                defang=False, operator_name=None)


# Process-pool children inherit fd 1, so the parent's redirect_stdout cannot
# catch their prints; each child rebinds stdout itself
def _json_child_init():
    sys.stdout = sys.stderr
    apply_memory_guard()


# argparse dest -> (per-file worker, run in processes vs threads); the
# document's mode is the option name, e.g. 'risk-score' for risk_score
_COLLECTORS = {
    'hash_checker': (calculate_file_hashes, False),
    'links': (_links_worker, True),
    'metadata': (analyze_pdf_metadata, True),
    'javascript': (extract_javascript_from_pdf, True),
    'embedded_files': (detect_embedded_files, True),
    'structure': (analyze_structure, True),
    'qr_codes': (detect_qr_codes, True),
    'risk_score': (analyze_pdf_for_risk, True),
    'report': (_report_data_worker, True),
}


def _envelope(mode, target, target_type):
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": tool_info(),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mode": mode,
        "target": str(target),
        "target_type": target_type,
        "ok": True,
    }


def _emit(doc):
    print(json.dumps(sanitize(doc), indent=2, default=str))


def _result_error(result):
    if result is None:
        return "Analysis failed to produce a result"
    errors = finding_errors(result)
    return "; ".join(map(str, errors)) if errors else None


def _run_json_single(mode, worker, target):
    doc = _envelope(mode, target, "file")
    error = validate_pdf(target)
    result = None
    if error is None:
        try:
            with contextlib.redirect_stdout(sys.stderr):
                result = worker(target)
        except Exception as e:
            error = str(e) or type(e).__name__
        else:
            error = _result_error(result)
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
        if ok:
            result_error = _result_error(payload)
            if result_error:
                ok, payload = False, result_error
        entries.append({
            "path": path,
            "ok": ok,
            "result": payload if ok else None,
            "error": None if ok else {"message": str(payload)},
        })

    if mode == 'risk-score':
        # Match the human ranking: most dangerous first, failures last
        entries.sort(key=lambda e: ranking_key(e["result"] if e["ok"] else None))

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
    worker, use_processes = _COLLECTORS[arg_name]
    mode = arg_name.replace('_', '-')
    if Path(target).is_dir():
        return _run_json_bulk(mode, worker, use_processes, target,
                              exclude_reports=(arg_name == 'report'))
    return _run_json_single(mode, worker, target)
