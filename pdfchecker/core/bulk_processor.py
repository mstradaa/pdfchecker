# Bulk (folder) mode: run the selected analysis on every PDF in a directory.
# Interactive questions are asked once up front, per-file work is parallelized,
# and each reputation service shares a single API budget across all files.
import multiprocessing
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from pathlib import Path

from .embedded_file_detector import detect_embedded_files, print_embedded_findings
from .hash_checker import calculate_file_hashes
from .javascript_detector import extract_javascript_from_pdf, print_javascript_findings
from .link_extractor import check_qr_urls, defang_url, print_link_list, print_link_summary
from .metadata_analyzer import analyze_pdf_metadata, print_metadata
from .pdf_access import (get_max_file_size_mb, get_password, set_max_file_size_mb,
                         set_password)
from .pipeline import analyze_pdf_for_risk
from .qr_detector import detect_qr_codes, print_qr_findings, qr_supported, QR_UNAVAILABLE_MESSAGE
from .report_generator import ask_operator_name, create_report
from .risk_scorer import ranking_key, risk_reasons
from .structure_analyzer import analyze_structure, print_structure_findings
from .threat_intel import check_file, print_call_summary, selected_providers
from .url_discovery import discover_urls
from .urlhaus import URLhausClient
from .utils import get_confirmation, apply_memory_guard
from .virustotal import VirusTotalClient

# fitz keeps whole documents in memory, so cap process workers to bound peak usage
MAX_PROCESS_WORKERS = 8
MAX_HASH_THREADS = 16

# Matches report files produced by previous runs (e.g. invoice_report.pdf,
# invoice_report_2.pdf) so bulk report mode does not report on its own output
GENERATED_REPORT_PATTERN = re.compile(r'_report(_\d+)?$')


def discover_pdfs(folder_path, max_file_size_mb=None, exclude_reports=False):
    valid = []
    skipped = []
    # Read at call time so a --max-size override applies
    if max_file_size_mb is None:
        max_file_size_mb = get_max_file_size_mb()
    max_bytes = max_file_size_mb * 1024 * 1024

    with os.scandir(folder_path) as entries:
        for entry in entries:
            if not entry.name.lower().endswith('.pdf'):
                continue
            if not entry.is_file(follow_symlinks=False):
                skipped.append((entry.name, "not a regular file"))
                continue
            if exclude_reports and GENERATED_REPORT_PATTERN.search(Path(entry.name).stem):
                skipped.append((entry.name, "previously generated report"))
                continue
            if entry.stat(follow_symlinks=False).st_size > max_bytes:
                skipped.append((entry.name, f"larger than {max_file_size_mb}MB "
                                            "(raise it with --max-size)"))
                continue
            valid.append(entry.path)

    valid.sort()
    return valid, skipped


def run_bulk_analysis(folder_path, operation_label, bulk_handler, exclude_reports=False):
    try:
        files, skipped = discover_pdfs(folder_path, exclude_reports=exclude_reports)
    except OSError as e:
        print(f"Error reading folder {folder_path}: {e}")
        return

    for name, reason in skipped:
        print(f"Skipping {name}: {reason}")

    if not files:
        print(f"No PDF files found in '{folder_path}'.")
        return

    print(f"\nBulk mode: {len(files)} PDF file(s) found in '{folder_path}'.")
    if not get_confirmation(f"You are about to run {operation_label} on {len(files)} PDF files. Continue?"):
        print("Bulk operation aborted.")
        return

    bulk_handler(files)


# ---------------------------------------------------------------------------
# Parallel execution
# ---------------------------------------------------------------------------

# Workers must be module-level functions so they can be pickled into the
# worker processes

def _report_worker(pdf_path, defang, operator_name, providers=(), include_logo=True):
    report_path = create_report(pdf_path, defang, operator_name, providers, include_logo)
    if not report_path:
        raise RuntimeError("report generation failed")
    return report_path


# Run worker over all files; returns {path: (ok, result_or_error_message)}.
# Threads suit hashing (hashlib/file IO release the GIL); PyMuPDF is not
# thread-safe, so fitz-based workers run in separate processes instead.
def _isolated_child(connection, worker, path, initializer, password, max_file_size_mb):
    # Children start from the forkserver's or a fresh interpreter's module
    # state, so the parent's settings are passed in explicitly
    set_password(password)
    set_max_file_size_mb(max_file_size_mb)
    try:
        # Keep machine-readable stdout clean in spawned children too.
        sys.stdout = sys.stderr
        if initializer:
            initializer()
        connection.send((True, worker(path)))
    except Exception as exc:
        connection.send((False, str(exc) or type(exc).__name__))
    finally:
        connection.close()
        set_password(None)


_process_context = None
_process_context_lock = threading.Lock()


# Every file gets a fresh process. A forkserver forks it from a server that
# has the analyzers imported already, about 3x cheaper than starting a new
# interpreter; spawn remains the fallback where the platform has no
# forkserver or forbids its Unix socket (Windows, some sandboxes).
def _worker_context():
    global _process_context
    with _process_context_lock:
        if _process_context is None:
            _process_context = multiprocessing.get_context('spawn')
            if 'forkserver' in multiprocessing.get_all_start_methods():
                # Imported here: the module only exists for POSIX start methods
                from multiprocessing import forkserver
                context = multiprocessing.get_context('forkserver')
                context.set_forkserver_preload([__name__])
                try:
                    forkserver.ensure_running()
                except Exception:
                    pass
                else:
                    _process_context = context
        return _process_context


def _isolated_call(worker, path, initializer):
    context = _worker_context()
    receiving, sending = context.Pipe(duplex=False)
    process = context.Process(target=_isolated_child,
                              args=(sending, worker, path, initializer, get_password(),
                                    get_max_file_size_mb()))
    try:
        process.start()
        sending.close()
        try:
            return receiving.recv()
        except EOFError:
            process.join()
            return False, f"Analysis worker exited without a result (exit code {process.exitcode})"
    finally:
        receiving.close()
        sending.close()
        if process.pid is not None:
            process.join()
            process.close()


def _run_parallel(files, worker, use_processes, process_initializer=apply_memory_guard,
                  max_workers=None):
    if not files:
        return {}
    if max_workers is None:
        max_workers = (min(len(files), os.cpu_count() or 2, MAX_PROCESS_WORKERS) if use_processes
                       else min(len(files), MAX_HASH_THREADS))
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        if use_processes:
            futures = {pool.submit(_isolated_call, worker, path, process_initializer): path
                       for path in files}
        else:
            futures = {pool.submit(worker, path): path for path in files}
        for done, future in enumerate(as_completed(futures), 1):
            path = futures[future]
            try:
                results[path] = future.result() if use_processes else (True, future.result())
            except Exception as exc:
                results[path] = False, str(exc)
            status = "done" if results[path][0] else f"failed ({results[path][1]})"
            print(f"  [{done}/{len(files)}] {Path(path).name}: {status}")
    return results


# ---------------------------------------------------------------------------
# Bulk operations
# ---------------------------------------------------------------------------

# Print each file's result in folder order, or its error
def _print_results(files, results, printer):
    for pdf_path in files:
        ok, payload = results[pdf_path]
        print(f"\n=== {Path(pdf_path).name} ===")
        if ok:
            printer(payload)
        else:
            print(f"Error: {payload}")


def _analyze_and_print(files, description, worker, printer):
    print(f"\n{description} {len(files)} files...")
    _print_results(files, _run_parallel(files, worker, use_processes=True), printer)


def bulk_hash_check(files):
    with selected_providers("these files", VirusTotalClient(), URLhausClient()) as providers:
        print(f"\nCalculating hashes for {len(files)} files...")
        results = _run_parallel(files, calculate_file_hashes, use_processes=False)

        def print_hashes(hashes):
            for hash_type, hash_value in hashes.items():
                print(f"{hash_type}: {hash_value}")
            check_file(providers, hashes['SHA-256'])

        _print_results(files, results, print_hashes)
        print_call_summary(providers)


def bulk_link_extraction(files):
    defanged = get_confirmation("Do you want to display links in defanged format?")

    # One client per service for the whole batch: the API limit is enforced
    # globally and a URL appearing in several PDFs is only checked once
    with selected_providers("the extracted links", VirusTotalClient(), URLhausClient()) as providers:
        print(f"\nExtracting links from {len(files)} files...")
        results = _run_parallel(files, discover_urls, use_processes=True)

        def print_links(findings):
            print_link_list(print_link_summary(findings), defanged, providers)

        _print_results(files, results, print_links)
        print_call_summary(providers)


def bulk_metadata_analysis(files):
    _analyze_and_print(files, "Analyzing metadata for", analyze_pdf_metadata, print_metadata)


def bulk_javascript_analysis(files):
    _analyze_and_print(files, "Analyzing JavaScript in", extract_javascript_from_pdf,
                       print_javascript_findings)


def bulk_structure_analysis(files):
    _analyze_and_print(files, "Analyzing structure of", analyze_structure,
                       print_structure_findings)


def bulk_embedded_analysis(files):
    _analyze_and_print(files, "Detecting embedded files in", detect_embedded_files,
                       print_embedded_findings)
    print("\nNote: extraction to disk is available in single-file mode only.")


def bulk_qr_analysis(files):
    if not qr_supported():
        print(f"\n{QR_UNAVAILABLE_MESSAGE}")
        return

    defanged = get_confirmation("Do you want to display QR URLs in defanged format?")

    # Same shared-budget model as bulk link extraction
    with selected_providers("decoded QR URLs", VirusTotalClient(), URLhausClient()) as providers:
        print(f"\nScanning {len(files)} files for QR codes...")
        results = _run_parallel(files, detect_qr_codes, use_processes=True)

        def print_qr(findings):
            print_qr_findings(findings, defanged=defanged, defang_url=defang_url)
            check_qr_urls(findings, defanged, providers)

        _print_results(files, results, print_qr)
        print_call_summary(providers)


def bulk_risk_scoring(files):
    print(f"\nComputing risk scores for {len(files)} files...")
    results = _run_parallel(files, analyze_pdf_for_risk, use_processes=True)

    # Rank by score so the riskiest files surface first
    scored = sorted(((path, results[path][1]) for path in files if all(results[path])),
                    key=lambda item: ranking_key(item[1]))

    print("\n=== Risk Ranking ===")
    for pdf_path, assessment in scored:
        print(f"\n[{assessment['score']:3d}/{assessment['max_score']}] "
              f"{assessment['level'].upper():8s} {Path(pdf_path).name}")
        for adjustment in assessment.get("adjustments", []):
            print(f"      NOTE: {adjustment}")
        reasons = risk_reasons(assessment)
        for reason in reasons[:3]:
            print(f"      - {reason}")
        if len(reasons) > 3:
            print(f"      ... and {len(reasons) - 3} more indicator(s)")

    for pdf_path in files:
        if not all(results[pdf_path]):
            print(f"\n[ERROR] {Path(pdf_path).name}: {results[pdf_path][1]}")


def bulk_report_generation(files):
    operator_name = ask_operator_name()
    if operator_name is None:
        return

    with selected_providers("elements", VirusTotalClient(), URLhausClient()) as providers:
        defang = get_confirmation("\nWould you like to defang URLs?")

        include_logo = get_confirmation("\nWould you like to include the logo in the reports?")

        print(f"\nGenerating reports for {len(files)} files...")
        worker = partial(_report_worker, defang=defang, operator_name=operator_name,
                         providers=providers, include_logo=include_logo)
        # Enrichment calls share per-service budgets across the batch, so those
        # reports run one at a time in this process with the shared clients.
        results = _run_parallel(files, worker, use_processes=not providers,
                                max_workers=1 if providers else None)

    generated = 0
    print()
    for pdf_path in files:
        ok, payload = results[pdf_path]
        if ok:
            generated += 1
            print(f"Report generated: {payload}")
        else:
            print(f"Failed for {Path(pdf_path).name}: {payload}")

    print(f"\n{generated}/{len(files)} reports generated successfully.")
