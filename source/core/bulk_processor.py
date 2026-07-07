# Bulk (folder) mode: run the selected analysis on every PDF in a directory.
# Interactive questions are asked once up front, per-file work is parallelized,
# and VirusTotal calls share a single API budget across all files.
import os
import re
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from functools import partial
from pathlib import Path

from .config_manager import get_api_key, get_api_limit, ConfigError
from .embedded_file_detector import detect_embedded_files, print_embedded_findings
from .hash_checker import calculate_file_hashes, check_virustotal, _print_virustotal_results
from .javascript_detector import extract_javascript_from_pdf, print_javascript_findings
from .link_extractor import LinkExtractor, defang_url, extract_links, remove_protocol
from .metadata_analyzer import analyze_pdf_metadata, print_metadata
from .qr_detector import detect_qr_codes, print_qr_findings, QR_SUPPORT, QR_UNAVAILABLE_MESSAGE
from .report_generator import create_report, MAX_OPERATOR_NAME_LENGTH
from .risk_scorer import compute_risk_score
from .structure_analyzer import analyze_structure, print_structure_findings
from .utils import get_confirmation

MAX_FILE_SIZE_MB = 100
# fitz keeps whole documents in memory, so cap process workers to bound peak usage
MAX_PROCESS_WORKERS = 8
MAX_HASH_THREADS = 16

# Matches report files produced by previous runs (e.g. invoice_report.pdf,
# invoice_report_2.pdf) so bulk report mode does not report on its own output
GENERATED_REPORT_PATTERN = re.compile(r'_report(_\d+)?$')


def discover_pdfs(folder_path, max_file_size_mb=MAX_FILE_SIZE_MB, exclude_reports=False):
    valid = []
    skipped = []
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
                skipped.append((entry.name, f"larger than {max_file_size_mb}MB"))
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

# Workers must be module-level so ProcessPoolExecutor can pickle them

def _hash_worker(pdf_path):
    return calculate_file_hashes(pdf_path)


def _links_worker(pdf_path):
    return extract_links(pdf_path)


def _metadata_worker(pdf_path):
    try:
        original_stats = os.stat(pdf_path)
    except OSError:
        original_stats = None

    metadata = analyze_pdf_metadata(pdf_path, file_stats=original_stats)

    if original_stats:
        try:
            os.utime(pdf_path, (original_stats.st_atime, original_stats.st_mtime))
        except OSError:
            pass

    # fitz objects (e.g. page rects) are not reliably picklable across processes
    if metadata and metadata.get("page_info"):
        metadata["page_info"] = {k: str(v) for k, v in metadata["page_info"].items()}
    return metadata


def _javascript_worker(pdf_path):
    return extract_javascript_from_pdf(pdf_path)


def _structure_worker(pdf_path):
    return analyze_structure(pdf_path)


def _embedded_worker(pdf_path):
    return detect_embedded_files(pdf_path)


def _qr_worker(pdf_path):
    return detect_qr_codes(pdf_path)


def _risk_worker(pdf_path):
    return compute_risk_score(
        js_findings=extract_javascript_from_pdf(pdf_path),
        structure_findings=analyze_structure(pdf_path),
        embedded_findings=detect_embedded_files(pdf_path),
        links=extract_links(pdf_path),
        qr_findings=detect_qr_codes(pdf_path)
    )


def _report_worker(pdf_path, defang, operator_name):
    report_path = create_report(pdf_path, check_virustotal=False, defang=defang,
                                operator_name=operator_name)
    if not report_path:
        raise RuntimeError("report generation failed")
    return report_path


# Run worker over all files; returns {path: (ok, result_or_error_message)}.
# Threads suit hashing (hashlib/file IO release the GIL); PyMuPDF is not
# thread-safe, so fitz-based workers run in separate processes instead.
def _run_parallel(files, worker, use_processes):
    if len(files) == 1:
        try:
            return {files[0]: (True, worker(files[0]))}
        except Exception as e:
            return {files[0]: (False, str(e))}

    if use_processes:
        executor_cls = ProcessPoolExecutor
        max_workers = min(len(files), os.cpu_count() or 2, MAX_PROCESS_WORKERS)
    else:
        executor_cls = ThreadPoolExecutor
        max_workers = min(len(files), MAX_HASH_THREADS)

    results = {}
    total = len(files)
    with executor_cls(max_workers=max_workers) as pool:
        futures = {pool.submit(worker, path): path for path in files}
        for done, future in enumerate(as_completed(futures), 1):
            path = futures[future]
            try:
                results[path] = (True, future.result())
                status = "done"
            except Exception as e:
                results[path] = (False, str(e))
                status = f"failed ({e})"
            print(f"  [{done}/{total}] {Path(path).name}: {status}")
    return results


# ---------------------------------------------------------------------------
# Bulk operations
# ---------------------------------------------------------------------------

def _get_vt_session():
    try:
        success, api_key = get_api_key()
    except ConfigError as e:
        print(f"Warning: Could not access VirusTotal API key: {e}")
        return None, 0

    if not success or not api_key:
        return None, 0

    limit_success, api_limit = get_api_limit()
    if not limit_success:
        print("Warning: Could not retrieve API limit, using default limit.")
    return api_key, api_limit


def bulk_hash_check(files):
    api_key, api_limit = _get_vt_session()
    check_vt = False
    if api_key:
        check_vt = get_confirmation("\nWould you like to check these files with VirusTotal?")
    else:
        print("\nVirusTotal API key not found. Hashes will be calculated without VirusTotal checks.")

    print(f"\nCalculating hashes for {len(files)} files...")
    results = _run_parallel(files, _hash_worker, use_processes=False)

    vt_calls = 0
    for pdf_path in files:
        ok, payload = results[pdf_path]
        print(f"\n=== {Path(pdf_path).name} ===")
        if not ok:
            print(f"Error: {payload}")
            continue

        for hash_type, hash_value in payload.items():
            print(f"{hash_type}: {hash_value}")

        if check_vt:
            if vt_calls >= api_limit:
                print("VirusTotal check skipped: API call limit reached.")
                continue
            vt_calls += 1
            result = check_virustotal(payload['SHA-256'], silent=True)
            if result:
                stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                _print_virustotal_results(stats)
            else:
                print("VirusTotal: hash not found or request failed.")

    if check_vt:
        print(f"\nTotal VirusTotal API calls made: {vt_calls}")


def bulk_link_extraction(files):
    defanged = get_confirmation("Do you want to display links in defanged format?")

    # One extractor for the whole batch: the API limit is enforced globally and
    # a URL appearing in several PDFs is only checked once
    extractor = LinkExtractor()
    check_vt = False
    if extractor._initialize_api_config() and extractor.api_key:
        check_vt = get_confirmation("\nWould you like to check the extracted links with VirusTotal?")
    else:
        print("\nVirusTotal API key not found. Links will be listed without checking.")

    print(f"\nExtracting links from {len(files)} files...")
    results = _run_parallel(files, _links_worker, use_processes=True)

    checked_count = 0
    skipped_count = 0
    duplicate_count = 0
    try:
        for pdf_path in files:
            ok, links = results[pdf_path]
            print(f"\n=== {Path(pdf_path).name} ===")
            if not ok:
                print(f"Error: {links}")
                continue
            if not links:
                print("No links found.")
                continue

            print(f"{len(links)} unique links found.")
            for i, link in enumerate(links, 1):
                display_link = defang_url(link) if defanged else remove_protocol(link)
                print(f"{i}. {display_link}")

                if not check_vt:
                    continue

                if link in extractor.checked_urls:
                    print("   URL already checked in this bulk operation.")
                    duplicate_count += 1
                    continue

                if extractor.api_calls_made >= extractor.api_limit:
                    print("   Skipped due to API limit.")
                    skipped_count += 1
                    continue

                print("   Checking with VirusTotal...")
                result = extractor.check_link_virustotal(link)
                if result:
                    checked_count += 1
                    _print_url_vt_result(result)
                else:
                    print("   VirusTotal check failed. Please check your API key or try again later.")

        if check_vt:
            print(f"\nAPI Call Summary:")
            print(f"- Links checked with VirusTotal: {checked_count}")
            if duplicate_count > 0:
                print(f"- Duplicate links skipped: {duplicate_count}")
            if skipped_count > 0:
                print(f"- Links skipped due to API limit: {skipped_count}")
            print(f"- Total API calls made: {extractor.api_calls_made}")
    finally:
        extractor.reset()


def _print_url_vt_result(result):
    attrs = result.get("data", {}).get("attributes", {})
    if attrs.get("status") not in (None, "completed"):
        print("   VirusTotal analysis still pending; try again later for results.")
        return
    stats = attrs.get("stats", {})
    print("   VirusTotal Results:")
    print(f"   - Harmless: {stats.get('harmless', 0)}")
    print(f"   - Malicious: {stats.get('malicious', 0)}")
    print(f"   - Suspicious: {stats.get('suspicious', 0)}")
    print(f"   - Undetected: {stats.get('undetected', 0)}")


def bulk_metadata_analysis(files):
    print(f"\nAnalyzing metadata for {len(files)} files...")
    results = _run_parallel(files, _metadata_worker, use_processes=True)

    for pdf_path in files:
        ok, metadata = results[pdf_path]
        print(f"\n=== {Path(pdf_path).name} ===")
        if not ok:
            print(f"Error: {metadata}")
        elif not metadata:
            print("Error analyzing PDF metadata.")
        else:
            print_metadata(metadata)


def bulk_javascript_analysis(files):
    print(f"\nAnalyzing JavaScript in {len(files)} files...")
    results = _run_parallel(files, _javascript_worker, use_processes=True)

    for pdf_path in files:
        ok, findings = results[pdf_path]
        print(f"\n=== {Path(pdf_path).name} ===")
        if not ok:
            print(f"Error: {findings}")
        else:
            print_javascript_findings(findings)


def bulk_structure_analysis(files):
    print(f"\nAnalyzing structure of {len(files)} files...")
    results = _run_parallel(files, _structure_worker, use_processes=True)

    for pdf_path in files:
        ok, findings = results[pdf_path]
        print(f"\n=== {Path(pdf_path).name} ===")
        if not ok:
            print(f"Error: {findings}")
        else:
            print_structure_findings(findings)


def bulk_embedded_analysis(files):
    print(f"\nDetecting embedded files in {len(files)} files...")
    print("Note: extraction to disk is available in single-file mode only.")
    results = _run_parallel(files, _embedded_worker, use_processes=True)

    for pdf_path in files:
        ok, findings = results[pdf_path]
        print(f"\n=== {Path(pdf_path).name} ===")
        if not ok:
            print(f"Error: {findings}")
        else:
            print_embedded_findings(findings)


def bulk_qr_analysis(files):
    if not QR_SUPPORT:
        print(f"\n{QR_UNAVAILABLE_MESSAGE}")
        return

    defanged = get_confirmation("Do you want to display QR URLs in defanged format?")

    # Same shared-budget model as bulk link extraction: one extractor for the
    # whole batch, and a URL appearing in several PDFs is only checked once
    extractor = LinkExtractor()
    check_vt = False
    if extractor._initialize_api_config() and extractor.api_key:
        check_vt = get_confirmation("\nWould you like to check decoded QR URLs with VirusTotal?")
    else:
        print("\nVirusTotal API key not found. QR payloads will be listed without checking.")

    print(f"\nScanning {len(files)} files for QR codes...")
    results = _run_parallel(files, _qr_worker, use_processes=True)

    try:
        for pdf_path in files:
            ok, findings = results[pdf_path]
            print(f"\n=== {Path(pdf_path).name} ===")
            if not ok:
                print(f"Error: {findings}")
                continue

            print_qr_findings(findings, defanged=defanged, defang_url=defang_url)

            if not check_vt or not findings:
                continue
            for qr in findings.get("qr_codes", []):
                if qr["type"] != "URL":
                    continue
                url = qr["payload"]
                display_url = defang_url(url) if defanged else url
                if url in extractor.checked_urls:
                    print(f"\n{display_url}: already checked in this bulk operation.")
                    continue
                if extractor.api_calls_made >= extractor.api_limit:
                    print(f"\n{display_url}: skipped due to API limit.")
                    continue
                print(f"\nChecking QR URL with VirusTotal: {display_url}")
                result = extractor.check_link_virustotal(url)
                if result:
                    _print_url_vt_result(result)
                else:
                    print("   VirusTotal check failed. Please check your API key or try again later.")

        if check_vt:
            print(f"\nTotal API calls made: {extractor.api_calls_made}")
    finally:
        extractor.reset()


def bulk_risk_scoring(files):
    print(f"\nComputing risk scores for {len(files)} files...")
    results = _run_parallel(files, _risk_worker, use_processes=True)

    # Rank by score so the riskiest files surface first
    scored = []
    failed = []
    for pdf_path in files:
        ok, assessment = results[pdf_path]
        if ok and assessment:
            scored.append((pdf_path, assessment))
        else:
            failed.append((pdf_path, assessment))
    scored.sort(key=lambda item: item[1]["score"], reverse=True)

    print("\n=== Risk Ranking ===")
    for pdf_path, assessment in scored:
        print(f"\n[{assessment['score']:3d}/{assessment['max_score']}] "
              f"{assessment['level'].upper():8s} {Path(pdf_path).name}")
        for adjustment in assessment.get("adjustments", []):
            print(f"      NOTE: {adjustment}")
        top_reasons = [reason for category in assessment["categories"].values()
                       for reason in category["reasons"]]
        for reason in top_reasons[:3]:
            print(f"      - {reason}")
        if len(top_reasons) > 3:
            print(f"      ... and {len(top_reasons) - 3} more indicator(s)")

    for pdf_path, error in failed:
        print(f"\n[ERROR] {Path(pdf_path).name}: {error}")


def bulk_report_generation(files):
    try:
        operator_name = input("\nPlease type your name (enter to skip): ").strip()[:MAX_OPERATOR_NAME_LENGTH]
    except (EOFError, KeyboardInterrupt):
        print("\nOperation cancelled.")
        return

    api_key, _ = _get_vt_session()
    check_vt = False
    if api_key:
        check_vt = get_confirmation("\nWould you like to check elements with VirusTotal?")

    defang = get_confirmation("\nWould you like to defang URLs?")

    print(f"\nGenerating reports for {len(files)} files...")
    if check_vt:
        # VirusTotal calls share one API budget and are rate limited, so
        # reports run sequentially with a single shared link checker
        link_checker = LinkExtractor()
        link_checker._initialize_api_config()
        results = {}
        for i, pdf_path in enumerate(files, 1):
            print(f"  [{i}/{len(files)}] {Path(pdf_path).name}...")
            report_path = create_report(pdf_path, check_virustotal=True, defang=defang,
                                        operator_name=operator_name, link_checker=link_checker)
            results[pdf_path] = (report_path is not None, report_path or "report generation failed")
    else:
        worker = partial(_report_worker, defang=defang, operator_name=operator_name)
        results = _run_parallel(files, worker, use_processes=True)

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
