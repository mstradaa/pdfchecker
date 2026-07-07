import os
from pathlib import Path
from datetime import datetime, timezone
from xhtml2pdf import pisa
from .hash_checker import calculate_file_hashes, check_virustotal as check_vt_hash
from .link_extractor import extract_links, defang_url, LinkExtractor
from .metadata_analyzer import analyze_pdf_metadata
from .javascript_detector import extract_javascript_from_pdf
from .structure_analyzer import analyze_structure
from .embedded_file_detector import detect_embedded_files
from .qr_detector import detect_qr_codes, QR_UNAVAILABLE_MESSAGE
from .risk_scorer import compute_risk_score
from .config_manager import get_api_key, ConfigError
from .utils import get_confirmation
from .report_html import build_report_html

PDFCHECKER_VERSION = "1.0"
MAX_OPERATOR_NAME_LENGTH = 100


class PDFAnalysisResult:
    def __init__(self):
        self.hashes = None
        self.links = None
        self.metadata = None
        self.javascript = None
        self.structure = None
        self.embedded = None
        self.qr = None
        self.risk = None
        self.errors = []

def analyze_pdf_once(pdf_path, validate_pdf_file=None):
    result = PDFAnalysisResult()
    original_stats = None

    try:
        original_stats = os.stat(pdf_path)
    except Exception as e:
        result.errors.append(f"Analysis error: {str(e)}")
        return result

    # Each analysis is isolated so one failure does not lose the rest of
    # the report
    try:
        result.metadata = analyze_pdf_metadata(
            pdf_path, validate_pdf_file=validate_pdf_file, file_stats=original_stats
        )
    except Exception as e:
        result.errors.append(f"Metadata analysis error: {str(e)}")

    try:
        result.hashes = calculate_file_hashes(pdf_path)
    except Exception as e:
        result.errors.append(f"Hash calculation error: {str(e)}")

    content_analyses = [
        ('links', lambda: extract_links(pdf_path)),
        ('javascript', lambda: extract_javascript_from_pdf(
            pdf_path, validate_pdf_file=validate_pdf_file)),
        ('structure', lambda: analyze_structure(pdf_path)),
        ('embedded', lambda: detect_embedded_files(pdf_path)),
        ('qr', lambda: detect_qr_codes(pdf_path)),
    ]
    try:
        for attr, analysis in content_analyses:
            try:
                setattr(result, attr, analysis())
            except Exception as e:
                result.errors.append(f"{attr} analysis error: {str(e)}")
    finally:
        if original_stats:
            try:
                os.utime(pdf_path, (original_stats.st_atime, original_stats.st_mtime))
            except Exception:
                pass

    result.risk = compute_risk_score(
        js_findings=result.javascript,
        structure_findings=result.structure,
        embedded_findings=result.embedded,
        links=result.links,
        qr_findings=result.qr
    )

    return result


def _vt_scan_date(attrs):
    last_scan_date = attrs.get("last_analysis_date")
    if last_scan_date:
        try:
            scan_datetime = datetime.fromtimestamp(last_scan_date, tz=timezone.utc)
            return scan_datetime.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            pass
    return None

# condense the VirusTotal hash lookup into template-ready data
def summarize_virustotal_file(vt_report):
    attrs = (vt_report or {}).get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values())
    if total == 0:
        return {"status": "not_found"}

    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
    detections = [
        (scanner, scan_result.get('result', 'Unknown'))
        for scanner, scan_result in attrs.get("last_analysis_results", {}).items()
        if scan_result.get("category") in ("malicious", "suspicious")
    ]
    return {
        "status": "ok",
        "positives": positives,
        "total": total,
        "detections": detections,
        "scan_date": _vt_scan_date(attrs),
    }

# condense a VirusTotal URL analysis into template-ready data
def summarize_virustotal_url(vt_result):
    if not vt_result:
        return {"status": "error"}

    attrs = vt_result.get("data", {}).get("attributes", {})
    if attrs.get("status") not in (None, "completed"):
        return {"status": "pending"}

    stats = attrs.get("stats", {})
    if sum(stats.values()) == 0:
        return {"status": "not_found"}

    return {
        "status": "ok",
        "stats": {
            "harmless": stats.get("harmless", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
        },
        "scan_date": _vt_scan_date(attrs),
    }


def _check_url_virustotal(link_checker, url):
    if url in link_checker.checked_urls:
        return {"status": "skipped",
                "message": "URL already checked in this operation."}
    if link_checker.api_calls_made >= link_checker.api_limit:
        return {"status": "skipped",
                "message": "VirusTotal API call limit reached."}
    return summarize_virustotal_url(link_checker.check_link_virustotal(url))


# Gather everything the HTML template needs, running the VirusTotal lookups
# (file hash first, then links, then QR URLs) against the shared call limit
def _collect_report_data(pdf_path, analysis_result, check_virustotal, defang,
                         operator_name, link_checker):
    vt_file = None
    if check_virustotal and analysis_result.hashes:
        sha256 = analysis_result.hashes.get("SHA-256")
        if sha256:
            if link_checker.consume_api_call():
                vt_file = summarize_virustotal_file(
                    check_vt_hash(sha256, silent=True))
            else:
                vt_file = {"status": "skipped",
                           "message": "VirusTotal API call limit reached."}

    links = []
    for link in (analysis_result.links or []):
        entry = {
            "url": link,
            "display": defang_url(link) if defang else link,
            "vt": None,
        }
        if check_virustotal:
            entry["vt"] = _check_url_virustotal(link_checker, link)
        links.append(entry)

    qr = None
    if analysis_result.qr:
        qr = dict(analysis_result.qr)
        qr_codes = []
        for qr_code in qr.get('qr_codes', []):
            entry = dict(qr_code)
            payload = entry.get('payload', '')
            is_url = entry.get('type') == 'URL'
            entry['display'] = defang_url(payload) if (is_url and defang) else payload
            entry['vt'] = None
            if check_virustotal and is_url:
                entry['vt'] = _check_url_virustotal(link_checker, payload)
            qr_codes.append(entry)
        qr['qr_codes'] = qr_codes

    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    return {
        "meta": {
            "scanned_path": str(pdf_path),
            "version": PDFCHECKER_VERSION,
            "timestamp": timestamp,
            "operator": operator_name,
            "vt_enabled": check_virustotal,
            "defang": defang,
        },
        "risk": analysis_result.risk,
        "hashes": analysis_result.hashes,
        "vt_file": vt_file,
        "links": links,
        "metadata": analysis_result.metadata,
        "javascript": analysis_result.javascript,
        "embedded": analysis_result.embedded,
        "structure": analysis_result.structure,
        "qr": qr,
        "qr_unavailable_message": QR_UNAVAILABLE_MESSAGE,
        "errors": analysis_result.errors,
    }


def create_report(pdf_path, check_virustotal=False, defang=False, operator_name=None,
                  validate_pdf_file=None, link_checker=None):
    try:
        if operator_name and len(operator_name) > MAX_OPERATOR_NAME_LENGTH:
            operator_name = operator_name[:MAX_OPERATOR_NAME_LENGTH-3] + "..."

        input_path = Path(pdf_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input PDF file not found: {pdf_path}")

        safe_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_')
        safe_stem = ''.join(c for c in input_path.stem if c in safe_chars).rstrip()
        if not safe_stem:
            safe_stem = "pdf_report"

        output_path = input_path.parent / f"{safe_stem}_report.pdf"

        counter = 1
        original_output_path = output_path
        while output_path.exists():
            output_path = original_output_path.parent / f"{safe_stem}_report_{counter}.pdf"
            counter += 1

        analysis_result = analyze_pdf_once(pdf_path, validate_pdf_file)

        # Share one extractor across the hash lookup, all links and QR URLs
        # so the API call limit is enforced; bulk mode passes its own so
        # the limit spans all files
        if check_virustotal and link_checker is None:
            link_checker = LinkExtractor()
            link_checker._initialize_api_config()

        report_data = _collect_report_data(
            pdf_path, analysis_result, check_virustotal, defang,
            operator_name, link_checker
        )
        report_html = build_report_html(report_data)

        with open(output_path, 'wb') as output_file:
            status = pisa.CreatePDF(report_html, dest=output_file)
        if status.err:
            output_path.unlink(missing_ok=True)
            raise RuntimeError("HTML to PDF conversion failed")

        return str(output_path)

    except Exception as e:
        print(f"Error generating report: {str(e)}")
        return None

# main function to generate the report
def main(pdf_path, validate_pdf_file=None):
    if validate_pdf_file and not validate_pdf_file(pdf_path):
        return

    try:
        operator_name = input("\nPlease type your name (enter to skip): ").strip()[:MAX_OPERATOR_NAME_LENGTH]
    except (EOFError, KeyboardInterrupt):
        print("\nOperation cancelled.")
        return

    # get_api_key raises when no secure keyring backend is available
    try:
        success, api_key = get_api_key()
    except ConfigError as e:
        print(f"Warning: Could not access VirusTotal API key: {e}")
        success, api_key = False, None

    check_vt = False
    defang = False

    if success and api_key:
        check_vt = get_confirmation("\nWould you like to check elements with VirusTotal?")

    defang = get_confirmation("\nWould you like to defang URLs?")

    print(f"\nGenerating report for {pdf_path}...")
    report_path = create_report(pdf_path, check_vt, defang, operator_name, validate_pdf_file=validate_pdf_file)

    if report_path:
        print(f"\nReport generated successfully: {report_path}")
        hashes = calculate_file_hashes(report_path)
        if 'SHA-256' in hashes:
            print(f"\nSHA256 of the report: {hashes['SHA-256']}")
    else:
        print("\nFailed to generate report.")

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Generate PDF analysis report')
    parser.add_argument('-r', '--report', help='Path to the PDF file to analyze')
    args = parser.parse_args()

    if not args.report:
        print("Error: Please provide a PDF file path using -r or --report")
        print("Usage: python report_generator.py -r <pdf_file>")
        sys.exit(1)

    pdf_path = args.report

    if not os.path.exists(pdf_path):
        print(f"Error: File {pdf_path} does not exist")
        sys.exit(1)

    main(pdf_path)
