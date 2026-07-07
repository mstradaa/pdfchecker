import os
from pathlib import Path
import fitz
from datetime import datetime, timezone
from .hash_checker import calculate_file_hashes, check_virustotal as check_vt_hash
from .link_extractor import extract_links, defang_url, LinkExtractor
from .metadata_analyzer import analyze_pdf_metadata
from .javascript_detector import extract_javascript_from_pdf
from .structure_analyzer import analyze_structure
from .embedded_file_detector import detect_embedded_files
from .qr_detector import detect_qr_codes, QR_UNAVAILABLE_MESSAGE
from .risk_scorer import compute_risk_score
from .config_manager import get_api_key, get_api_limit, ConfigError
from .utils import get_confirmation

PDFCHECKER_VERSION = "1.0"
PAGE_HEIGHT = 842
PAGE_MARGIN = 50
MAX_TEXT_LENGTH = 200
MAX_LINES_PER_SECTION = 5
MAX_OPERATOR_NAME_LENGTH = 100

CHAR_REPLACEMENTS = str.maketrans({
    '\n': ' ', '\r': ' ', '\t': ' ', '\x00': '', '\x01': '', '\x02': '', '\x03': '',
    '\x04': '', '\x05': '', '\x06': '', '\x07': '', '\x08': '', '\x0b': '', '\x0c': '',
    '\x0e': '', '\x0f': '', '\u2019': "'", '\u201c': '"', '\u201d': '"', '\u2013': '-', '\u2014': '-'
})



def check_page_break(y, page, doc, margin=PAGE_MARGIN, page_height=PAGE_HEIGHT):
    if y > (page_height - margin):
        page = doc.new_page()
        y = 50
    return y, page

def _wrap_text_for_pdf(text, max_length=80):
    if not text:
        return [""]
    
    text = str(text).translate(CHAR_REPLACEMENTS)
    
    if len(text) <= max_length:
        return [text]
    
    words = text.split()
    if not words:
        return [""]
    
    lines = []
    current_line = words[0]
    
    for word in words[1:]:
        if len(current_line) + len(word) + 1 <= max_length:
            current_line += " " + word
        else:
            lines.append(current_line)
            if len(word) > max_length:
                current_line = word[:max_length-3] + "..."
            else:
                current_line = word
    
    if current_line:
        lines.append(current_line)
    
    return lines

# remove control characters and cut long text
def _clean_text_for_pdf(text):
    if not text:
        return ""
    
    text = str(text).translate(CHAR_REPLACEMENTS)
    
    text = ''.join(char for char in text if ord(char) >= 32)
    
    if len(text) > MAX_TEXT_LENGTH:
        text = text[:MAX_TEXT_LENGTH-3] + "..."
    
    return text

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

# insert one logical line, wrapped and page-break safe; returns updated (y, page)
def _insert_wrapped(page, doc, y, text, x=50, fontsize=10, step=15, max_length=80):
    for line in _wrap_text_for_pdf(text, max_length=max_length):
        y, page = check_page_break(y, page, doc)
        page.insert_text((x, y), line, fontsize=fontsize)
        y += step
    return y, page


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

        doc = fitz.open()
        
        page = doc.new_page()
        
        page.insert_text((50, 50), "PDFChecker Report", fontsize=18, fontname='helv')
        
        y = 90
        page.insert_text((50, y), "Report Information:", fontsize=14, fontname='helv')
        y += 25
        
        page.insert_text((50, y), f"Scanned PDF: {pdf_path}", fontsize=10)
        y += 20
        
        page.insert_text((50, y), f"Report Generation Tool: PDFChecker {PDFCHECKER_VERSION}", fontsize=10)
        y += 20
        
        current_time = datetime.now(timezone.utc)
        timestamp_str = current_time.strftime('%Y-%m-%d %H:%M:%S')
        page.insert_text((50, y), f"Report Generation Date: {timestamp_str} UTC", fontsize=10)
        y += 20

        if operator_name:
            page.insert_text((50, y), f"Operator: {operator_name}", fontsize=10)
            y += 20

        y += 15

        y, page = check_page_break(y, page, doc)
        page.insert_text((50, y), "Risk Assessment:", fontsize=14, fontname='helv')
        y += 25

        risk = analysis_result.risk
        if risk:
            page.insert_text(
                (50, y),
                f"Overall Risk Score: {risk['score']}/{risk['max_score']} ({risk['level'].upper()})",
                fontsize=12, fontname='helv'
            )
            y += 20
            for adjustment in risk.get('adjustments', []):
                y, page = _insert_wrapped(page, doc, y, f"NOTE: {adjustment}",
                                          x=70, fontsize=9, step=12)
            for name, category in risk['categories'].items():
                y, page = check_page_break(y, page, doc)
                label = name.replace('_', ' ').title()
                page.insert_text((70, y), f"{label}: {category['score']}/{category['max']}",
                                 fontsize=10)
                y += 15
                for reason in category['reasons'][:MAX_LINES_PER_SECTION]:
                    y, page = _insert_wrapped(page, doc, y, f"- {_clean_text_for_pdf(reason)}",
                                              x=90, fontsize=9, step=12)
                if len(category['reasons']) > MAX_LINES_PER_SECTION:
                    y, page = check_page_break(y, page, doc)
                    page.insert_text((90, y), "[Additional indicators truncated...]", fontsize=8)
                    y += 12
        else:
            page.insert_text((50, y), "Risk score not available.", fontsize=10)
            y += 15

        y += 15
        y, page = check_page_break(y, page, doc)
        page.insert_text((50, y), "Hash Information:", fontsize=14, fontname='helv')
        y += 25
        
        if analysis_result.hashes:
            for hash_type, hash_value in analysis_result.hashes.items():
                y, page = check_page_break(y, page, doc)
                page.insert_text((50, y), f"{hash_type}: {hash_value}", fontsize=10)
                y += 15
                if check_virustotal and hash_type == "SHA-256":
                    y, page = check_page_break(y, page, doc)
                    vt_report = check_vt_hash(hash_value, silent=True)
                    result = format_virustotal_file_result(vt_report)
                    for line in result.split('\n'):
                        y, page = check_page_break(y, page, doc)
                        page.insert_text((50, y), line, fontsize=10)
                        y += 15
        
        y += 15
        y, page = check_page_break(y, page, doc)
        page.insert_text((50, y), "Document Links:", fontsize=14, fontname='helv')
        y += 25

        # Share one extractor across all links (and QR URLs below) so the API
        # call limit is enforced; bulk mode passes its own so the limit spans
        # all files
        if check_virustotal and link_checker is None:
            link_checker = LinkExtractor()
            link_checker._initialize_api_config()

        if analysis_result.links:
            page.insert_text((50, y), f"{len(analysis_result.links)} links found.", fontsize=10)
            y += 20

            for i, link in enumerate(analysis_result.links, 1):
                y, page = check_page_break(y, page, doc)
                display_link = defang_url(link) if defang else link
                page.insert_text((50, y), f"{i}. {display_link}", fontsize=10)
                y += 15

                if check_virustotal:
                    y, page = check_page_break(y, page, doc)
                    if link in link_checker.checked_urls:
                        result = "Skipped: URL already checked in this operation."
                    elif link_checker.api_calls_made >= link_checker.api_limit:
                        result = "Skipped: VirusTotal API call limit reached."
                    else:
                        vt_result = link_checker.check_link_virustotal(link)
                        result = format_virustotal_url_result(vt_result)
                    for line in result.split('\n'):
                        y, page = check_page_break(y, page, doc)
                        page.insert_text((70, y), line, fontsize=9)
                        y += 12
                    y += 8
        else:
            page.insert_text((50, y), "No links found in the PDF.", fontsize=10)
        
        y += 20
        y, page = check_page_break(y, page, doc)
        page.insert_text((50, y), "PDF Metadata:", fontsize=14, fontname='helv')
        y += 25
        
        if analysis_result.metadata:
            for section, data in analysis_result.metadata.items():
                if data and isinstance(data, dict):
                    y, page = check_page_break(y, page, doc)
                    section_title = section.replace('_', ' ').title()
                    page.insert_text((50, y), f"{section_title}:", fontsize=12, fontname='helv')
                    y += 20
                    
                    for key, value in data.items():
                        y, page = check_page_break(y, page, doc)
                        clean_value = _clean_text_for_pdf(str(value))
                        lines = _wrap_text_for_pdf(f"{key}: {clean_value}", max_length=70)
                        for line in lines[:MAX_LINES_PER_SECTION]:
                            y, page = check_page_break(y, page, doc)
                            page.insert_text((70, y), line, fontsize=9)
                            y += 12
                        if len(lines) > MAX_LINES_PER_SECTION:
                            y, page = check_page_break(y, page, doc)
                            page.insert_text((70, y), "[Content truncated...]", fontsize=8)
                            y += 12
                    y += 15
        else:
            page.insert_text((50, y), "Error analyzing PDF metadata.", fontsize=10)
        
        y += 20
        y, page = check_page_break(y, page, doc)
        page.insert_text((50, y), "JavaScript Analysis:", fontsize=14, fontname='helv')
        y += 25
        
        if analysis_result.javascript:
            js_findings = analysis_result.javascript
            page.insert_text((50, y), f"JavaScript Detected: {'Yes' if js_findings.get('has_javascript') else 'No'}", fontsize=10)
            y += 15
            page.insert_text((50, y), f"JavaScript Objects Found: {js_findings.get('javascript_count', 0)}", fontsize=10)
            y += 20
            
            if js_findings.get('javascript_sources'):
                y, page = check_page_break(y, page, doc)
                page.insert_text((50, y), "JavaScript Sources:", fontsize=12, fontname='helv')
                y += 20
                
                for i, source in enumerate(js_findings['javascript_sources'], 1):
                    y, page = check_page_break(y, page, doc)
                    page.insert_text((70, y), f"{i}. Source: {source.get('source', 'Unknown')}", fontsize=10)
                    y += 15
                    
                    y, page = check_page_break(y, page, doc)
                    page.insert_text((70, y), f"Location: {source.get('location', 'Unknown')}", fontsize=10)
                    y += 15
                    
                    content = source.get('content', '')
                    if content:
                        y, page = check_page_break(y, page, doc)
                        content_lines = _wrap_text_for_pdf(content, max_length=80)
                        page.insert_text((70, y), "Content:", fontsize=9)
                        y += 12
                        
                        for line in content_lines[:MAX_LINES_PER_SECTION]:
                            y, page = check_page_break(y, page, doc)
                            clean_line = _clean_text_for_pdf(line)
                            page.insert_text((90, y), clean_line, fontsize=8)
                            y += 12
                        
                        if len(content_lines) > MAX_LINES_PER_SECTION:
                            y, page = check_page_break(y, page, doc)
                            page.insert_text((90, y), "[Content truncated...]", fontsize=8)
                            y += 12
                    
                    y += 15
            
            if js_findings.get('suspicious_patterns'):
                y += 10
                y, page = check_page_break(y, page, doc)
                page.insert_text((50, y), "Suspicious Patterns Detected:", fontsize=12, fontname='helv')
                y += 20
                
                for pattern in js_findings['suspicious_patterns']:
                    y, page = check_page_break(y, page, doc)
                    severity_indicator = "[HIGH]" if pattern.get('severity') == 'High' else "[MED]"
                    clean_pattern = _clean_text_for_pdf(pattern.get('pattern', ''))
                    pattern_type = pattern.get('type', 'Unknown')
                    page.insert_text((70, y), f"{severity_indicator} {pattern_type}: {clean_pattern}", fontsize=10)
                    y += 15
                    
                    y, page = check_page_break(y, page, doc)
                    clean_location = _clean_text_for_pdf(pattern.get('location', 'Unknown'))
                    page.insert_text((70, y), f"Location: {clean_location}", fontsize=9)
                    y += 12
                    
                    y, page = check_page_break(y, page, doc)
                    page.insert_text((70, y), f"Severity: {pattern.get('severity', 'Unknown')}", fontsize=9)
                    y += 20
        else:
            y, page = check_page_break(y, page, doc)
            page.insert_text((50, y), "Error analyzing JavaScript content.", fontsize=10)

        y += 20
        y, page = check_page_break(y, page, doc)
        page.insert_text((50, y), "Embedded Files:", fontsize=14, fontname='helv')
        y += 25

        embedded = analysis_result.embedded
        if embedded:
            page.insert_text((50, y), f"Embedded Files Found: {embedded['embedded_count']}", fontsize=10)
            y += 15
            y, page = check_page_break(y, page, doc)
            page.insert_text((50, y), f"Hidden/Orphaned Streams: {embedded['hidden_stream_count']}", fontsize=10)
            y += 20

            for i, entry in enumerate(embedded['embedded_files'], 1):
                y, page = _insert_wrapped(
                    page, doc, y,
                    f"{i}. {_clean_text_for_pdf(entry['filename'])} "
                    f"({entry['size']} bytes) - Risk: {entry['risk']}",
                    x=70, fontsize=10
                )
                y, page = _insert_wrapped(page, doc, y, f"Source: {entry['source']}",
                                          x=90, fontsize=9, step=12)
                if entry['content_type']:
                    y, page = _insert_wrapped(page, doc, y,
                                              f"Content Type: {entry['content_type']}",
                                              x=90, fontsize=9, step=12)
                sha256 = entry['hashes'].get('SHA-256')
                if sha256:
                    y, page = _insert_wrapped(page, doc, y, f"SHA-256: {sha256}",
                                              x=90, fontsize=9, step=12)
                for reason in entry['risk_reasons']:
                    y, page = _insert_wrapped(page, doc, y,
                                              f"WARNING: {_clean_text_for_pdf(reason)}",
                                              x=90, fontsize=9, step=12)
                y += 8

            for stream in embedded['hidden_streams']:
                y, page = _insert_wrapped(
                    page, doc, y,
                    f"Hidden stream at XRef {stream['xref']} ({stream['size']} bytes) "
                    f"- Risk: {stream['risk']}",
                    x=70, fontsize=10
                )
                sha256 = stream['hashes'].get('SHA-256')
                if sha256:
                    y, page = _insert_wrapped(page, doc, y, f"SHA-256: {sha256}",
                                              x=90, fontsize=9, step=12)
                y += 8
        else:
            page.insert_text((50, y), "Embedded file analysis not available.", fontsize=10)
            y += 15

        y += 20
        y, page = check_page_break(y, page, doc)
        page.insert_text((50, y), "Structural Anomalies:", fontsize=14, fontname='helv')
        y += 25

        structure = analysis_result.structure
        if structure:
            page.insert_text((50, y), f"Anomalies Detected: {structure['anomaly_count']}", fontsize=10)
            y += 20
            for anomaly in structure['anomalies']:
                y, page = _insert_wrapped(
                    page, doc, y,
                    f"[{anomaly['severity'].upper()}] {anomaly['type']} (x{anomaly['count']})",
                    x=70, fontsize=10
                )
                y, page = _insert_wrapped(page, doc, y,
                                          _clean_text_for_pdf(anomaly['description']),
                                          x=90, fontsize=9, step=12)
                if anomaly['locations']:
                    y, page = _insert_wrapped(
                        page, doc, y,
                        "Locations: " + ", ".join(anomaly['locations']),
                        x=90, fontsize=9, step=12
                    )
                y += 8
        else:
            page.insert_text((50, y), "Structure analysis not available.", fontsize=10)
            y += 15

        y += 20
        y, page = check_page_break(y, page, doc)
        page.insert_text((50, y), "QR Codes:", fontsize=14, fontname='helv')
        y += 25

        qr = analysis_result.qr
        if qr and qr['supported']:
            page.insert_text((50, y), f"QR Codes Decoded: {qr['qr_count']}", fontsize=10)
            y += 15
            if qr['undecoded_count']:
                y, page = check_page_break(y, page, doc)
                page.insert_text((50, y),
                                 f"QR Codes Detected but Unreadable: {qr['undecoded_count']}",
                                 fontsize=10)
                y += 15
            y += 5

            for i, qr_code in enumerate(qr['qr_codes'], 1):
                payload = qr_code['payload']
                is_url = qr_code['type'] == 'URL'
                display_payload = defang_url(payload) if (is_url and defang) else payload
                y, page = _insert_wrapped(
                    page, doc, y,
                    f"{i}. Page {qr_code['page']} [{qr_code['type']}]: "
                    f"{_clean_text_for_pdf(display_payload)}",
                    x=70, fontsize=10
                )

                if check_virustotal and is_url:
                    if payload in link_checker.checked_urls:
                        result = "Skipped: URL already checked in this operation."
                    elif link_checker.api_calls_made >= link_checker.api_limit:
                        result = "Skipped: VirusTotal API call limit reached."
                    else:
                        vt_result = link_checker.check_link_virustotal(payload)
                        result = format_virustotal_url_result(vt_result)
                    for line in result.split('\n'):
                        y, page = check_page_break(y, page, doc)
                        page.insert_text((90, y), line, fontsize=9)
                        y += 12
                y += 8
        elif qr:
            y, page = _insert_wrapped(page, doc, y, QR_UNAVAILABLE_MESSAGE)
        else:
            page.insert_text((50, y), "QR analysis not available.", fontsize=10)
            y += 15

        if analysis_result.errors:
            y += 20
            y, page = check_page_break(y, page, doc)
            page.insert_text((50, y), "Analysis Errors:", fontsize=14, fontname='helv')
            y += 25
            for error in analysis_result.errors:
                y, page = _insert_wrapped(page, doc, y,
                                          f"- {_clean_text_for_pdf(error)}",
                                          x=70, fontsize=9, step=12)

        doc.save(str(output_path))
        doc.close()
        return str(output_path)
        
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        return None

# format the VirusTotal hash result
def format_virustotal_file_result(vt_report):
    if not vt_report:
        return "File not found in VirusTotal database. No previous analysis available."
    
    attrs = vt_report.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values())
    
    if total == 0:
        return "File not found in VirusTotal database. No previous analysis available."
    
    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
    result = f"Detection Rate: {positives}/{total} ({positives/total*100:.1f}%)"
    if positives > 0:
        result += "\nDetections:"
        for scanner, scan_result in attrs.get("last_analysis_results", {}).items():
            if scan_result.get("category") in ("malicious", "suspicious"):
                result += f"\n- {scanner}: {scan_result.get('result', 'Unknown')}"
    
    last_scan_date = attrs.get("last_analysis_date")
    if last_scan_date:
        try:
            scan_datetime = datetime.fromtimestamp(last_scan_date, tz=timezone.utc)
            result += f"\nScan Date: {scan_datetime.strftime('%Y-%m-%d %H:%M:%S')} UTC"
        except (ValueError, TypeError):
            pass
    
    return result

# format the VirusTotal URL result (API call)
def format_virustotal_url_result(vt_result):
    if not vt_result:
        return "VirusTotal API call failed. Please check your API key or try again later."

    attrs = vt_result.get("data", {}).get("attributes", {})
    if attrs.get("status") not in (None, "completed"):
        return "VirusTotal analysis still pending. Results were not available at report time."

    stats = attrs.get("stats", {})
    total = sum(stats.values())

    if total == 0:
        return "URL not found in VirusTotal database. No previous analysis available."

    result = "VirusTotal Results:"
    result += f"\n- Harmless: {stats.get('harmless', 0)}"
    result += f"\n- Malicious: {stats.get('malicious', 0)}"
    result += f"\n- Suspicious: {stats.get('suspicious', 0)}"
    result += f"\n- Undetected: {stats.get('undetected', 0)}"

    last_scan_date = attrs.get("last_analysis_date")
    if last_scan_date:
        try:
            scan_datetime = datetime.fromtimestamp(last_scan_date, tz=timezone.utc)
            result += f"\nLast Scan Date: {scan_datetime.strftime('%Y-%m-%d %H:%M:%S')} UTC"
        except (ValueError, TypeError):
            pass
    
    return result

# main function to generate the report
def main(pdf_path, validate_pdf_file=None):
    if validate_pdf_file and not validate_pdf_file(pdf_path):
        return

    operator_name = input("\nPlease type your name (enter to skip): ").strip()[:MAX_OPERATOR_NAME_LENGTH]

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
