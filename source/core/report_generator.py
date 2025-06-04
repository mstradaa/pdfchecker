import os
from pathlib import Path
import fitz
from datetime import datetime, timezone
from .hash_checker import calculate_file_hashes, check_virustotal as check_vt_hash
from .link_extractor import extract_links, check_link_virustotal, defang_url
from .metadata_analyzer import analyze_pdf_metadata
from .javascript_detector import extract_javascript_from_pdf
from .config_manager import get_api_key, get_api_limit

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

def get_confirmation(prompt: str) -> bool:
    while True:
        try:
            response = input(f"{prompt} (Y/N, Q to quit): ").strip().upper()
            
            if len(response) > 1000:
                print("Error: Input too long. Please try again.")
                continue
                
            if response == 'Q':
                print("Operation cancelled by user.")
                return False
            if response in ('Y', 'N'):
                return response == 'Y'
            print("Please enter Y, N, or Q.")
        except (EOFError, KeyboardInterrupt):
            print("\nOperation cancelled.")
            return False

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
        self.errors = []

def analyze_pdf_once(pdf_path, validate_pdf_file=None):
    result = PDFAnalysisResult()
    original_stats = None

    try:
        original_stats = os.stat(pdf_path)
        result.metadata = analyze_pdf_metadata(
            pdf_path, validate_pdf_file=validate_pdf_file, file_stats=original_stats
        )

        result.hashes = calculate_file_hashes(pdf_path)

        result.links = extract_links(pdf_path)

        result.javascript = extract_javascript_from_pdf(
            pdf_path, validate_pdf_file=validate_pdf_file
        )
    except Exception as e:
        result.errors.append(f"Analysis error: {str(e)}")
    finally:
        if original_stats:
            try:
                os.utime(pdf_path, (original_stats.st_atime, original_stats.st_mtime))
            except Exception:
                pass

    return result

def create_report(pdf_path, check_virustotal=False, defang=False, operator_name=None, validate_pdf_file=None):
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
                    vt_result = check_link_virustotal(link)
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
    
    positives = vt_report.get('positives', 0)
    total = vt_report.get('total', 0)
    
    if total == 0:
        return "File not found in VirusTotal database. No previous analysis available."
    
    result = f"Detection Rate: {positives}/{total} ({positives/total*100:.1f}%)"
    if positives > 0:
        result += "\nDetections:"
        for scanner, scan_result in vt_report.get('scans', {}).items():
            if scan_result.get('detected'):
                result += f"\n- {scanner}: {scan_result.get('result', 'Unknown')}"
    
    scan_date = vt_report.get('scan_date')
    if scan_date:
        try:
            scan_datetime = datetime.fromtimestamp(scan_date, tz=timezone.utc)
            result += f"\nScan Date: {scan_datetime.strftime('%Y-%m-%d %H:%M:%S')} UTC"
        except (ValueError, TypeError):
            pass
    
    return result

# format the VirusTotal URL result (API call)
def format_virustotal_url_result(vt_result):
    if not vt_result:
        return "VirusTotal API call failed. Please check your API key or try again later."
    
    stats = vt_result.get("data", {}).get("attributes", {}).get("stats", {})
    total = sum(stats.values())
    
    if total == 0:
        return "URL not found in VirusTotal database. No previous analysis available."
    
    result = "VirusTotal Results:"
    result += f"\n- Harmless: {stats.get('harmless', 0)}"
    result += f"\n- Malicious: {stats.get('malicious', 0)}"
    result += f"\n- Suspicious: {stats.get('suspicious', 0)}"
    result += f"\n- Undetected: {stats.get('undetected', 0)}"
    
    last_scan_date = vt_result.get("data", {}).get("attributes", {}).get("last_analysis_date")
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
        
    operator_name = input("\nPlease type your name (enter to skip): ").strip()
    
    success, api_key = get_api_key()
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
