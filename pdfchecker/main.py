import argparse
import getpass
from pathlib import Path
import os

if __package__ in (None, ""):
    # Executed as a plain script (python pdfchecker/main.py): register the
    # parent directory as package root so the relative imports below resolve
    # the same way they do for the installed package
    import importlib
    import sys
    _package_dir = Path(__file__).resolve().parent
    sys.path.insert(0, str(_package_dir.parent))
    __package__ = _package_dir.name
    importlib.import_module(__package__)

from .core import bulk_processor, config_manager
from .core.config_manager import ConfigError, KeyringError
from .core.hash_checker import main as hash_checker_main
from .core.link_extractor import main as link_extractor_main
from .core.metadata_analyzer import analyze_pdf_metadata, print_metadata
from .core.javascript_detector import extract_javascript_from_pdf, print_javascript_findings
from .core.embedded_file_detector import (detect_embedded_files, extract_embedded_files,
                                          print_embedded_findings)
from .core.structure_analyzer import analyze_structure, print_structure_findings
from .core.qr_detector import (detect_qr_codes, print_qr_findings,
                               QR_SUPPORT, QR_UNAVAILABLE_MESSAGE)
from .core.link_extractor import LinkExtractor, defang_url
from .core.risk_scorer import analyze_pdf_for_risk, print_risk_assessment
from .core.report_generator import main as report_generator_main
from .core.utils import get_confirmation, apply_memory_guard

MAX_FILE_SIZE_MB = 100
MAX_INPUT_LENGTH = 1000

# check on file size and type
def validate_pdf_file(file_path: str) -> bool:
    try:
        path = Path(file_path)
        
        if not path.exists():
            print(f"Error: File {file_path} does not exist")
            return False
        
        if not path.is_file():
            print(f"Error: {file_path} is not a file")
            return False
        
        if path.suffix.lower() != '.pdf':
            print(f"Error: {file_path} is not a PDF")
            return False
        
        if path.stat().st_size > (MAX_FILE_SIZE_MB*1024*1024):
            print(f"Error: File {file_path} is too large (max {MAX_FILE_SIZE_MB}MB)")
            return False
            
        return True
    except Exception as e:
        print(f"Error validating file {file_path}: {e}")
        return False

def get_user_input(prompt: str, max_length: int = MAX_INPUT_LENGTH) -> str:
    try:
        user_input = input(prompt).strip()
        if len(user_input) > max_length:
            raise ValueError("Input too long")
        return user_input
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt("Operation cancelled")



def handle_config_error(operation_name: str, error: Exception):
    if isinstance(error, (ConfigError, KeyringError)):
        print(f"Configuration error during {operation_name}: {error}")
    else:
        print(f"Unexpected error during {operation_name}: {error}")

def secure_set_api_key():
    print("Setting VirusTotal API key securely...")

    try:
        # getpass keeps the key off the screen and out of the terminal echo
        api_key = getpass.getpass("Enter your VirusTotal API key (input hidden): ").strip()

        if len(api_key) > MAX_INPUT_LENGTH:
            print("Error: Input too long.")
            return

        if not api_key:
            print("Error: No API key provided.")
            return

        success, message = config_manager.set_api_key_secure(api_key)
        print(f"{'Success' if success else 'Error'}: {message}")

    except (EOFError, KeyboardInterrupt):
        print("\nOperation cancelled.")
    except Exception as e:
        handle_config_error("API key setting", e)

def mask_api_key(api_key: str) -> str:
    # Only reveal the first/last 8 chars when at least half the key stays masked
    if not api_key or len(api_key) < 32:
        return "***masked***"

    mask_length = len(api_key) - 16
    return f"{api_key[:8]}{'*' * mask_length}{api_key[-8:]}"

# Dispatch API key related sub-commands based on parsed arguments
def handle_api_key_management(args):
    if args.set_api_key:
        secure_set_api_key()
        return True
    
    if args.remove_api_key:
        if get_confirmation("Are you sure you want to remove the VirusTotal API key?"):
            success, message = config_manager.remove_api_key()
            print(f"{'Success' if success else 'Error'}: {message}")
        else:
            print("Operation aborted.")
        return True
    
    if args.show_api_key:
        if get_confirmation("Are you sure you want to display the VirusTotal API key (masked)?"):
            try:
                success, result = config_manager.get_api_key()
                if success:
                    masked_key = mask_api_key(result)
                    print(f"Current VirusTotal API key: {masked_key}")
                else:
                    print(f"Error: {result}")
            except Exception as e:
                handle_config_error("API key retrieval", e)
        else:
            print("Operation aborted.")
        return True

    if args.edit_api_limit:
        handle_api_limit_edit()
        return True
    
    return False

def handle_api_limit_edit():
    success, current_limit = config_manager.get_api_limit()
    
    if not success:
        print(f"Warning: Could not retrieve current limit. Using default: {current_limit}")
    else:
        print(f"Current API call limit: {current_limit}")
    
    try:
        new_limit_input = get_user_input("Enter new API call limit (press Enter to keep current): ")

        if not new_limit_input:
            return

        try:
            new_limit = int(new_limit_input)
        except ValueError:
            print("Error: Please enter a valid integer.")
            return

        if not (1 <= new_limit <= 10000):
            print("Error: API limit must be between 1 and 10000!")
            return

        success, message = config_manager.set_api_limit(new_limit)
        print(f"{'Success' if success else 'Error'}: {message}")

    except ValueError as e:
        # Raised by get_user_input for oversized input
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nOperation cancelled.")

def handle_pdf_analysis(args):
    # (single-file handler, bulk-folder handler, operation label)
    analysis_map = {
        'hash_checker': (lambda target: hash_checker_main(target, validate_pdf_file=validate_pdf_file),
                         bulk_processor.bulk_hash_check, 'hash checking'),
        'links': (handle_link_extraction,
                  bulk_processor.bulk_link_extraction, 'link extraction'),
        'metadata': (handle_metadata_analysis,
                     bulk_processor.bulk_metadata_analysis, 'metadata analysis'),
        'javascript': (handle_javascript_analysis,
                       bulk_processor.bulk_javascript_analysis, 'JavaScript analysis'),
        'embedded_files': (handle_embedded_analysis,
                           bulk_processor.bulk_embedded_analysis, 'embedded file detection'),
        'structure': (handle_structure_analysis,
                      bulk_processor.bulk_structure_analysis, 'structure analysis'),
        'qr_codes': (handle_qr_analysis,
                     bulk_processor.bulk_qr_analysis, 'QR code detection'),
        'risk_score': (handle_risk_score,
                       bulk_processor.bulk_risk_scoring, 'risk scoring'),
        'report': (lambda target: report_generator_main(target, validate_pdf_file=validate_pdf_file),
                   bulk_processor.bulk_report_generation, 'report generation')
    }

    for arg_name, (handler, bulk_handler, label) in analysis_map.items():
        target = getattr(args, arg_name)
        if target:
            # Cap this process's memory before parsing any untrusted PDF so a
            # decompression bomb aborts rather than exhausting the host
            apply_memory_guard()
            if Path(target).is_dir():
                bulk_processor.run_bulk_analysis(
                    target, label, bulk_handler,
                    exclude_reports=(arg_name == 'report')
                )
            else:
                handler(target)
            return True

    return False

def handle_link_extraction(pdf_file):
    defanged = get_confirmation("Do you want to display links in defanged format?")
    link_extractor_main(pdf_file, defanged=defanged, validate_pdf_file=validate_pdf_file)

def handle_metadata_analysis(pdf_file):
    if not validate_pdf_file(pdf_file):
        return
    
    try:
        original_stats = os.stat(pdf_file)
    except Exception:
        print(f"Error: Cannot access file {pdf_file}")
        return
    
    metadata = analyze_pdf_metadata(
        pdf_file, validate_pdf_file=None, file_stats=original_stats
    )
    print_metadata(metadata)
    try:
        os.utime(pdf_file, (original_stats.st_atime, original_stats.st_mtime))
    except Exception:
        pass

def handle_javascript_analysis(pdf_file):
    js_findings = extract_javascript_from_pdf(pdf_file, validate_pdf_file=validate_pdf_file)
    print_javascript_findings(js_findings)

def handle_embedded_analysis(pdf_file):
    # include_data=True so a later extraction reuses these findings instead
    # of parsing the document a second time
    findings = detect_embedded_files(pdf_file, validate_pdf_file=validate_pdf_file,
                                     include_data=True)
    if findings is None:
        return
    print_embedded_findings(findings)

    if not findings['embedded_files'] and not findings['hidden_streams']:
        return

    print("\nWARNING: Embedded files may be malicious. Only extract them in an "
          "isolated analysis environment.")
    if get_confirmation("Extract embedded files to disk?"):
        saved = extract_embedded_files(pdf_file, findings=findings)
        if saved:
            print(f"\n{len(saved)} file(s) extracted (owner read/write only, not executable):")
            for path, sha256 in saved:
                print(f"- {path}")
                if sha256:
                    print(f"  SHA-256: {sha256}")
        else:
            print("No file content could be extracted.")

def handle_structure_analysis(pdf_file):
    findings = analyze_structure(pdf_file, validate_pdf_file=validate_pdf_file)
    print_structure_findings(findings)

def handle_qr_analysis(pdf_file):
    if not validate_pdf_file(pdf_file):
        return
    if not QR_SUPPORT:
        print(QR_UNAVAILABLE_MESSAGE)
        return

    defanged = get_confirmation("Do you want to display QR URLs in defanged format?")
    print(f"\nScanning {pdf_file} for QR codes...")
    findings = detect_qr_codes(pdf_file)
    print_qr_findings(findings, defanged=defanged, defang_url=defang_url)

    urls = [qr['payload'] for qr in (findings or {}).get('qr_codes', [])
            if qr['type'] == 'URL']
    if urls:
        _check_qr_urls_with_virustotal(urls, defanged)

def _check_qr_urls_with_virustotal(urls, defanged):
    extractor = LinkExtractor()
    try:
        if not extractor._initialize_api_config() or not extractor.api_key:
            print("\nVirusTotal API key not found. Please set your API key to use this feature.")
            return
        if not get_confirmation("\nWould you like to check decoded QR URLs with VirusTotal?"):
            return

        for url in urls:
            display_url = defang_url(url) if defanged else url
            print(f"\nChecking {display_url} with VirusTotal...")
            if url in extractor.checked_urls:
                print("   URL already checked in this operation.")
                continue
            if extractor.api_calls_made >= extractor.api_limit:
                print("   Skipped due to API limit.")
                continue
            result = extractor.check_link_virustotal(url)
            if result:
                bulk_processor._print_url_vt_result(result)
            else:
                print("   VirusTotal check failed. Please check your API key or try again later.")

        print(f"\nTotal API calls made: {extractor.api_calls_made}")
    finally:
        extractor.reset()

def handle_risk_score(pdf_file):
    if not validate_pdf_file(pdf_file):
        return

    print(f"\nComputing risk score for {pdf_file}...")
    assessment = analyze_pdf_for_risk(pdf_file)
    print_risk_assessment(assessment)
    if not QR_SUPPORT:
        print(f"\nNote: {QR_UNAVAILABLE_MESSAGE}")

def create_argument_parser():
    parser = argparse.ArgumentParser(description='PDF Checker Tool')
    
    parser.add_argument('-hc', '--hash-checker', metavar='PDF_FILE_OR_DIR',
                      help='Generate hash values for a PDF file, or for all PDFs in a folder (bulk mode)')
    parser.add_argument('-l', '--links', metavar='PDF_FILE_OR_DIR',
                      help='Extract and check links from a PDF file, or from all PDFs in a folder (bulk mode)')
    parser.add_argument('-m', '--metadata', metavar='PDF_FILE_OR_DIR',
                      help='Extract and display PDF metadata information, for a single PDF or all PDFs in a folder (bulk mode)')
    parser.add_argument('-js', '--javascript', metavar='PDF_FILE_OR_DIR',
                      help='Analyze and detect JavaScript in a PDF file, or in all PDFs in a folder (bulk mode)')
    parser.add_argument('-ef', '--embedded-files', metavar='PDF_FILE_OR_DIR',
                      help='Detect and optionally extract files embedded in a PDF, or in all PDFs in a folder (bulk mode)')
    parser.add_argument('-sa', '--structure', metavar='PDF_FILE_OR_DIR',
                      help='Detect structural anomalies (auto-run actions, launch actions, XFA, obfuscation) in a PDF file, or in all PDFs in a folder (bulk mode)')
    parser.add_argument('-qr', '--qr-codes', metavar='PDF_FILE_OR_DIR',
                      help='Detect and decode QR codes in a PDF file, or in all PDFs in a folder (bulk mode)')
    parser.add_argument('-rs', '--risk-score', metavar='PDF_FILE_OR_DIR',
                      help='Compute a 0-100 risk score combining JavaScript, structure, embedded file, link and QR analysis, for a single PDF or all PDFs in a folder (bulk mode)')
    parser.add_argument('-r', '--report', metavar='PDF_FILE_OR_DIR',
                      help='Generate a comprehensive PDF report with hash, links, metadata, and JavaScript analysis, for a single PDF or all PDFs in a folder (bulk mode)')
    
    vt_group = parser.add_argument_group('VirusTotal API Key Management')
    vt_group.add_argument('--set-api-key', action='store_true',
                         help='Set your VirusTotal API key (secure interactive prompt)')
    vt_group.add_argument('--remove-api-key', action='store_true',
                         help='Remove your VirusTotal API key')
    vt_group.add_argument('--show-api-key', action='store_true',
                         help='Show your current VirusTotal API key (masked)')
    vt_group.add_argument('--edit-api-limit', action='store_true',
                         help='View and edit the API call limit for VirusTotal operations')
    
    return parser

def main():
    parser = create_argument_parser()
    args = parser.parse_args()
    
    if handle_api_key_management(args):
        return
    
    if handle_pdf_analysis(args):
        return
    
    parser.print_help()

if __name__ == "__main__":
    main()