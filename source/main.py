import argparse
from pathlib import Path
import os
from core import config_manager
from core.config_manager import ConfigError, KeyringError
from core.hash_checker import main as hash_checker_main
from core.link_extractor import main as link_extractor_main
from core.metadata_analyzer import analyze_pdf_metadata, print_metadata
from core.javascript_detector import extract_javascript_from_pdf, print_javascript_findings
from core.report_generator import main as report_generator_main
from core.utils import get_confirmation

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
    print("Note: Input will be visible for accuracy. Ensure no one is watching your screen -.-")
    
    try:
        api_key = get_user_input("Enter your VirusTotal API key: ")
        
        if not api_key:
            print("Error: No API key provided.")
            return
            
        success, message = config_manager.set_api_key_secure(api_key)
        print(f"{'Success' if success else 'Error'}: {message}")
        
    except KeyboardInterrupt:
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
    analysis_map = {
        'hash_checker': lambda: hash_checker_main(args.hash_checker, validate_pdf_file=validate_pdf_file),
        'links': lambda: handle_link_extraction(args.links),
        'metadata': lambda: handle_metadata_analysis(args.metadata),
        'javascript': lambda: handle_javascript_analysis(args.javascript),
        'report': lambda: report_generator_main(args.report, validate_pdf_file=validate_pdf_file)
    }
    
    for arg_name, handler in analysis_map.items():
        if getattr(args, arg_name):
            handler()
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

def create_argument_parser():
    parser = argparse.ArgumentParser(description='PDF Checker Tool')
    
    parser.add_argument('-hc', '--hash-checker', metavar='PDF_FILE',
                      help='Generate hash values for a PDF file')
    parser.add_argument('-l', '--links', metavar='PDF_FILE',
                      help='Extract and check links from a PDF file')
    parser.add_argument('-m', '--metadata', metavar='PDF_FILE',
                      help='Extract and display PDF metadata information')
    parser.add_argument('-js', '--javascript', metavar='PDF_FILE',
                      help='Analyze and detect JavaScript in a PDF file')
    parser.add_argument('-r', '--report', metavar='PDF_FILE',
                      help='Generate a comprehensive PDF report with hash, links, metadata, and JavaScript analysis')
    
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