import argparse
import getpass
from pathlib import Path
import os
import sys

if __package__ in (None, ""):
    # Executed as a plain script (python pdfchecker/main.py): register the
    # parent directory as package root so the relative imports below resolve
    # the same way they do for the installed package
    import importlib
    _package_dir = Path(__file__).resolve().parent
    sys.path.insert(0, str(_package_dir.parent))
    __package__ = _package_dir.name
    importlib.import_module(__package__)

from .core import bulk_processor, config_manager, indicator_export, json_output
from .core.analysis import run_analysis
from .core.config_manager import PROVIDERS, ConfigError
from .core.coverage import print_coverage
from .core.hash_checker import main as hash_checker_main
from .core.link_extractor import check_qr_urls, defang_url, main as link_extractor_main
from .core.metadata_analyzer import analyze_pdf_metadata, print_metadata
from .core.javascript_detector import extract_javascript_from_pdf, print_javascript_findings
from .core.embedded_file_detector import (detect_embedded_files, extract_embedded_files,
                                          print_embedded_findings)
from .core.pdf_access import (DEFAULT_MAX_FILE_SIZE_MB, MAX_FILE_SIZE_LIMIT_MB,
                              set_max_file_size_mb, set_password, validate_pdf)
from .core.pipeline import analyze_pdf_for_risk
from .core.policies import load_policy
from .core.structure_analyzer import analyze_structure, print_structure_findings
from .core.qr_detector import (detect_qr_codes, print_qr_findings, qr_supported,
                               url_payloads, QR_UNAVAILABLE_MESSAGE)
from .core.risk_scorer import print_risk_assessment
from .core.report_generator import main as report_generator_main
from .core.threat_intel import print_call_summary, selected_providers
from .core.urlhaus import URLhausClient
from .core.utils import MAX_INPUT_LENGTH, get_confirmation, apply_memory_guard
from .core.virustotal import VirusTotalClient
from .core.yara_scanner import compile_rules

# Analysis actions: (short flag, long flag, help text)
ACTIONS = [
    ('-a', '--analyze', 'Full terminal scan with coverage and optional policy/YARA/grouping'),
    ('-l', '--links', 'Find URLs in annotations, text, actions and JavaScript'),
    ('-rs', '--risk-score', 'Show local risk score and coverage'),
    ('-m', '--metadata', 'Show document metadata'),
    ('-js', '--javascript', 'Inspect embedded JavaScript'),
    ('-ef', '--embedded-files', 'Inspect attachments; optionally extract in single-file mode'),
    ('-sa', '--structure', 'Inspect PDF actions and structural anomalies'),
    ('-qr', '--qr-codes', 'Decode QR codes (requires the qr extra)'),
    ('-hc', '--hash-checker', 'Compute hashes; optionally check reputation'),
    ('-r', '--report', 'Create a PDF report (interactive)'),
    ('-i', '--export-indicators', 'Export URL/domain/JavaScript indicators (non-interactive)'),
]

# Reputation service configuration: (flag, help text, operation, service)
KEY_OPTIONS = [
    ('set-api-key', 'Store a VirusTotal key securely', 'set', 'virustotal'),
    ('show-api-key', 'Show the masked VirusTotal key', 'show', 'virustotal'),
    ('remove-api-key', 'Remove the stored VirusTotal key', 'remove', 'virustotal'),
    ('set-urlhaus-api-key', 'Store a URLhaus Auth-Key securely', 'set', 'urlhaus'),
    ('show-urlhaus-api-key', 'Show the masked URLhaus Auth-Key', 'show', 'urlhaus'),
    ('remove-urlhaus-api-key', 'Remove the stored URLhaus Auth-Key', 'remove', 'urlhaus'),
    ('edit-api-limit', 'Change the per-provider request budget', 'limit', None),
]


def _dest(flag):
    return flag.lstrip('-').replace('-', '_')

def _max_size(value):
    try:
        size = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f'invalid size: {value!r}') from None
    if not 1 <= size <= MAX_FILE_SIZE_LIMIT_MB:
        raise argparse.ArgumentTypeError(f'must be between 1 and {MAX_FILE_SIZE_LIMIT_MB} MB')
    return size

def get_user_input(prompt: str, max_length: int = MAX_INPUT_LENGTH) -> str:
    try:
        user_input = input(prompt).strip()
        if len(user_input) > max_length:
            raise ValueError("Input too long")
        return user_input
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt("Operation cancelled")



def handle_config_error(operation_name: str, error: Exception):
    if isinstance(error, ConfigError):
        print(f"Configuration error during {operation_name}: {error}")
    else:
        print(f"Unexpected error during {operation_name}: {error}")

def secure_set_key(provider):
    label = PROVIDERS[provider].label
    print(f"Setting {label} securely...")

    try:
        # getpass keeps the key off the screen and out of the terminal echo
        key = getpass.getpass(f"Enter your {label} (input hidden): ").strip()

        if len(key) > MAX_INPUT_LENGTH:
            print("Error: Input too long.")
            return

        if not key:
            print(f"Error: No {label} provided.")
            return

        success, message = config_manager.set_provider_key(provider, key)
        print(f"{'Success' if success else 'Error'}: {message}")

    except (EOFError, KeyboardInterrupt):
        print("\nOperation cancelled.")
    except Exception as e:
        handle_config_error(f"{label} setting", e)


def show_key(provider):
    label = PROVIDERS[provider].label
    if not get_confirmation(f"Are you sure you want to display the {label} (masked)?"):
        print("Operation aborted.")
        return
    try:
        success, result = config_manager.get_provider_key(provider)
        print(f"Current {label}: {mask_api_key(result)}" if success else f"Error: {result}")
    except Exception as e:
        handle_config_error(f"{label} retrieval", e)


def remove_key(provider):
    label = PROVIDERS[provider].label
    if get_confirmation(f"Are you sure you want to remove the {label}?"):
        success, message = config_manager.remove_provider_key(provider)
        print(f"{'Success' if success else 'Error'}: {message}")
    else:
        print("Operation aborted.")

def mask_api_key(api_key: str) -> str:
    # Only reveal the first/last 8 chars when at least half the key stays masked
    if not api_key or len(api_key) < 32:
        return "***masked***"

    mask_length = len(api_key) - 16
    return f"{api_key[:8]}{'*' * mask_length}{api_key[-8:]}"

# Dispatch API key related sub-commands based on parsed arguments
def handle_api_key_management(args):
    operations = {'set': secure_set_key, 'show': show_key, 'remove': remove_key}
    for flag, _, operation, provider in KEY_OPTIONS:
        if getattr(args, _dest(flag)):
            if operation == 'limit':
                handle_api_limit_edit()
            else:
                operations[operation](provider)
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
        'hash_checker': (hash_checker_main, bulk_processor.bulk_hash_check, 'hash checking'),
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
        'report': (report_generator_main,
                   bulk_processor.bulk_report_generation, 'report generation')
    }

    for arg_name, (handler, bulk_handler, label) in analysis_map.items():
        target = getattr(args, arg_name)
        if target:
            if args.json:
                sys.exit(json_output.run_json_analysis(arg_name, target))
            if Path(target).is_dir():
                bulk_processor.run_bulk_analysis(
                    target, label, bulk_handler,
                    exclude_reports=(arg_name == 'report')
                )
            else:
                # Validated once here; the analyses trust their input path
                error = validate_pdf(target)
                if error:
                    print(f"Error: {error}")
                else:
                    handler(target)
            return True

    return False

def handle_link_extraction(pdf_file):
    defanged = get_confirmation("Do you want to display links in defanged format?")
    link_extractor_main(pdf_file, defanged=defanged)

def handle_metadata_analysis(pdf_file):
    print_metadata(analyze_pdf_metadata(pdf_file))

def handle_javascript_analysis(pdf_file):
    print_javascript_findings(extract_javascript_from_pdf(pdf_file))

def handle_embedded_analysis(pdf_file):
    # include_data=True so a later extraction reuses these findings instead
    # of parsing the document a second time
    findings = detect_embedded_files(pdf_file, include_data=True)
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
    print_structure_findings(analyze_structure(pdf_file))

def handle_qr_analysis(pdf_file):
    if not qr_supported():
        print_coverage({'qr': {'status': 'unavailable', 'details': [QR_UNAVAILABLE_MESSAGE]}})
        return

    defanged = get_confirmation("Do you want to display QR URLs in defanged format?")
    print(f"\nScanning {pdf_file} for QR codes...")
    findings = detect_qr_codes(pdf_file)
    print_qr_findings(findings, defanged=defanged, defang_url=defang_url)

    if url_payloads(findings):
        with selected_providers("decoded QR URLs", VirusTotalClient(), URLhausClient()) as providers:
            check_qr_urls(findings, defanged, providers)
            print_call_summary(providers)

def handle_risk_score(pdf_file):
    print(f"\nComputing risk score for {pdf_file}...")
    try:
        assessment = analyze_pdf_for_risk(pdf_file)
    except Exception as exc:
        print_coverage({'risk analysis': {'status': 'failed', 'details': [str(exc)]}})
        raise SystemExit(1)
    print_risk_assessment(assessment)
    if not qr_supported():
        print(f"\nNote: {QR_UNAVAILABLE_MESSAGE}")

def create_argument_parser():
    parser = argparse.ArgumentParser(
        prog='pdfchecker', usage='%(prog)s ACTION PATH [options]',
        description='Inspect PDFs for security indicators. Use -a for a complete terminal scan.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  pdfchecker -a invoice.pdf
  pdfchecker -a samples/ --campaigns --recursive
  pdfchecker -a invoice.pdf --fail-on-risk 55
  pdfchecker -a samples/ --policy policy.json --yara rules.yar
  pdfchecker -a locked.pdf --ask-password
  pdfchecker -l invoice.pdf

-a exit codes: 0 completed/policy passed; 1 scan failed, skipped input, or
required coverage missing; 2 invalid arguments/config; 3 policy rejected.
Folders are non-recursive unless --recursive is used. No external lookups in -a.
Policy JSON keys: risk_threshold (0-100), reject_javascript, reject_attachments,
reject_link_mismatch, reject_yara, require_complete (booleans). --fail-on-risk
overrides risk_threshold.
""")
    actions = parser.add_argument_group('Choose one action (FILE or FOLDER)')
    action = actions.add_mutually_exclusive_group()
    for short, long, description in ACTIONS:
        action.add_argument(short, long, metavar='PATH', help=description)
    scan = parser.add_argument_group('Full scan options (with -a)')
    scan.add_argument('--policy', metavar='FILE', help='Apply a policy file; see keys and exit codes below')
    scan.add_argument('--fail-on-risk', type=int, metavar='0-100', help='Reject a file at or above this score')
    scan.add_argument('--yara', action='append', metavar='RULES', help='Match local YARA rules; repeat for more files (requires yara extra)')
    scan.add_argument('--campaigns', action='store_true', help='Group a folder by shared URLs, scripts and attachment hashes')
    scan.add_argument('--recursive', action='store_true', help='Include subfolders in a folder scan')
    passwords = parser.add_argument_group('Encrypted PDFs (all analysis actions)')
    password = passwords.add_mutually_exclusive_group()
    password.add_argument('--ask-password', action='store_true', help='Prompt once without echo; use this password for the whole batch')
    password.add_argument('--password-env', metavar='NAME', help='Read the PDF password from this environment variable')
    limits = parser.add_argument_group('Input limits (all analysis actions)')
    limits.add_argument('--max-size', type=_max_size, metavar='MB',
                        help=f'Analyze PDFs up to this size (default: {DEFAULT_MAX_FILE_SIZE_MB}, '
                             f'max: {MAX_FILE_SIZE_LIMIT_MB}); larger files are skipped')
    output = parser.add_argument_group('Output')
    output.add_argument('--json', action='store_true', help='Write JSON to stdout; no analysis prompts or external lookups')
    output.add_argument('--format', dest='indicator_format', choices=('json', 'stix'), help='Indicator export format for -i (default: json)')
    output.add_argument('-o', '--output', metavar='FILE', help='Write -i export to a file instead of stdout')
    keys = parser.add_argument_group('Optional reputation service configuration')
    management = keys.add_mutually_exclusive_group()
    for flag, description, _, _ in KEY_OPTIONS:
        management.add_argument('--' + flag, action='store_true', help=description)
        if 'urlhaus' in flag:
            management.add_argument('--' + flag.replace('urlhaus', 'abusech'),
                                    dest=_dest(flag), action='store_true',
                                    help=argparse.SUPPRESS)
    return parser


def main():
    parser = create_argument_parser()
    args = parser.parse_args()
    selected = any(getattr(args, _dest(long)) for _, long, _ in ACTIONS)
    management = any(getattr(args, _dest(flag)) for flag, *_ in KEY_OPTIONS)
    scan_options = args.policy or args.fail_on_risk is not None or args.yara or args.campaigns or args.recursive
    if scan_options and not args.analyze:
        parser.error('--policy, --fail-on-risk, --yara, --campaigns and --recursive require -a/--analyze')
    if (args.campaigns or args.recursive) and not Path(args.analyze).is_dir():
        parser.error('--campaigns and --recursive require a folder')
    input_options = args.json or args.ask_password or args.password_env or args.max_size is not None
    if management and (selected or input_options):
        parser.error('Choose either an analysis action or a configuration action')
    if (args.output or args.indicator_format) and not args.export_indicators:
        parser.error('--output and --format require -i/--export-indicators')
    if args.export_indicators and args.json and args.indicator_format == 'stix':
        parser.error('--json cannot be combined with --format stix')
    if not selected and input_options:
        parser.error('Choose an analysis action, for example -a FILE')
    if management:
        handle_api_key_management(args)
        return
    if not selected:
        parser.print_help()
        return
    try:
        policy = load_policy(args.policy, args.fail_on_risk)
        if policy.get('reject_yara') and not args.yara:
            parser.error('A reject_yara policy requires --yara RULES')
        compiled = compile_rules(args.yara) if args.yara else None
    except Exception as exc:
        parser.error(str(exc))
    try:
        if args.password_env:
            if args.password_env not in os.environ:
                parser.error(f'Password environment variable {args.password_env} is not set')
            set_password(os.environ[args.password_env])
        elif args.ask_password:
            set_password(getpass.getpass('PDF password (hidden): '))
        if args.max_size is not None:
            set_max_file_size_mb(args.max_size)
        # Cap this process's memory before parsing any untrusted PDF so a
        # decompression bomb aborts rather than exhausting the host
        apply_memory_guard()
        if args.analyze:
            sys.exit(run_analysis(args.analyze, policy, compiled, args.campaigns, args.recursive, args.json))
        if args.export_indicators:
            sys.exit(indicator_export.run_indicator_export(
                args.export_indicators, args.indicator_format or 'json', args.output))
        handle_pdf_analysis(args)
    except (EOFError, KeyboardInterrupt):
        print('Operation cancelled.', file=sys.stderr)
        sys.exit(1)
    finally:
        set_password(None)


if __name__ == '__main__':
    main()
