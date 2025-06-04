import hashlib
import os
import requests
from core.config_manager import get_api_key


REQUEST_TIMEOUT = 30
CHUNK_SIZE = 8192
MAX_INPUT_LENGTH = 1000

def _secure_clear_variable(var):
    if var is not None:
        try:
            del var
        except:
            pass

def get_confirmation(prompt: str) -> bool:
    full_prompt = f"{prompt} (Y/N, Q to quit): "
    while True:
        try:
            response = input(full_prompt).strip().upper()
            
            if len(response) > MAX_INPUT_LENGTH:
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

def calculate_file_hashes(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(CHUNK_SIZE):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
    except OSError as e:
        raise OSError(f"Error reading file {file_path}: {e}")
    
    return {
        'MD5': md5_hash.hexdigest(),
        'SHA-1': sha1_hash.hexdigest(),
        'SHA-256': sha256_hash.hexdigest()
    }

def check_virustotal(hash_value, silent=False):
    try:
        success, api_key = get_api_key()
        if not success or not api_key:
            if not silent:
                print("API key error: Unable to retrieve API key" if not success else "No API key available")
            return None

        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=True)
        response.raise_for_status()
        
        return response.json()
        
    except requests.exceptions.Timeout:
        if not silent:
            print("VirusTotal request timed out. Please try again later.")
    except requests.exceptions.HTTPError as e:
        if not silent:
            if e.response.status_code == 404:
                print("Hash not found in VirusTotal database.")
            else:
                print(f"VirusTotal API error: HTTP {e.response.status_code}")
    except requests.exceptions.RequestException:
        if not silent:
            print("Network error communicating with VirusTotal")
    except Exception:
        if not silent:
            print("Unexpected error checking hash with VirusTotal")
    return None

def _print_virustotal_results(stats):
    print("\nVirusTotal Results:")
    result_types = [
        'harmless', 'malicious', 'suspicious', 'undetected', 
        'timeout', 'confirmed-timeout', 'failure', 'type-unsupported'
    ]
    
    for result_type in result_types:
        count = stats.get(result_type, 0)
        display_name = result_type.replace('-', ' ').title()
        print(f"- {display_name}: {count}")

def main(file_path, silent=False, validate_pdf_file=None):
    if validate_pdf_file and not validate_pdf_file(file_path):
        return
        
    try:
        if not silent:
            print(f"\nCalculating hashes for {file_path}...")
        
        hashes = calculate_file_hashes(file_path)
        
        if not silent:
            for hash_type, hash_value in hashes.items():
                print(f"{hash_type}: {hash_value}")
        
        success, api_key = get_api_key()
        has_api_key = success and api_key
        
        if has_api_key:
            check_vt = True if silent else get_confirmation("\nWould you like to check this file with VirusTotal?")
        else:
            check_vt = False
            if not silent:
                print("\nVirusTotal API key not found.")
        

        if check_vt:
            if not silent:
                print("Checking SHA-256 hash with VirusTotal...")
            
            result = check_virustotal(hashes['SHA-256'], silent)
            if result and not silent:
                stats = result.get("data", {}).get("attributes", {}).get("stats", {})
                _print_virustotal_results(stats)
            elif not result and not silent:
                print("VirusTotal check failed. Please check your API key or try again later.")
            
    except FileNotFoundError as e:
        if not silent:
            print(f"Error: {e}")
    except Exception as e:
        if not silent:
            print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python hash_checker.py <pdf_file>")
        sys.exit(1)
    main(sys.argv[1])
