# Manage VirusTotal API key and related settings using the system keyring.
import sys
import gc
import re
from typing import Tuple, Optional
import keyring
import keyring.errors
from keyring.backends import fail

SERVICE_NAME = "PDFChecker"
ACCOUNT_NAME = "VirusTotalAPI"
API_LIMIT_KEY = "APILimit"
DEFAULT_API_LIMIT = 10
API_KEY_LENGTH = 64
API_KEY_PATTERN = re.compile(r'^[0-9a-fA-F]{64}$')

_backend_verified = None
_platform_message = None

class ConfigError(Exception):
    pass

class KeyringError(ConfigError):
    pass

# remove sensitive data from memory
def _secure_clear_string(string_var: Optional[str]) -> None:
    if string_var is None:
        return
    try:
        if hasattr(string_var, '__del__'):
            del string_var
        gc.collect()
    except Exception:
        pass

def _get_platform_specific_error_message() -> str:
    global _platform_message
    
    if _platform_message is not None:
        return _platform_message
    
    platform_messages = {
        "win32": "Please ensure Windows Credential Manager is accessible",
        "darwin": "Please ensure Keychain Access is accessible",
    }
    
    _platform_message = platform_messages.get(
        sys.platform, 
        "Please ensure a keyring service (GNOME Keyring, KWallet) is installed and running"
    )
    return _platform_message

# check uf secure backend is available
def _verify_secure_backend() -> bool:
    global _backend_verified
    
    if _backend_verified is not None:
        return _backend_verified
    try:
        backend = keyring.get_keyring()
        if isinstance(backend, fail.Keyring):
            print("Error: No secure keyring backend available. Falling back to plaintext storage is not allowed.")
            _backend_verified = False
            return False
        _backend_verified = True
        return True
        
    except Exception as e:
        print(f"Error verifying keyring backend: {str(e)}")
        _backend_verified = False
        return False

# validate VT API key format
def _validate_api_key(api_key: str) -> bool:
    return bool(api_key and len(api_key) == API_KEY_LENGTH and API_KEY_PATTERN.match(api_key))

class _SecureApiKeyManager:
    def __init__(self, api_key: Optional[str]):
        self.api_key = api_key
    def __enter__(self):
        return self.api_key
    def __exit__(self, exc_type, exc_val, exc_tb):
        _secure_clear_string(self.api_key)

# get API key from keyring
def get_api_key() -> Tuple[bool, str]:
    if not _verify_secure_backend():
        raise KeyringError("No secure keyring backend available")
    try:
        with _SecureApiKeyManager(keyring.get_password(SERVICE_NAME, ACCOUNT_NAME)) as api_key:
            if not api_key:
                return False, "No API key is currently set."
            return True, api_key
        
    except keyring.errors.KeyringError as e:
        error_msg = f"Error accessing system keyring: {str(e)}\n{_get_platform_specific_error_message()}"
        raise KeyringError(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error retrieving API key: {str(e)}"
        raise ConfigError(error_msg)

def set_api_key_secure(api_key: str) -> Tuple[bool, str]:
    if not _verify_secure_backend():
        return False, "No secure keyring backend available"
        
    if not api_key or not isinstance(api_key, str):
        _secure_clear_string(api_key)
        return False, "Invalid API key format"
    
    if not _validate_api_key(api_key):
        _secure_clear_string(api_key)
        return False, "Invalid VirusTotal API key format. Expected 64 hexadecimal characters."
    
    try:
        with _SecureApiKeyManager(api_key):
            keyring.set_password(SERVICE_NAME, ACCOUNT_NAME, api_key)
            return True, "VirusTotal API key is now securely stored."
            
    except keyring.errors.KeyringError as e:
        error_msg = f"Error accessing system keyring: {str(e)}\n{_get_platform_specific_error_message()}"
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error setting API key: {str(e)}"
        return False, error_msg

def remove_api_key() -> Tuple[bool, str]:
    if not _verify_secure_backend():
        return False, "No secure keyring backend available"
        
    existing_key = None
    try:
        existing_key = keyring.get_password(SERVICE_NAME, ACCOUNT_NAME)
        if not existing_key:
            return False, "No API key is currently set."
            
        keyring.delete_password(SERVICE_NAME, ACCOUNT_NAME)
        return True, "VirusTotal API key successfully removed!"
        
    except keyring.errors.KeyringError as e:
        error_msg = f"Error accessing system keyring: {str(e)}\n{_get_platform_specific_error_message()}"
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error removing API key: {str(e)}"
        return False, error_msg
    finally:
        _secure_clear_string(existing_key)

def get_api_limit() -> Tuple[bool, int]:
    if not _verify_secure_backend():
        return False, DEFAULT_API_LIMIT
    try:
        limit_str = keyring.get_password(SERVICE_NAME, API_LIMIT_KEY)
        if not limit_str:
            return True, DEFAULT_API_LIMIT
        limit = int(limit_str)
        return True, limit
        
    except (keyring.errors.KeyringError, ValueError):
        return False, DEFAULT_API_LIMIT

# store the API usage limit in the keyring after validation (1-10000 x single call)
def set_api_limit(limit: int) -> Tuple[bool, str]:
    if not _verify_secure_backend():
        return False, "No secure keyring backend available"
    if not isinstance(limit, int):
        return False, "API limit must be an integer."
    if limit < 1:
        return False, "API limit must be a positive integer."
    if limit > 10000:
        return False, "API limit cannot exceed 10,000."
    try:
        keyring.set_password(SERVICE_NAME, API_LIMIT_KEY, str(limit))
        return True, f"API call limit successfully set to {limit}."
        
    except keyring.errors.KeyringError as e:
        error_msg = f"Error accessing system keyring: {str(e)}\n{_get_platform_specific_error_message()}"
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error setting API limit: {str(e)}"
        return False, error_msg

def reset_backend_cache() -> None:
    global _backend_verified, _platform_message
    _backend_verified = None
    _platform_message = None

def get_config_status() -> dict:
    try:
        has_api_key = get_api_key()[0]
        api_limit_success, api_limit = get_api_limit()
        backend_ok = _verify_secure_backend()
        
        return {
            "backend_available": backend_ok,
            "api_key_set": has_api_key,
            "api_limit": api_limit if api_limit_success else DEFAULT_API_LIMIT,
            "backend_type": type(keyring.get_keyring()).__name__ if backend_ok else "None"
        }
    except Exception as e:
        return {
            "backend_available": False,
            "api_key_set": False,
            "api_limit": DEFAULT_API_LIMIT,
            "backend_type": "Error",
            "error": str(e)
        } 