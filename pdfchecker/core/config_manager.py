# Manage the VirusTotal API key (env var or system keyring) and non-secret
# settings such as the API call limit (JSON config file).
import sys
import os
import json

import re
from pathlib import Path
from typing import Optional, Tuple
import keyring
import keyring.errors
from keyring.backends import fail

SERVICE_NAME = "PDFChecker"
ACCOUNT_NAME = "VirusTotalAPI"
API_LIMIT_KEY = "APILimit"  # legacy keyring entry, migrated to the config file
API_KEY_ENV_VARS = ("PDFCHECKER_VT_API_KEY", "VT_API_KEY")
API_LIMIT_CONFIG_KEY = "api_limit"
CONFIG_FILE_NAME = "config.json"
DEFAULT_API_LIMIT = 10
MIN_API_LIMIT = 1
MAX_API_LIMIT = 10000
API_KEY_LENGTH = 64
API_KEY_PATTERN = re.compile(r'^[0-9a-fA-F]{64}$')

# Backends that store secrets unencrypted (or not at all); a user-level
# keyring config can select these even when a real backend exists
_INSECURE_BACKEND_MODULES = ("keyrings.alt", "keyring.backends.fail", "keyring.backends.null")

_backend_verified = None
_platform_message = None
_cached_api_key = None

class ConfigError(Exception):
    pass

class KeyringError(ConfigError):
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

# check if secure backend is available
def _verify_secure_backend() -> bool:
    global _backend_verified

    if _backend_verified is not None:
        return _backend_verified
    try:
        backend = keyring.get_keyring()
        backend_module = type(backend).__module__
        if isinstance(backend, fail.Keyring) or backend_module.startswith(_INSECURE_BACKEND_MODULES):
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


def _get_api_key_from_env() -> Optional[str]:
    for env_var in API_KEY_ENV_VARS:
        api_key = os.environ.get(env_var, "").strip()
        if api_key:
            if not _validate_api_key(api_key):
                raise ConfigError(
                    f"{env_var} is set but is not a valid VirusTotal API key "
                    "(expected 64 hexadecimal characters)."
                )
            return api_key
    return None


# ---------------------------------------------------------------------------
# Config file (non-secret settings only; the API key never goes here)
# ---------------------------------------------------------------------------

def _get_config_path() -> Path:
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    return base / "pdfchecker" / CONFIG_FILE_NAME

def _load_config() -> dict:
    try:
        with open(_get_config_path(), "r", encoding="utf-8") as f:
            config = json.load(f)
        return config if isinstance(config, dict) else {}
    except (OSError, ValueError):
        return {}

def _save_config(config: dict) -> bool:
    config_path = _get_config_path()
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        return True
    except OSError:
        return False

# One-time migration of the API limit from the keyring, where older versions
# stored it; silent because a missing/locked keyring is expected on CI
def _migrate_api_limit_from_keyring() -> Optional[int]:
    try:
        limit_str = keyring.get_password(SERVICE_NAME, API_LIMIT_KEY)
        if not limit_str:
            return None
        limit = int(limit_str)
        if not (MIN_API_LIMIT <= limit <= MAX_API_LIMIT):
            return None
        try:
            keyring.delete_password(SERVICE_NAME, API_LIMIT_KEY)
        except Exception:
            pass
        return limit
    except Exception:
        return None



# get API key: environment variable first (CI/headless hosts have no
# keyring backend), then the system keyring
def get_api_key() -> Tuple[bool, str]:
    global _cached_api_key

    env_key = _get_api_key_from_env()
    if env_key:
        return True, env_key

    if _cached_api_key is not None:
        return True, _cached_api_key

    if not _verify_secure_backend():
        raise KeyringError("No secure keyring backend available")
    try:
        api_key = keyring.get_password(SERVICE_NAME, ACCOUNT_NAME)
        if not api_key:
            return False, "No API key is currently set."
        _cached_api_key = api_key
        return True, api_key
    except keyring.errors.KeyringError as e:
        error_msg = f"Error accessing system keyring: {str(e)}\n{_get_platform_specific_error_message()}"
        raise KeyringError(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error retrieving API key: {str(e)}"
        raise ConfigError(error_msg)

def set_api_key_secure(api_key: str) -> Tuple[bool, str]:
    global _cached_api_key

    if not _verify_secure_backend():
        return False, "No secure keyring backend available"

    if not api_key or not isinstance(api_key, str):
        return False, "Invalid API key format"

    if not _validate_api_key(api_key):
        return False, "Invalid VirusTotal API key format. Expected 64 hexadecimal characters."

    try:
        keyring.set_password(SERVICE_NAME, ACCOUNT_NAME, api_key)
        _cached_api_key = api_key
        message = "VirusTotal API key is now securely stored."
        env_vars_set = [v for v in API_KEY_ENV_VARS if os.environ.get(v, "").strip()]
        if env_vars_set:
            message += f" Note: {env_vars_set[0]} is set and takes precedence over the stored key."
        return True, message

    except keyring.errors.KeyringError as e:
        error_msg = f"Error accessing system keyring: {str(e)}\n{_get_platform_specific_error_message()}"
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error setting API key: {str(e)}"
        return False, error_msg

def remove_api_key() -> Tuple[bool, str]:
    global _cached_api_key

    if not _verify_secure_backend():
        return False, "No secure keyring backend available"

    existing_key = None
    try:
        existing_key = keyring.get_password(SERVICE_NAME, ACCOUNT_NAME)
        if not existing_key:
            return False, "No API key is currently set."

        keyring.delete_password(SERVICE_NAME, ACCOUNT_NAME)
        _cached_api_key = None
        return True, "VirusTotal API key successfully removed!"

    except keyring.errors.KeyringError as e:
        error_msg = f"Error accessing system keyring: {str(e)}\n{_get_platform_specific_error_message()}"
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error removing API key: {str(e)}"
        return False, error_msg


def get_api_limit() -> Tuple[bool, int]:
    config = _load_config()
    limit = config.get(API_LIMIT_CONFIG_KEY)

    if limit is None:
        migrated = _migrate_api_limit_from_keyring()
        limit = migrated if migrated is not None else DEFAULT_API_LIMIT
        # Persist so the keyring is not probed again on the next run
        config[API_LIMIT_CONFIG_KEY] = limit
        _save_config(config)
        return True, limit

    # Stored value may have been edited by hand or written by older versions
    if not isinstance(limit, int) or not (MIN_API_LIMIT <= limit <= MAX_API_LIMIT):
        return False, DEFAULT_API_LIMIT
    return True, limit

# store the API usage limit in the config file after validation (1-10000 x single call)
def set_api_limit(limit: int) -> Tuple[bool, str]:
    if not isinstance(limit, int):
        return False, "API limit must be an integer."
    if limit < MIN_API_LIMIT:
        return False, "API limit must be a positive integer."
    if limit > MAX_API_LIMIT:
        return False, f"API limit cannot exceed {MAX_API_LIMIT:,}."

    config = _load_config()
    config[API_LIMIT_CONFIG_KEY] = limit
    if not _save_config(config):
        return False, f"Error writing config file: {_get_config_path()}"
    return True, f"API call limit successfully set to {limit}."

def reset_backend_cache() -> None:
    global _backend_verified, _platform_message, _cached_api_key
    _backend_verified = None
    _platform_message = None
    _cached_api_key = None

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
