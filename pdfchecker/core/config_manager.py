# Manage threat-intelligence API keys (env vars or system keyring) and non-secret
# settings such as the API call limit (JSON config file).
import json
import os
import re
import sys
from collections import namedtuple
from pathlib import Path
from typing import Optional, Tuple

import keyring
import keyring.errors
from keyring.backends import fail
from keyring.backends.chainer import ChainerBackend

SERVICE_NAME = "PDFChecker"
ACCOUNT_NAME = "VirusTotalAPI"
URLHAUS_ACCOUNT_NAME = "URLhausAuthKey"
API_LIMIT_KEY = "APILimit"  # legacy keyring entry, migrated to the config file
API_KEY_ENV_VARS = ("PDFCHECKER_VT_API_KEY", "VT_API_KEY")
URLHAUS_AUTH_KEY_ENV_VARS = ("PDFCHECKER_URLHAUS_AUTH_KEY", "URLHAUS_AUTH_KEY")
API_LIMIT_CONFIG_KEY = "api_limit"
CONFIG_FILE_NAME = "config.json"
DEFAULT_API_LIMIT = 10
MIN_API_LIMIT = 1
MAX_API_LIMIT = 10000
API_KEY_PATTERN = re.compile(r'[0-9a-fA-F]{64}')

# Backends that store secrets unencrypted (or not at all); a user-level
# keyring config can select these even when a real backend exists
_INSECURE_BACKEND_MODULES = ("keyrings.alt", "keyring.backends.fail", "keyring.backends.null")

_backend_verified = None
_cached_keys = {}

class ConfigError(Exception):
    pass

class KeyringError(ConfigError):
    pass


def _keyring_error_message(error) -> str:
    platform_help = {
        "win32": "Please ensure Windows Credential Manager is accessible",
        "darwin": "Please ensure Keychain Access is accessible",
    }.get(sys.platform,
          "Please ensure a keyring service (GNOME Keyring, KWallet) is installed and running")
    return f"Error accessing system keyring: {error}\n{platform_help}"

# check if secure backend is available
def _verify_secure_backend() -> bool:
    global _backend_verified

    if _backend_verified is not None:
        return _backend_verified
    try:
        backend = keyring.get_keyring()
        def secure(candidate, visited):
            if id(candidate) in visited:
                return False
            visited = visited | {id(candidate)}
            if isinstance(candidate, fail.Keyring) or type(candidate).__module__.startswith(_INSECURE_BACKEND_MODULES):
                return False
            if isinstance(candidate, ChainerBackend):
                children = candidate.backends
                return bool(children) and all(secure(child, visited) for child in children)
            return True
        if not secure(backend, set()):
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
    return isinstance(api_key, str) and API_KEY_PATTERN.fullmatch(api_key) is not None


def _validate_urlhaus_auth_key(auth_key: str) -> bool:
    """Accept URLhaus keys without assuming an undocumented fixed format.

    Header values must be printable ASCII and may not contain whitespace.  The
    official URLhaus documentation does not specify a key length or alphabet,
    so enforcing the VirusTotal key shape here would reject valid credentials.
    """
    return bool(
        isinstance(auth_key, str)
        and 1 <= len(auth_key) <= 512
        and all(33 <= ord(char) <= 126 for char in auth_key)
    )


# Everything that differs between the reputation services' keys
Provider = namedtuple("Provider", "label account env_vars validate expected")
PROVIDERS = {
    "virustotal": Provider("VirusTotal API key", ACCOUNT_NAME, API_KEY_ENV_VARS,
                           _validate_api_key, "64 hexadecimal characters"),
    "urlhaus": Provider("URLhaus Auth-Key", URLHAUS_ACCOUNT_NAME, URLHAUS_AUTH_KEY_ENV_VARS,
                        _validate_urlhaus_auth_key, "a printable value without whitespace"),
}


def _get_key_from_env(provider: str) -> Optional[str]:
    spec = PROVIDERS[provider]
    for env_var in spec.env_vars:
        key = os.environ.get(env_var, "").strip()
        if key:
            if not spec.validate(key):
                raise ConfigError(
                    f"{env_var} is set but is not a valid {spec.label} (expected {spec.expected})."
                )
            return key
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


# get a service key: environment variable first (CI/headless hosts have no
# keyring backend), then the system keyring
def get_provider_key(provider: str) -> Tuple[bool, str]:
    spec = PROVIDERS[provider]

    env_key = _get_key_from_env(provider)
    if env_key:
        return True, env_key

    if provider in _cached_keys:
        return True, _cached_keys[provider]

    if not _verify_secure_backend():
        raise KeyringError("No secure keyring backend available")
    try:
        key = keyring.get_password(SERVICE_NAME, spec.account)
    except keyring.errors.KeyringError as e:
        raise KeyringError(_keyring_error_message(e))
    except Exception as e:
        raise ConfigError(f"Unexpected error retrieving {spec.label}: {str(e)}")
    if not key:
        return False, f"No {spec.label} is currently set."
    if not spec.validate(key):
        return False, f"The stored {spec.label} is invalid."
    _cached_keys[provider] = key
    return True, key


def set_provider_key(provider: str, key: str) -> Tuple[bool, str]:
    spec = PROVIDERS[provider]

    if not _verify_secure_backend():
        return False, "No secure keyring backend available"
    if not spec.validate(key):
        return False, f"Invalid {spec.label} format. Expected {spec.expected}."
    try:
        keyring.set_password(SERVICE_NAME, spec.account, key)
    except keyring.errors.KeyringError as e:
        return False, _keyring_error_message(e)
    except Exception as e:
        return False, f"Unexpected error setting {spec.label}: {str(e)}"
    _cached_keys[provider] = key
    message = f"{spec.label} is now securely stored."
    env_vars_set = [v for v in spec.env_vars if os.environ.get(v, "").strip()]
    if env_vars_set:
        message += f" Note: {env_vars_set[0]} is set and takes precedence over the stored key."
    return True, message


def remove_provider_key(provider: str) -> Tuple[bool, str]:
    spec = PROVIDERS[provider]

    if not _verify_secure_backend():
        return False, "No secure keyring backend available"
    try:
        if not keyring.get_password(SERVICE_NAME, spec.account):
            return False, f"No {spec.label} is currently set."
        keyring.delete_password(SERVICE_NAME, spec.account)
    except keyring.errors.KeyringError as e:
        return False, _keyring_error_message(e)
    except Exception as e:
        return False, f"Unexpected error removing {spec.label}: {str(e)}"
    _cached_keys.pop(provider, None)
    return True, f"{spec.label} successfully removed!"


# Per-service shortcuts
def get_api_key() -> Tuple[bool, str]:
    return get_provider_key("virustotal")

def get_urlhaus_auth_key() -> Tuple[bool, str]:
    return get_provider_key("urlhaus")

def set_api_key_secure(api_key: str) -> Tuple[bool, str]:
    return set_provider_key("virustotal", api_key)

def set_urlhaus_auth_key_secure(auth_key: str) -> Tuple[bool, str]:
    return set_provider_key("urlhaus", auth_key)

def remove_api_key() -> Tuple[bool, str]:
    return remove_provider_key("virustotal")

def remove_urlhaus_auth_key() -> Tuple[bool, str]:
    return remove_provider_key("urlhaus")


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
    global _backend_verified
    _backend_verified = None
    _cached_keys.clear()
