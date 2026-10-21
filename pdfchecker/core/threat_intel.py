"""Shared plumbing for the optional reputation services (VirusTotal, URLhaus):
key loading, one call budget and duplicate tracking per service and
operation, choosing the services to use, and the terminal output of lookups."""
import contextlib

from .config_manager import (DEFAULT_API_LIMIT, PROVIDERS, ConfigError,
                             get_api_limit, get_provider_key)
from .utils import (HTTPNetworkError, HTTPStatusError, HTTPTimeoutError,
                    get_confirmation)


class ProviderClient:
    """One reputation service for one operation. The key, the call budget and
    the indicators already looked up are shared by every lookup and file, so
    the limit holds across a batch and each indicator is queried once."""
    provider = None      # config_manager.PROVIDERS key
    label = None         # service name in messages
    display_name = None  # service name in prompts

    def __init__(self, key=None, api_limit=DEFAULT_API_LIMIT):
        self.key = key
        self.api_limit = api_limit
        self.api_calls_made = 0
        self.skipped = 0
        self.checked_urls = set()
        self.checked_hashes = set()
        self._initialized = key is not None

    def initialize(self) -> bool:
        """Load the configured key and call limit once; False without a key."""
        if not self._initialized:
            self._initialized = True
            try:
                success, key = get_provider_key(self.provider)
            except ConfigError as e:
                print(f"Warning: Could not access {PROVIDERS[self.provider].label}: {e}")
                return False
            if success and key:
                self.key = key
                limit_success, self.api_limit = get_api_limit()
                if not limit_success:
                    print("Warning: Could not retrieve API limit, using default limit.")
        return self.key is not None

    # Reserve one call from the shared budget; False when the limit is exhausted
    def consume_api_call(self) -> bool:
        if self.api_calls_made >= self.api_limit:
            return False
        self.api_calls_made += 1
        return True

    def skip_reason(self, indicator, seen, noun="URL"):
        """Why `indicator` will not be looked up, or None if a call is available."""
        if indicator in seen:
            return f"{noun} already checked in this operation."
        if self.api_calls_made >= self.api_limit:
            return "API call limit reached."
        return None

    def _reserve(self, indicator, seen) -> bool:
        # Claimed before any network I/O: even an error response uses a call
        # and must not cause the same indicator to be retried repeatedly.
        if not self.key or self.skip_reason(indicator, seen):
            return False
        self.api_calls_made += 1
        seen.add(indicator)
        return True

    def _report_error(self, error, silent):
        if silent:
            return
        if isinstance(error, HTTPTimeoutError):
            print(f"{self.label} request timed out. Please try again later.")
        elif isinstance(error, HTTPStatusError):
            print(f"{self.label} API error: HTTP {error.status}")
        elif isinstance(error, HTTPNetworkError):
            print(f"Network error communicating with {self.label}")
        else:
            print(f"Unexpected error checking indicator with {self.label}")

    def reset(self) -> None:
        self.key = None
        self.api_calls_made = 0
        self.skipped = 0
        self.checked_urls.clear()
        self.checked_hashes.clear()
        self._initialized = False


@contextlib.contextmanager
def selected_providers(subject, *clients):
    """Ask once per configured service whether to check `subject` with it,
    yield the chosen clients, and forget every key afterwards."""
    chosen = []
    try:
        for client in clients:
            if not client.initialize():
                print(f"{PROVIDERS[client.provider].label} not found; "
                      f"{client.label} checks are skipped.")
            elif get_confirmation(f"\nWould you like to check {subject} with {client.display_name}?"):
                chosen.append(client)
        yield chosen
    finally:
        for client in clients:
            client.reset()


def check_url(providers, url):
    """Look `url` up with every chosen service, printing each result."""
    for client in providers:
        reason = client.skip_reason(url, client.checked_urls)
        if reason:
            client.skipped += 1
            print(f"   {client.label} check skipped: {reason}")
        else:
            print(f"   Checking with {client.label}...")
            client.print_url_result(client.check_url(url))


def check_file(providers, sha256):
    """Look a file's SHA-256 up with every chosen service, printing each result."""
    for client in providers:
        reason = client.skip_reason(sha256.lower(), client.checked_hashes, noun="File hash")
        if reason:
            client.skipped += 1
            print(f"{client.label} check skipped: {reason}")
        else:
            print(f"Checking SHA-256 hash with {client.label}...")
            client.print_file_result(client.check_file(sha256))


def print_call_summary(providers):
    for client in providers:
        skipped = f"; {client.skipped} lookup(s) skipped" if client.skipped else ""
        print(f"\nTotal {client.label} API calls made: {client.api_calls_made}{skipped}")
