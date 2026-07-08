import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_INPUT_LENGTH = 1000

# HTTP is done with the standard library (no requests dependency). One shared,
# certificate-verifying TLS context is reused for every VirusTotal call.
HTTP_USER_AGENT = "PDFChecker"
_TLS_CONTEXT = ssl.create_default_context()


class HTTPStatusError(Exception):
    """Non-2xx HTTP response; carries the status code."""
    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.status = status


class HTTPTimeoutError(Exception):
    """The request exceeded its timeout."""


class HTTPNetworkError(Exception):
    """DNS/connection/TLS failure before a response was received."""


def http_request_json(url, headers=None, data=None, timeout=30):
    """Perform a JSON HTTP request with the standard library.

    GET when ``data`` is None, otherwise a form-encoded POST. TLS certificates
    are always verified. Returns the parsed JSON body (a dict) or raises one of
    HTTPStatusError / HTTPTimeoutError / HTTPNetworkError so callers can map
    failures the same way they did with requests.
    """
    request_headers = {"User-Agent": HTTP_USER_AGENT}
    if headers:
        request_headers.update(headers)

    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        request_headers.setdefault("Content-Type",
                                   "application/x-www-form-urlencoded")

    request = urllib.request.Request(
        url, data=body, headers=request_headers,
        method="POST" if data is not None else "GET")

    try:
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=_TLS_CONTEXT) as response:
            raw = response.read()
    except urllib.error.HTTPError as e:
        raise HTTPStatusError(e.code)
    except socket.timeout:
        raise HTTPTimeoutError()
    except urllib.error.URLError as e:
        # URLError wraps timeouts too, depending on where they fire
        if isinstance(e.reason, (socket.timeout, TimeoutError)):
            raise HTTPTimeoutError()
        raise HTTPNetworkError()
    except TimeoutError:
        raise HTTPTimeoutError()

    return json.loads(raw.decode("utf-8"))


# Best-effort virtual-memory cap for processes that parse untrusted PDFs, so a
# decompression bomb aborts with MemoryError instead of exhausting the host.
# Enforced on Linux via RLIMIT_AS; a silent no-op where the OS ignores it
# (notably macOS) or the resource module is missing (Windows).
DEFAULT_MEMORY_LIMIT_BYTES = 4 * 1024 * 1024 * 1024


def apply_memory_guard(limit_bytes=DEFAULT_MEMORY_LIMIT_BYTES):
    try:
        import resource
    except ImportError:
        return False
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        new_soft = limit_bytes if hard == resource.RLIM_INFINITY else min(limit_bytes, hard)
        resource.setrlimit(resource.RLIMIT_AS, (new_soft, hard))
        return True
    except (ValueError, OSError):
        return False


# doc.xref_object() serializes each object to text and is the most expensive
# repeated PyMuPDF call; when several analyzers run on the same document they
# share one sweep through this cache instead of each doing their own.
def build_xref_object_cache(doc):
    """Map each xref number to (object_text, error_message).

    Exactly one of the two tuple members is None: object_text on a read
    error, error_message on success.
    """
    cache = {}
    for xref_num in range(1, doc.xref_length()):
        try:
            cache[xref_num] = (doc.xref_object(xref_num), None)
        except Exception as e:
            cache[xref_num] = (None, str(e))
    return cache


def get_confirmation(prompt: str) -> bool:
    while True:
        try:
            response = input(f"{prompt} (Y/N, Q to quit): ").strip().upper()
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
