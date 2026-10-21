"""VirusTotal client: URL scans and file-hash lookups within a shared call
budget, plus the report summaries and terminal output of their results."""
import time
from datetime import datetime, timezone
from typing import Dict, Optional

from .threat_intel import ProviderClient
from .utils import REQUEST_TIMEOUT, HTTPStatusError, http_request_json

API_URL = "https://www.virustotal.com/api/v3"
ANALYSIS_POLL_INTERVAL = 3
ANALYSIS_MAX_POLLS = 10
# A hash VirusTotal has never seen, as opposed to a failed request (None)
NOT_FOUND = {"error": {"code": "NotFoundError"}}

URL_RESULT_TYPES = ('harmless', 'malicious', 'suspicious', 'undetected')
FILE_RESULT_TYPES = URL_RESULT_TYPES + ('timeout', 'confirmed-timeout', 'failure', 'type-unsupported')


def _scan_date(attrs):
    last_scan_date = attrs.get("last_analysis_date")
    if last_scan_date:
        try:
            scan_datetime = datetime.fromtimestamp(last_scan_date, tz=timezone.utc)
            return scan_datetime.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            pass
    return None

# condense a file-hash lookup into template-ready data
def summarize_file_result(vt_report: Optional[Dict]) -> Dict:
    if not vt_report:
        return {"status": "error"}
    if vt_report.get('error', {}).get('code') == 'NotFoundError':
        return {"status": "not_found"}
    attrs = vt_report.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values())
    if total == 0:
        return {"status": "not_found"}

    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
    detections = [
        (scanner, scan_result.get('result', 'Unknown'))
        for scanner, scan_result in attrs.get("last_analysis_results", {}).items()
        if scan_result.get("category") in ("malicious", "suspicious")
    ]
    return {
        "status": "ok",
        "positives": positives,
        "total": total,
        "detections": detections,
        "scan_date": _scan_date(attrs),
    }

# condense a URL analysis into template-ready data
def summarize_url_result(vt_result: Optional[Dict]) -> Dict:
    if not vt_result:
        return {"status": "error"}

    attrs = vt_result.get("data", {}).get("attributes", {})
    if attrs.get("status") not in (None, "completed"):
        return {"status": "pending"}

    stats = attrs.get("stats", {})
    if sum(stats.values()) == 0:
        return {"status": "not_found"}

    return {
        "status": "ok",
        "stats": {name: stats.get(name, 0) for name in URL_RESULT_TYPES},
        "scan_date": _scan_date(attrs),
    }


def print_url_result(result: Optional[Dict]) -> None:
    if not result:
        print("   VirusTotal check failed. Please check your API key or try again later.")
        return
    attrs = result.get("data", {}).get("attributes", {})
    if attrs.get("status") not in (None, "completed"):
        print("   VirusTotal analysis still pending; try again later for results.")
        return
    stats = attrs.get("stats", {})
    print("   VirusTotal Results:")
    for name in URL_RESULT_TYPES:
        print(f"   - {name.title()}: {stats.get(name, 0)}")


def print_file_result(result: Optional[Dict]) -> None:
    if not result:
        print("VirusTotal check failed. Please check your API key or try again later.")
        return
    if result.get('error', {}).get('code') == 'NotFoundError':
        print("Hash not found in VirusTotal database.")
        return
    stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    print("\nVirusTotal Results:")
    for name in FILE_RESULT_TYPES:
        print(f"- {name.replace('-', ' ').title()}: {stats.get(name, 0)}")


class VirusTotalClient(ProviderClient):
    provider = "virustotal"
    label = display_name = "VirusTotal"
    summarize_url = staticmethod(summarize_url_result)
    summarize_file = staticmethod(summarize_file_result)
    print_url_result = staticmethod(print_url_result)
    print_file_result = staticmethod(print_file_result)

    def _request(self, url, data=None):
        return http_request_json(url, headers={"x-apikey": self.key}, data=data,
                                 timeout=REQUEST_TIMEOUT)

    def check_url(self, url: str, silent: bool = False) -> Optional[Dict]:
        if not self._reserve(url, self.checked_urls):
            return None
        try:
            submission = self._request(f"{API_URL}/urls", data={"url": url})
            result_url = f"{API_URL}/analyses/{submission['data']['id']}"
            # URL analyses are asynchronous: poll until the scan completes, the
            # API call budget runs out, or we give up
            result = None
            for attempt in range(ANALYSIS_MAX_POLLS):
                if not self.consume_api_call():
                    if not silent:
                        print("   API call limit reached while waiting for analysis results.")
                    break
                result = self._request(result_url)
                status = result.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    break
                if attempt < ANALYSIS_MAX_POLLS - 1:
                    time.sleep(ANALYSIS_POLL_INTERVAL)
            return result
        except Exception as e:
            self._report_error(e, silent)
        return None

    def check_file(self, sha256_hash: str, silent: bool = False) -> Optional[Dict]:
        normalized = sha256_hash.lower()
        if not self._reserve(normalized, self.checked_hashes):
            return None
        try:
            return self._request(f"{API_URL}/files/{normalized}")
        except HTTPStatusError as e:
            if e.status == 404:
                return dict(NOT_FOUND)
            self._report_error(e, silent)
        except Exception as e:
            self._report_error(e, silent)
        return None
