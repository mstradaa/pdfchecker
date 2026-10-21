"""URLhaus (abuse.ch) threat-intelligence client.

The API is synchronous: URL and payload lookups each consume exactly one POST
request.  Malware downloads are deliberately outside PDFChecker's enrichment
scope; reports only include metadata and URLhaus reference links.
"""
from typing import Dict, Optional

from .threat_intel import ProviderClient
from .utils import REQUEST_TIMEOUT, http_request_json

URL_QUERY_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
PAYLOAD_QUERY_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/payload/"


def summarize_url_result(result: Optional[Dict]) -> Dict:
    if not result:
        return {"status": "error"}
    query_status = result.get("query_status")
    if query_status == "no_results":
        return {"status": "not_found"}
    if query_status == "invalid_url":
        return {"status": "invalid", "query_status": query_status}
    if query_status != "ok":
        return {"status": "error", "query_status": query_status or "unknown"}
    return {
        "status": "ok",
        "url_status": result.get("url_status", "unknown"),
        "host": result.get("host"),
        "threat": result.get("threat"),
        "date_added": result.get("date_added"),
        "last_online": result.get("last_online"),
        "tags": result.get("tags") or [],
        "blacklists": result.get("blacklists") or {},
        "payload_count": len(result.get("payloads") or []),
        "reference": result.get("urlhaus_reference"),
    }


def summarize_payload_result(result: Optional[Dict]) -> Dict:
    if not result:
        return {"status": "error"}
    query_status = result.get("query_status")
    if query_status == "no_results":
        return {"status": "not_found"}
    if query_status in ("invalid_md5", "invalid_sha256"):
        return {"status": "invalid", "query_status": query_status}
    if query_status != "ok":
        return {"status": "error", "query_status": query_status or "unknown"}
    return {
        "status": "ok",
        "file_type": result.get("file_type"),
        "file_size": result.get("file_size"),
        "signature": result.get("signature"),
        "first_seen": result.get("firstseen"),
        "last_seen": result.get("lastseen"),
        "url_count": result.get("url_count"),
        "known_urls": len(result.get("urls") or []),
    }


def print_url_result(result: Optional[Dict]) -> None:
    summary = summarize_url_result(result)
    if summary["status"] == "not_found":
        print("   URLhaus: URL not found.")
    elif summary["status"] == "invalid":
        print("   URLhaus: the API rejected the URL as invalid.")
    elif summary["status"] != "ok":
        print("   URLhaus check failed. Please check your Auth-Key or try again later.")
    else:
        print("   URLhaus Results:")
        print(f"   - URL status: {summary['url_status']}")
        print(f"   - Threat: {summary['threat'] or 'Unknown'}")
        print(f"   - Host: {summary['host'] or 'Unknown'}")
        print(f"   - Payloads recorded: {summary['payload_count']}")
        if summary["tags"]:
            print(f"   - Tags: {', '.join(map(str, summary['tags']))}")
        if summary["reference"]:
            print(f"   - Reference: {summary['reference']}")


def print_payload_result(result: Optional[Dict]) -> None:
    summary = summarize_payload_result(result)
    if summary["status"] == "not_found":
        print("URLhaus: payload hash not found.")
    elif summary["status"] == "invalid":
        print("URLhaus: the API rejected the payload hash as invalid.")
    elif summary["status"] != "ok":
        print("URLhaus check failed. Please check your Auth-Key or try again later.")
    else:
        print("\nURLhaus Payload Results:")
        print(f"- Signature: {summary['signature'] or 'Unknown'}")
        print(f"- File type: {summary['file_type'] or 'Unknown'}")
        print(f"- First seen: {summary['first_seen'] or 'Unknown'}")
        print(f"- Last seen: {summary['last_seen'] or 'Unknown'}")
        print(f"- Associated URLs: {summary['url_count'] or summary['known_urls']}")


class URLhausClient(ProviderClient):
    provider = "urlhaus"
    label = "URLhaus"
    display_name = "URLhaus (abuse.ch)"
    summarize_url = staticmethod(summarize_url_result)
    summarize_file = staticmethod(summarize_payload_result)
    print_url_result = staticmethod(print_url_result)
    print_file_result = staticmethod(print_payload_result)

    def _query(self, endpoint, data, indicator, seen, silent):
        if not self._reserve(indicator, seen):
            return None
        try:
            return http_request_json(
                endpoint,
                headers={"Auth-Key": self.key},
                data=data,
                timeout=REQUEST_TIMEOUT,
            )
        except Exception as e:
            self._report_error(e, silent)
        return None

    def check_url(self, url: str, silent: bool = False) -> Optional[Dict]:
        return self._query(URL_QUERY_ENDPOINT, {"url": url}, url,
                           self.checked_urls, silent)

    # Payload (file) lookup by SHA-256
    def check_file(self, sha256_hash: str,
                   silent: bool = False) -> Optional[Dict]:
        normalized = sha256_hash.lower()
        return self._query(PAYLOAD_QUERY_ENDPOINT,
                           {"sha256_hash": normalized}, normalized,
                           self.checked_hashes, silent)
