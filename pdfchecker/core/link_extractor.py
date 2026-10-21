from .coverage import check_coverage, print_coverage
from .qr_detector import url_payloads
from .terminal import safe_text
from .threat_intel import check_url, print_call_summary, selected_providers
from .url_discovery import discover_urls, has_mismatch
from .urlhaus import URLhausClient
from .virustotal import VirusTotalClient


def remove_protocol(url: str) -> str:
    if url.startswith(('http://', 'https://')):
        return url.split('://', 1)[1]
    return url

def defang_url(url: str) -> str:
    url = remove_protocol(url)
    return url.replace('.', '[.]')

# Coverage, link count and link-text warnings; returns the URLs found
def print_link_summary(findings):
    print_coverage({'urls': check_coverage('urls', findings)})
    links = [entry['url'] for entry in (findings or {}).get('urls', [])]
    if not links:
        print("No links found in the inspected content.")
        return links

    print(f"\n{len(links)} unique links found.")
    for entry in findings['urls']:
        if has_mismatch(entry):
            print(f"WARNING: displayed link text differs from destination: {safe_text(entry['url'])}")
    return links

def print_link_list(links, defanged, providers=()):
    for i, link in enumerate(links, 1):
        display_link = defang_url(link) if defanged else remove_protocol(link)
        print(f"\n{i}. {display_link}" if providers else f"{i}. {display_link}")
        check_url(providers, link)

def check_qr_urls(findings, defanged, providers):
    if not providers:
        return
    for url in url_payloads(findings):
        print(f"\n{defang_url(url) if defanged else url}")
        check_url(providers, url)

def main(pdf_path: str, defanged: bool = False):
    print(f"Extracting links from {pdf_path}...")
    try:
        findings = discover_urls(pdf_path)
    except Exception as e:
        print(f"Error extracting links: {str(e)}")
        findings = None

    links = print_link_summary(findings)
    if not links:
        return
    with selected_providers("these links", VirusTotalClient(), URLhausClient()) as providers:
        print_link_list(links, defanged, providers)
        print_call_summary(providers)
