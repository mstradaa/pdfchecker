import fitz
import requests
import os
from typing import List, Dict, Optional, Tuple, Set
from .config_manager import get_api_key, get_api_limit
from .utils import get_confirmation

REQUEST_TIMEOUT = 30



class LinkExtractor:
    def __init__(self):
        self.checked_urls: Set[str] = set()
        self.api_calls_made = 0
        self.api_key: Optional[str] = None
        self.api_limit: int = 10
        self._api_initialized = False
    
    def _initialize_api_config(self) -> bool:
        if self._api_initialized:
            return self.api_key is not None
            
        try:
            success, api_key = get_api_key()
            if success and api_key:
                self.api_key = api_key
                success, api_limit = get_api_limit()
                if success:
                    self.api_limit = api_limit
                else:
                    print("Warning: Could not retrieve API limit, using default limit.")
                    self.api_limit = 10
            else:
                self.api_key = None
            self._api_initialized = True
            return self.api_key is not None
            
        except Exception:
            self._api_initialized = True
            return False
    
    def extract_links_from_pdf(self, pdf_path: str) -> List[str]:
        links = []
        doc = None
        original_stats = None
        try:
            # Capture original file timestamps
            original_stats = os.stat(pdf_path)
            doc = fitz.open(pdf_path)
            for page in doc:
                link_list = page.get_links()
                for link in link_list:
                    if link["kind"] == fitz.LINK_URI:
                        links.append(link["uri"])
        except Exception as e:
            print(f"Error extracting links: {str(e)}")
        finally:
            if doc:
                doc.close()
            if original_stats:
                try:
                    os.utime(pdf_path, (original_stats.st_atime, original_stats.st_mtime))
                except Exception:
                    pass
        
        seen = set()
        unique_links = []
        for link in links:
            if link not in seen:
                seen.add(link)
                unique_links.append(link)
        return unique_links
    
    def check_link_virustotal(self, url: str) -> Optional[Dict]:
        if url in self.checked_urls:
            return None
        
        if self.api_calls_made >= self.api_limit:
            return None
        
        if not self.api_key:
            return None
        try:
            headers = {"x-apikey": self.api_key}
            submit_url = "https://www.virustotal.com/api/v3/urls"
            response = requests.post(
                submit_url, 
                headers=headers, 
                data={"url": url}, 
                timeout=REQUEST_TIMEOUT, 
                verify=True
            )
            response.raise_for_status()
            
            analysis_id = response.json()["data"]["id"]
            result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            response = requests.get(result_url, headers=headers, timeout=REQUEST_TIMEOUT, verify=True)
            response.raise_for_status()
            result = response.json()
            self.api_calls_made += 1
            self.checked_urls.add(url)
            return result
            
        except requests.exceptions.Timeout:
            print("VirusTotal request timed out. Please try again later.")
        except requests.exceptions.HTTPError as e:
            print(f"VirusTotal API error: HTTP {e.response.status_code}")
        except requests.exceptions.RequestException:
            print("Network error communicating with VirusTotal")
        except Exception:
            print("Unexpected error checking URL with VirusTotal")
        
        return None
    
    def reset(self):
        self.checked_urls.clear()
        self.api_calls_made = 0

        self.api_key = None
        self._api_initialized = False

def remove_protocol(url: str) -> str:
    if url.startswith(('http://', 'https://')):
        return url.split('://', 1)[1]
    return url

def defang_url(url: str) -> str:
    url = remove_protocol(url)
    return url.replace('.', '[.]')

def main(pdf_path: str, defanged: bool = False, validate_pdf_file=None):
    if validate_pdf_file and not validate_pdf_file(pdf_path):
        return
    extractor = LinkExtractor()
    
    try:
        print(f"Extracting links from {pdf_path}...")
        links = extractor.extract_links_from_pdf(pdf_path)
    
        if not links:
            print("No links found in the PDF.")
            return
        
        print(f"\n{len(links)} unique links found.")
        
        check_vt = False
        if extractor._initialize_api_config() and extractor.api_key:
            check_vt = get_confirmation("\nWould you like to check these links with VirusTotal?")
        
        if check_vt:
            print(f"\nChecking links with VirusTotal (limit: {extractor.api_limit})...")    
            checked_count = 0
            skipped_count = 0
            duplicate_count = 0
            for i, link in enumerate(links, 1):
                display_link = remove_protocol(link)
                if defanged:
                    display_link = defang_url(link)
                print(f"\n{i}. {display_link}")
                
                if extractor.api_calls_made >= extractor.api_limit:
                    if skipped_count == 0:
                        print("\n---- API call limit reached ----")
                    skipped_count += 1
                    print("   Skipped due to API limit.")
                    continue
                
                if link in extractor.checked_urls:
                    print("   URL already checked in this operation.")
                    duplicate_count += 1
                    continue
                
                print("   Checking with VirusTotal...")
                result = extractor.check_link_virustotal(link)
                
                if result:
                    stats = result.get("data", {}).get("attributes", {}).get("stats", {})
                    print("   VirusTotal Results:")
                    print(f"   - Harmless: {stats.get('harmless', 0)}")
                    print(f"   - Malicious: {stats.get('malicious', 0)}")
                    print(f"   - Suspicious: {stats.get('suspicious', 0)}")
                    print(f"   - Undetected: {stats.get('undetected', 0)}")
                    checked_count += 1
                else:
                    print("   VirusTotal check failed. Please check your API key or try again later.")
            
            print(f"\nAPI Call Summary:")
            print(f"- Total links found: {len(links)}")
            print(f"- Links checked with VirusTotal: {checked_count}")
            if duplicate_count > 0:
                print(f"- Duplicate links skipped: {duplicate_count}")
            if skipped_count > 0:
                print(f"- Links skipped due to API limit: {skipped_count}")
            print(f"- Total API calls made: {extractor.api_calls_made}")
            
        else:
            for i, link in enumerate(links, 1):
                display_link = remove_protocol(link)
                if defanged:
                    display_link = defang_url(link)
                print(f"{i}. {display_link}")
            
            if not extractor._initialize_api_config() or not extractor.api_key:
                print("\nVirusTotal API key not found. Please set your API key to use this feature.")
            else:
                print("\nVirusTotal check skipped.")
    
    finally:
        extractor.reset()

def extract_links(pdf_path: str) -> List[str]:
    extractor = LinkExtractor()
    try:
        return extractor.extract_links_from_pdf(pdf_path)
    finally:
        extractor.reset()

def check_link_virustotal(url: str) -> Optional[Dict]:
    extractor = LinkExtractor()
    try:
        if not extractor._initialize_api_config():
            return None
        return extractor.check_link_virustotal(url)
    finally:
        extractor.reset()