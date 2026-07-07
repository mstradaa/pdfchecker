import fitz
import re
import logging
import os


MAX_JS_CONTENT_SIZE = 50000
PREVIEW_CONTENT_SIZE = 500
MAX_EXTRACTION_ERRORS = 10

logger = logging.getLogger(__name__)


JS_OBJECT_PATTERNS = [
    re.compile(r'/JavaScript\s*\(\s*([^)]+)\s*\)', re.IGNORECASE | re.DOTALL),
    re.compile(r'/JS\s*\(\s*([^)]+)\s*\)', re.IGNORECASE | re.DOTALL),
    re.compile(r'/JavaScript\s*<<[^>]*>>', re.IGNORECASE | re.DOTALL),
    re.compile(r'/JS\s*<<[^>]*>>', re.IGNORECASE | re.DOTALL)
]

JS_CONTENT_PATTERNS = [
    re.compile(r'javascript:\s*([^;]+)', re.IGNORECASE | re.DOTALL),
    re.compile(r'eval\s*\(\s*([^)]+)\s*\)', re.IGNORECASE | re.DOTALL),
    re.compile(r'function\s+\w+\s*\([^)]*\)\s*{[^}]*}', re.IGNORECASE | re.DOTALL),
]

OBFUSCATION_PATTERNS = [
    re.compile(r'String\.fromCharCode\(', re.IGNORECASE),
    re.compile(r'eval\s*\(', re.IGNORECASE),
    re.compile(r'unescape\s*\(', re.IGNORECASE),
    re.compile(r'\\x[0-9a-fA-F]{2}'),
    re.compile(r'\\u[0-9a-fA-F]{4}'),
    re.compile(r'%[0-9a-fA-F]{2}'),
]

LONG_STRING_PATTERN = re.compile(r'"[^"]{100,}"')


HIGH_SEVERITY_KEYWORDS = frozenset([
    'eval', 'exploit', 'shellcode', 'ActiveXObject', 'Shell.Application',
    'this.exportDataObject', 'this.mailDoc', 'Collab.collectEmailInfo'
])
MEDIUM_SEVERITY_KEYWORDS = frozenset([
    'unescape', 'fromCharCode', 'document.write', 'WScript.Shell',
    'payload', 'CVE-', 'overflow', 'heap', 'spray', 'ROP', 'gadget', 'bypass',
    'app.launchURL', 'app.execMenuItem', 'Collab.storeData'
])

def extract_javascript_from_pdf(pdf_path, validate_pdf_file=None):
    if validate_pdf_file and not validate_pdf_file(pdf_path):
        return None
    
    # Capture original file timestamps
    original_stats = None
    try:
        original_stats = os.stat(pdf_path)
    except Exception:
        pass

    js_findings = JSFindings()
    
    try:
        with fitz.open(pdf_path) as doc:

            _check_document_javascript(doc, js_findings)
            _check_page_javascript(doc, js_findings)
            _check_form_javascript(doc, js_findings)
            _check_annotation_javascript(doc, js_findings)


            if js_findings.javascript_sources:
                js_findings.suspicious_patterns = _analyze_suspicious_patterns(js_findings.javascript_sources)

    except Exception as e:
        logger.error(f"Error extracting JavaScript from PDF: {str(e)}")
        js_findings.add_error(f"General extraction error: {str(e)}")
    finally:
        # Restore original access and modification times
        if original_stats:
            try:
                os.utime(pdf_path, (original_stats.st_atime, original_stats.st_mtime))
            except Exception:
                pass
    
    return js_findings.to_dict()


class JSFindings:
    
    def __init__(self):
        self.javascript_sources = []
        self.suspicious_patterns = []
        self.extraction_errors = []
        self._error_count = 0
    
    def add_javascript(self, source, location, content, full_content=None):
        if full_content is None:
            full_content = content
        

        if len(full_content) > MAX_JS_CONTENT_SIZE:
            full_content = full_content[:MAX_JS_CONTENT_SIZE] + "... [Content truncated for security]"
        

        preview = full_content[:PREVIEW_CONTENT_SIZE]
        if len(full_content) > PREVIEW_CONTENT_SIZE:
            preview += "..."
        
        self.javascript_sources.append({
            "source": source,
            "location": location,
            "content": preview,
            "full_content": full_content
        })
    
    def add_error(self, error_msg):
        if self._error_count < MAX_EXTRACTION_ERRORS:
            self.extraction_errors.append(error_msg)
            self._error_count += 1
    
    @property
    def javascript_count(self):
        return len(self.javascript_sources)
    
    @property
    def has_javascript(self):
        return self.javascript_count > 0
    
    def to_dict(self):
        return {
            "has_javascript": self.has_javascript,
            "javascript_count": self.javascript_count,
            "javascript_sources": self.javascript_sources,
            "suspicious_patterns": self.suspicious_patterns,
            "extraction_errors": self.extraction_errors
        }

# search for JavaScript in document objects, labeling open actions separately
def _check_document_javascript(doc, findings):
    try:

        xref_length = doc.xref_length()
        for xref_num in range(1, xref_length):
            try:
                obj = doc.xref_object(xref_num)

                if "/JavaScript" in obj or "/JS" in obj:
                    js_content = _extract_js_from_object(doc, obj, xref_num)
                    if js_content:
                        if "/OpenAction" in obj:
                            source = "Open Action"
                            location = f"Document Open Action (XRef {xref_num})"
                        else:
                            source = "Document Catalog"
                            location = f"XRef {xref_num}"
                        findings.add_javascript(source, location, js_content, js_content)
            except Exception as e:
                logger.debug(f"Error checking xref {xref_num}: {str(e)}")
                findings.add_error(f"XRef {xref_num} error: {str(e)}")

    except Exception as e:
        findings.add_error(f"Document JavaScript check error: {str(e)}")

# search for JavaScript in the page content
def _check_page_javascript(doc, findings):
    try:
        for page_num, page in enumerate(doc):
            try:
                xrefs = page.get_contents()
                if not xrefs:
                    continue
                for xref in xrefs:
                    try:
                        stream = doc.xref_stream(xref)
                        if not stream:
                            continue
                        content_str = stream.decode('utf-8', errors='ignore')
                        if 'JavaScript' in content_str or '/JS' in content_str:
                            js_content = _extract_js_from_content(content_str)
                            if js_content:
                                findings.add_javascript(
                                    "Page Content",
                                    f"Page {page_num + 1}",
                                    js_content,
                                    js_content
                                )
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"Error checking page {page_num}: {str(e)}")
    except Exception as e:
        findings.add_error(f"Page JavaScript check error: {str(e)}")

# search for JavaScript in the form fields
def _check_form_javascript(doc, findings):
    try:

        script_attrs = [
            ('script', 'general script'),
            ('script_stroke', 'keystroke script'),
            ('script_format', 'format script'),
            ('script_change', 'value change script'),
            ('script_calc', 'calculation script'),
            ('script_blur', 'blur script'),
            ('script_focus', 'focus script')
        ]
        
        for page_num, page in enumerate(doc):
            try:
                widgets = page.widgets()
                if not widgets:
                    continue
                    
                for widget in widgets:
                    try:
                        field_name = getattr(widget, 'field_name', 'Unknown field')
                        

                        for attr_name, description in script_attrs:
                            if hasattr(widget, attr_name):
                                script_content = getattr(widget, attr_name)
                                if script_content:
                                    content_desc = f"{description}: {script_content}"
                                    findings.add_javascript(
                                        "Form Field",
                                        f"Page {page_num + 1}, Field: {field_name}",
                                        content_desc,
                                        script_content
                                    )
                                    
                    except Exception as e:
                        logger.debug(f"Error checking form field on page {page_num}: {str(e)}")
                        
            except Exception as e:
                logger.debug(f"Error accessing widgets on page {page_num}: {str(e)}")
                
    except Exception as e:
        findings.add_error(f"Form JavaScript check error: {str(e)}")

# search for JavaScript in the annotations
def _check_annotation_javascript(doc, findings):
    try:
        for page_num, page in enumerate(doc):
            try:
                annotations = page.annots()
                if not annotations:
                    continue
                    
                for annot in annotations:
                    try:
                        # JavaScript lives in annotation actions (/A << /S /JavaScript /JS ... >>),
                        # not in a dedicated annotation type, so inspect the raw object
                        xref = annot.xref
                        if xref:
                            obj_str = doc.xref_object(xref)
                            if '/JavaScript' in obj_str or '/JS' in obj_str:
                                js_content = _extract_js_from_object(doc, obj_str, xref)
                                findings.add_javascript(
                                    "Annotation",
                                    f"Page {page_num + 1}, Annotation",
                                    js_content if js_content else "JavaScript reference detected in annotation",
                                    js_content if js_content else obj_str
                                )

                    except Exception as e:
                        logger.debug(f"Error checking annotation on page {page_num}: {str(e)}")
                        
            except Exception as e:
                logger.debug(f"Error checking annotations on page {page_num}: {str(e)}")
                
    except Exception as e:
        findings.add_error(f"Annotation JavaScript check error: {str(e)}")

def _extract_js_from_object(doc, obj_str, xref_num):
    try:

        for pattern in JS_OBJECT_PATTERNS:
            matches = pattern.findall(obj_str)
            if matches:
                return ' '.join(matches)
        

        try:
            stream_content = doc.xref_stream(xref_num)
            if stream_content:
                return stream_content.decode('utf-8', errors='ignore')
        except:
            pass
            
        return None
        
    except Exception as e:
        logger.debug(f"Error extracting JS from object {xref_num}: {str(e)}")
        return None


def _extract_js_from_content(content_str):
    try:
        js_content = []

        for pattern in JS_CONTENT_PATTERNS:
            matches = pattern.findall(content_str)
            js_content.extend(matches)
        
        return ' | '.join(js_content) if js_content else None
        
    except Exception as e:
        logger.debug(f"Error extracting JS from content: {str(e)}")
        return None

# flag suspicious keywor or obfuscation
def _analyze_suspicious_patterns(js_sources):
    suspicious_patterns = []
    
    for js_source in js_sources:
        content = js_source.get('full_content', '')
        content_lower = content.lower()
        location = js_source.get('location', 'Unknown')
        

        for keyword in HIGH_SEVERITY_KEYWORDS:
            if keyword.lower() in content_lower:
                suspicious_patterns.append({
                    "type": "Suspicious Keyword",
                    "pattern": keyword,
                    "location": location,
                    "severity": "High"
                })
        
        for keyword in MEDIUM_SEVERITY_KEYWORDS:
            if keyword.lower() in content_lower:
                suspicious_patterns.append({
                    "type": "Suspicious Keyword", 
                    "pattern": keyword,
                    "location": location,
                    "severity": "Medium"
                })
        

        for pattern in OBFUSCATION_PATTERNS:
            if pattern.search(content):
                suspicious_patterns.append({
                    "type": "Obfuscation Pattern",
                    "pattern": pattern.pattern,
                    "location": location,
                    "severity": "High"
                })
        

        long_strings = LONG_STRING_PATTERN.findall(content)
        if long_strings:
            suspicious_patterns.append({
                "type": "Long String",
                "pattern": f"String of length {len(long_strings[0])} characters",
                "location": location,
                "severity": "Medium"
            })
    
    return suspicious_patterns

def print_javascript_findings(js_findings):
    if not js_findings:
        print("No JavaScript analysis results available.")
        return
    
    print(f"\n=== JavaScript Analysis Results ===")
    print(f"JavaScript Detected: {'Yes' if js_findings['has_javascript'] else 'No'}")
    print(f"JavaScript Objects Found: {js_findings['javascript_count']}")
    
    if js_findings['javascript_sources']:
        print(f"\n--- JavaScript Sources ---")
        for i, source in enumerate(js_findings['javascript_sources'], 1):
            print(f"{i}. Source: {source['source']}")
            print(f"   Location: {source['location']}")
            print(f"   Content Preview: {source['content']}")
            print()
    
    if js_findings['suspicious_patterns']:
        print(f"\n--- Suspicious Patterns Detected ---")
        for pattern in js_findings['suspicious_patterns']:
            print(f"WARNING:  {pattern['type']}: {pattern['pattern']}")
            print(f"   Location: {pattern['location']}")
            print(f"   Severity: {pattern['severity']}")
            print()
    
    if js_findings['extraction_errors']:
        print(f"\n--- Extraction Errors ---")
        for error in js_findings['extraction_errors']:
            print(f"ERROR: {error}") 