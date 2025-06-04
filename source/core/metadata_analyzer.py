import os
import fitz
from datetime import datetime, timezone
import logging
import re

MAX_METADATA_SIZE = 10000
MAX_STRING_LENGTH = 1000

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PDF_VERSION_PATTERN = re.compile(r'PDF-[\d.]+', re.IGNORECASE)
PDFA_PART_PATTERN = re.compile(r'<pdfaid:part>([^<]*)</pdfaid:part>', re.IGNORECASE)
PDFA_CONFORMANCE_PATTERN = re.compile(r'<pdfaid:conformance>([^<]*)</pdfaid:conformance>', re.IGNORECASE)
PDFX_PATTERNS = [
    re.compile(r'pdfxid:GTS_PDFXVersion="([^"]*)"', re.IGNORECASE),
    re.compile(r'<pdfxid:GTS_PDFXVersion>([^<]*)</pdfxid:GTS_PDFXVersion>', re.IGNORECASE),
    re.compile(r'GTS_PDFXConformance="([^"]*)"', re.IGNORECASE),
    re.compile(r'<GTS_PDFXConformance>([^<]*)</GTS_PDFXConformance>', re.IGNORECASE)
]

def safe_get_attr(obj, attr_name, default="Not available", *args, **kwargs):
    try:
        value = getattr(obj, attr_name)
        if callable(value):
            return value(*args, **kwargs)
        return value
    except (AttributeError, Exception) as e:
        logger.debug(f"Failed to get attribute {attr_name}: {str(e)}")
        return default

def _parse_pdf_date(date_str):
    if not date_str:
        return None
    try:
        if date_str.startswith('D:'):
            date_str = date_str[2:]
        
        if len(date_str) < 14:
            return None
            
        year = int(date_str[:4])
        month = int(date_str[4:6])
        day = int(date_str[6:8])
        hour = int(date_str[8:10])
        minute = int(date_str[10:12])
        second = int(date_str[12:14])
        
        return f"{datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)} UTC"
    except (ValueError, IndexError) as e:
        logger.debug(f"Failed to parse date '{date_str}': {str(e)}")
        return None

def detect_pdf_format(doc, xmp_cache=None):
    format_info = {
        "format": "PDF",
        "version": "Unknown",
        "is_pdfa": False,
        "is_pdfx": False,
        "pdfa_version": None,
        "pdfx_version": None
    }
    
    try:
        metadata = doc.metadata
        
        if metadata.get('format'):
            format_info["format"] = metadata['format']

            version_match = PDF_VERSION_PATTERN.search(metadata['format'])
            if version_match:
                format_info["version"] = version_match.group(0)
        
        xmp = xmp_cache if xmp_cache is not None else doc.get_xml_metadata()
        
        if xmp:
            pdfa_part_match = PDFA_PART_PATTERN.search(xmp)
            pdfa_conformance_match = PDFA_CONFORMANCE_PATTERN.search(xmp)
            
            if pdfa_part_match or pdfa_conformance_match:
                format_info["is_pdfa"] = True
                if pdfa_part_match and pdfa_conformance_match:
                    part = pdfa_part_match.group(1)
                    conformance = pdfa_conformance_match.group(1)
                    format_info["pdfa_version"] = f"PDF/A-{part}{conformance}"
                elif pdfa_part_match:
                    format_info["pdfa_version"] = f"PDF/A-{pdfa_part_match.group(1)}"
            
            for pattern in PDFX_PATTERNS:
                match = pattern.search(xmp)
                if match:
                    format_info["is_pdfx"] = True
                    format_info["pdfx_version"] = match.group(1)
                    break
        
        for key, value in metadata.items():
            key_lower = key.lower()
            value_str = str(value).lower()
            if 'pdfa' in key_lower or 'pdf/a' in value_str:
                format_info["is_pdfa"] = True
            elif 'pdfx' in key_lower or 'pdf/x' in value_str:
                format_info["is_pdfx"] = True
                        
    except Exception as e:
        logger.debug(f"Error detecting PDF format: {str(e)}")
    
    return format_info

def get_human_readable_file_permissions(mode):
    perms = []
    for i in range(3):
        perm = ''
        perm += 'r' if mode & (0o400 >> (i * 3)) else '-'
        perm += 'w' if mode & (0o200 >> (i * 3)) else '-'
        perm += 'x' if mode & (0o100 >> (i * 3)) else '-'
        perms.append(perm)
    return ''.join(perms)

def get_human_readable_pdf_permissions(perms):
    if perms is None:
        return "Not available"
    permission_map = [
        (0x0004, "Print"),
        (0x0008, "Modify"), 
        (0x0010, "Copy"),
        (0x0020, "Annotate")
    ]
    
    permissions = [name for flag, name in permission_map if perms & flag]
    return ", ".join(permissions) if permissions else "No permissions"

def get_file_system_attributes(file_path, file_stats_param=None):
    try:
        stats_to_use = file_stats_param
        if stats_to_use is None:
            stats_to_use = os.stat(file_path)
        
        return {
            "size": f"{stats_to_use.st_size} bytes",
            "created": f"{datetime.fromtimestamp(stats_to_use.st_ctime, tz=timezone.utc)} UTC",
            "last_modified": f"{datetime.fromtimestamp(stats_to_use.st_mtime, tz=timezone.utc)} UTC",
            "last_accessed": f"{datetime.fromtimestamp(stats_to_use.st_atime, tz=timezone.utc)} UTC",
            "permissions_octal": oct(stats_to_use.st_mode)[-3:],
            "permissions_readable_octal": get_human_readable_file_permissions(stats_to_use.st_mode)
        }
    except Exception as e:
        logger.error(f"Error getting file system attributes for {file_path}: {str(e)}")
        error_value = "Error retrieving attribute"
        return {
            "size": error_value,
            "created": error_value,
            "last_modified": error_value,
            "last_accessed": error_value,
            "permissions_octal": error_value,
            "permissions_readable_octal": error_value
        }

def _analyze_pages_combined(doc):
    page_analysis = {
        "has_form_fields": False,
        "has_images": False,
        "has_text": False,
        "has_javascript": False,
        "first_page_info": {}
    }
    
    try:
        page_count = len(doc)
        if page_count == 0:
            return page_analysis
        
        first_page = doc[0]
        page_analysis["first_page_info"] = {
            "page_size": safe_get_attr(first_page, "rect"),
            "page_rotation": safe_get_attr(first_page, "rotation")
        }

        if not page_analysis["has_images"]:
            page_analysis["has_images"] = bool(safe_get_attr(first_page, "get_images", []))
        
        if not page_analysis["has_text"]:
            page_analysis["has_text"] = bool(safe_get_attr(first_page, "get_text", "").strip())
        
        for page in doc:
            if (page_analysis["has_form_fields"] and 
                page_analysis["has_images"] and 
                page_analysis["has_text"] and 
                page_analysis["has_javascript"]):
                break
                
            for annot in page.annots():
                annot_type = annot.type
                if not page_analysis["has_form_fields"] and annot_type[1] == "Widget":
                    page_analysis["has_form_fields"] = True
                
                if not page_analysis["has_javascript"] and annot_type[0] == 8:
                    page_analysis["has_javascript"] = True
            
            if not page_analysis["has_images"]:
                page_analysis["has_images"] = bool(safe_get_attr(page, "get_images", []))
            
            if not page_analysis["has_text"]:
                page_analysis["has_text"] = bool(safe_get_attr(page, "get_text", "").strip())
        
        if not page_analysis["has_form_fields"]:
            page_analysis["has_form_fields"] = safe_get_attr(doc, "is_form_pdf", False)
            
    except Exception as e:
        logger.debug(f"Error in combined page analysis: {str(e)}")
    return page_analysis

def _get_document_id(doc):
    try:
        if hasattr(doc, 'xref_get_key') and hasattr(doc, 'xref_get_keys'):
            try:
                trailer_keys = doc.xref_get_keys(-1)
                if 'ID' in trailer_keys:
                    id_type, id_value = doc.xref_get_key(-1, 'ID')
                    if id_value:
                        return id_value
            except Exception as e:
                logger.debug(f"Error getting trailer ID: {str(e)}")
        

        metadata = doc.metadata

        id_fields = ['DocumentID', 'id', 'identifier', 'uuid']
        for field in id_fields:
            if field in metadata and metadata[field]:
                return metadata[field]
        
        doc_name = safe_get_attr(doc, "name", None)
        if doc_name:
            return f"Document: {doc_name}"
        
        return "Not available"
        
    except Exception as e:
        logger.debug(f"Error getting document ID: {str(e)}")
        return "Not available"

def analyze_pdf_metadata(pdf_path, validate_pdf_file=None, file_stats=None):
    local_file_stats = file_stats  # Use provided stats if available
    if local_file_stats is None:
        try:
            local_file_stats = os.stat(pdf_path) # Fetch fresh stats *now*
        except FileNotFoundError:
            logger.error(f"File not found: {pdf_path}")
            return None 
        except Exception as e:
            logger.warning(f"Could not get initial file system attributes for {pdf_path}: {str(e)}. Proceeding with caution.")
            pass # local_file_stats remains None if error other than FileNotFoundError

    if validate_pdf_file and not validate_pdf_file(pdf_path):
        return None
    
    result = {
        "file_system": get_file_system_attributes(pdf_path, local_file_stats), 
        "document_info": {},
        "structural_info": {},
        "page_info": {},
        "document_structure": {},
        "content_info": {},
        "security_info": {},
        "additional_properties": {}
    }
    
    try:
        with fitz.open(pdf_path) as doc:
            metadata = doc.metadata
            processed_metadata = dict(metadata)
            for date_field in ['creationDate', 'modDate']:
                if date_field in processed_metadata:
                    parsed_date = _parse_pdf_date(processed_metadata[date_field])
                    if parsed_date:
                        processed_metadata[date_field] = parsed_date
            
            result["document_info"] = {k: v for k, v in processed_metadata.items() if v}
            
            xmp_metadata = None
            try:
                xmp_metadata = doc.get_xml_metadata()
            except Exception as e:
                logger.debug(f"Failed to get XMP metadata: {str(e)}")
            
            format_info = detect_pdf_format(doc, xmp_metadata)
            
            is_encrypted = safe_get_attr(doc, "is_encrypted")
            permissions = safe_get_attr(doc, "permissions")
            
            structural_info = {
                "page_count": len(doc),
                "is_encrypted": is_encrypted,
                "is_pdfa": format_info["is_pdfa"],
                "is_pdfx": format_info["is_pdfx"],
                "file_format": format_info["format"],
                "pdf_version": format_info["version"],
                "permissions": get_human_readable_pdf_permissions(permissions)
            }
            
            if format_info["is_pdfa"] and format_info["pdfa_version"]:
                structural_info["pdfa_version"] = format_info["pdfa_version"]
            if format_info["is_pdfx"] and format_info["pdfx_version"]:
                structural_info["pdfx_version"] = format_info["pdfx_version"]
                
            result["structural_info"] = structural_info
            
            page_analysis = _analyze_pages_combined(doc)
            
            result["page_info"] = page_analysis["first_page_info"]
            
            has_outline = bool(safe_get_attr(doc, "get_toc", []))
            result["document_structure"] = {
                "has_outline": has_outline,
                "has_bookmarks": has_outline,
                "has_form_fields": page_analysis["has_form_fields"]
            }
            
            content_info = {
                "has_images": page_analysis["has_images"],
                "has_text": page_analysis["has_text"],
                "has_javascript": page_analysis["has_javascript"]
            }
            
            result["content_info"] = content_info
            
            if is_encrypted:
                result["security_info"] = {
                    "encryption_method": safe_get_attr(doc, "get_encryption_method"),
                    "encryption_level": safe_get_attr(doc, "get_encryption_level"),
                    "user_permissions": safe_get_attr(doc, "get_user_permissions")
                }
            
            result["additional_properties"] = {
                "document_id": _get_document_id(doc),
                "language": metadata.get("language", "Not available"),
                "page_mode": safe_get_attr(doc, "pagemode", "Not available"),
                "page_layout": safe_get_attr(doc, "pagelayout", "Not available"),
                "is_linearized": safe_get_attr(doc, "is_fast_webaccess", False),
                "is_repaired": safe_get_attr(doc, "is_repaired", False),
                "needs_password": safe_get_attr(doc, "needs_pass", False),
                "version_count": safe_get_attr(doc, "version_count", 0)
            }
            return result
            
    except Exception as e:
        logger.error(f"Error analyzing PDF: {str(e)}")
        return None

def print_metadata(metadata):
    if not metadata:
        logger.error("No metadata to print")
        return
        
    for section, data in metadata.items():
        if data:
            print(f"\n=== {section.replace('_', ' ').title()} ===")
            if isinstance(data, dict):
                for key, value in data.items():
                    print(f"{key}: {value}")
            else:
                print(data)
