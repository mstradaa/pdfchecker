import os
import fitz
from datetime import datetime, timezone, timedelta
import logging
import re

MAX_METADATA_SIZE = 10000
MAX_STRING_LENGTH = 1000


logger = logging.getLogger(__name__)

# PyMuPDF reports the format as "PDF 1.7"; other sources use "PDF-1.7"
PDF_VERSION_PATTERN = re.compile(r'PDF[- ][\d.]+', re.IGNORECASE)


def _xmp_property_patterns(name):
    # XMP simple properties may be serialized as child elements
    # (<pdfaid:part>2</pdfaid:part>, possibly carrying attributes) or in the
    # compact form as attributes of rdf:Description (pdfaid:part="2")
    return [
        re.compile(rf'<{name}(?:\s[^>]*)?>\s*([^<]*?)\s*</{name}>', re.IGNORECASE),
        re.compile(rf'{name}\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE),
    ]

# PDF/A identification (ISO 19005-1..4): XMP properties in the
# http://www.aiim.org/pdfa/ns/id/ namespace, conventional prefix "pdfaid".
# part: 1-4; conformance: A/B (part 1), A/B/U (parts 2-3), E/F (PDF/A-4e/4f
# only, absent for plain PDF/A-4); rev: standard year, required by PDF/A-4
PDFA_PART_PATTERNS = _xmp_property_patterns('pdfaid:part')
PDFA_CONFORMANCE_PATTERNS = _xmp_property_patterns('pdfaid:conformance')
PDFA_REV_PATTERNS = _xmp_property_patterns('pdfaid:rev')
PDFA_VALID_PARTS = {'1', '2', '3', '4'}

# PDF/X identification, XMP form (ISO 15930-7/8/9 — PDF/X-4, X-5, X-6):
# GTS_PDFXVersion in the http://www.npes.org/pdfx/ns/id/ namespace,
# conventional prefix "pdfxid". GTS_PDFXConformance is matched too for
# PDF/X-1a-era metadata mirrored into XMP, where it carries the full label
PDFX_PATTERNS = (
    _xmp_property_patterns('pdfxid:GTS_PDFXVersion')
    + _xmp_property_patterns('GTS_PDFXConformance')
)

# PDF/X identification, document Info dictionary form (ISO 15930-1/3/4/6 —
# PDF/X-1a:2001/2003 and PDF/X-3:2002/2003, which pre-date XMP-based
# identification). GTS_PDFXConformance is preferred because in X-1a:2001 it
# holds the specific label ("PDF/X-1a:2001") while GTS_PDFXVersion holds the
# generic "PDF/X-1:2001"
PDFX_INFO_KEYS = ('GTS_PDFXConformance', 'GTS_PDFXVersion')

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

        # Per the PDF spec everything after the year is optional
        # (D:YYYYMMDDHHmmSS), with month/day defaulting to 1 and time to 0
        if len(date_str) < 4:
            return None

        year = int(date_str[:4])
        month = int(date_str[4:6]) if len(date_str) >= 6 else 1
        day = int(date_str[6:8]) if len(date_str) >= 8 else 1
        hour = int(date_str[8:10]) if len(date_str) >= 10 else 0
        minute = int(date_str[10:12]) if len(date_str) >= 12 else 0
        second = int(date_str[12:14]) if len(date_str) >= 14 else 0

        # Parse timezone offset if present (e.g. +05'30', -04'00', Z);
        # per the spec a missing offset means the timezone is unknown, so
        # the result stays naive rather than being assumed UTC
        tz_info = None
        tz_suffix = date_str[14:].strip("'")
        if tz_suffix:
            if tz_suffix.startswith('Z'):
                tz_info = timezone.utc
            else:
                tz_match = re.match(r"([+-])(\d{2})'?(\d{2})?'?", tz_suffix)
                if tz_match:
                    sign = 1 if tz_match.group(1) == '+' else -1
                    tz_hours = int(tz_match.group(2))
                    tz_minutes = int(tz_match.group(3)) if tz_match.group(3) else 0
                    tz_info = timezone(timedelta(hours=sign * tz_hours, minutes=sign * tz_minutes))

        dt = datetime(year, month, day, hour, minute, second, tzinfo=tz_info)
        return str(dt)
    except (ValueError, IndexError) as e:
        logger.debug(f"Failed to parse date '{date_str}': {str(e)}")
        return None

def _search_patterns(patterns, text):
    for pattern in patterns:
        match = pattern.search(text)
        if match and match.group(1):
            return match.group(1).strip()
    return None

def _get_pdfx_info_dict_version(doc):
    # PDF/X-1a and PDF/X-3 identify themselves in the document Info
    # dictionary; PyMuPDF's doc.metadata only exposes the standard Info keys,
    # so the GTS_* entries have to be read from the xref directly
    try:
        info_type, info_value = doc.xref_get_key(-1, 'Info')
        if info_type != 'xref':
            return None
        info_xref = int(info_value.split()[0])
        for key in PDFX_INFO_KEYS:
            value_type, value = doc.xref_get_key(info_xref, key)
            if value_type == 'string' and value:
                return value.strip()
    except Exception as e:
        logger.debug(f"Error reading PDF/X keys from Info dictionary: {str(e)}")
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
            part = _search_patterns(PDFA_PART_PATTERNS, xmp)
            conformance = _search_patterns(PDFA_CONFORMANCE_PATTERNS, xmp)

            if part in PDFA_VALID_PARTS:
                format_info["is_pdfa"] = True
                version = f"PDF/A-{part}"
                if conformance:
                    # customary lowercase display: PDF/A-2b, PDF/A-4f, ...
                    version += conformance.lower()
                format_info["pdfa_version"] = version
                rev = _search_patterns(PDFA_REV_PATTERNS, xmp)
                if rev:
                    format_info["pdfa_revision"] = rev

            pdfx_version = _search_patterns(PDFX_PATTERNS, xmp)
            if pdfx_version:
                format_info["is_pdfx"] = True
                format_info["pdfx_version"] = pdfx_version

        if not format_info["is_pdfx"]:
            pdfx_version = _get_pdfx_info_dict_version(doc)
            if pdfx_version:
                format_info["is_pdfx"] = True
                format_info["pdfx_version"] = pdfx_version

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
        (fitz.PDF_PERM_PRINT, "Print"),
        (fitz.PDF_PERM_MODIFY, "Modify"),
        (fitz.PDF_PERM_COPY, "Copy"),
        (fitz.PDF_PERM_ANNOTATE, "Annotate"),
        (fitz.PDF_PERM_FORM, "Fill Forms"),
        (fitz.PDF_PERM_ASSEMBLE, "Assemble"),
        (fitz.PDF_PERM_PRINT_HQ, "Print High Quality")
    ]
    
    permissions = [name for flag, name in permission_map if perms & flag]
    return ", ".join(permissions) if permissions else "No permissions"

def get_file_system_attributes(file_path, file_stats_param=None):
    try:
        stats_to_use = file_stats_param
        if stats_to_use is None:
            stats_to_use = os.stat(file_path)
        
        # Use st_birthtime on macOS/FreeBSD for actual creation time;
        # st_ctime is metadata change time on Unix, not creation time
        if hasattr(stats_to_use, 'st_birthtime'):
            created_ts = stats_to_use.st_birthtime
        else:
            created_ts = stats_to_use.st_ctime
        
        return {
            "size": f"{stats_to_use.st_size} bytes",
            "created": f"{datetime.fromtimestamp(created_ts, tz=timezone.utc)} UTC",
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
                
            for annot in (page.annots() or []):
                annot_type = annot.type
                if not page_analysis["has_form_fields"] and annot_type[1] == "Widget":
                    page_analysis["has_form_fields"] = True

                # JavaScript lives in annotation actions, not in an annotation type,
                # so inspect the raw annotation object for /JavaScript or /JS keys
                if not page_analysis["has_javascript"] and annot.xref:
                    try:
                        annot_obj = doc.xref_object(annot.xref)
                        if '/JavaScript' in annot_obj or '/JS' in annot_obj:
                            page_analysis["has_javascript"] = True
                    except Exception as e:
                        logger.debug(f"Error reading annotation object: {str(e)}")
            
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
                        hex_parts = re.findall(r'<([0-9a-fA-F]+)>', id_value)
                        if hex_parts:
                            return hex_parts[0].upper()
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

def analyze_pdf_metadata(pdf_path, validate_pdf_file=None, file_stats=None, doc=None):
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
        # A caller running several analyses may pass its already-open document
        if doc is not None:
            return _populate_document_metadata(doc, result)
        with fitz.open(pdf_path) as opened_doc:
            return _populate_document_metadata(opened_doc, result)

    except Exception as e:
        logger.error(f"Error analyzing PDF: {str(e)}")
        return None


def _populate_document_metadata(doc, result):
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
        if format_info.get("pdfa_revision"):
            structural_info["pdfa_revision"] = format_info["pdfa_revision"]
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
    
    # safe_get_attr returns a truthy "Not available" string on failure
    if is_encrypted is True:
        result["security_info"] = {
            "encryption_method": metadata.get("encryption", "Not available"),
            "permissions": get_human_readable_pdf_permissions(permissions)
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
