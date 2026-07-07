# QR code detection: renders each page and decodes QR codes so that URLs
# hidden in images ("quishing") can be reviewed, defanged and checked with
# VirusTotal like regular document links.
#
# OpenCV is an optional dependency (pip install pdfchecker[qr]); detection
# degrades gracefully when it is not installed.
import logging
import os
import re

import fitz

logger = logging.getLogger(__name__)

try:
    import cv2
    import numpy as np
    QR_SUPPORT = True
except ImportError:
    QR_SUPPORT = False

QR_UNAVAILABLE_MESSAGE = (
    "QR detection requires the optional dependency opencv-python-headless "
    "(install with: pip install 'pdfchecker[qr]')"
)

RENDER_DPI = 150
MAX_QR_PAGES = 200
MAX_PAYLOAD_LENGTH = 2000
MAX_QR_ERRORS = 10

_URL_PATTERN = re.compile(r'^(?:[a-zA-Z][a-zA-Z0-9+.-]*://|www\.)', re.IGNORECASE)


def is_url_payload(payload):
    return bool(payload) and bool(_URL_PATTERN.match(payload.strip()))


def _decode_page(page, detector):
    pix = page.get_pixmap(dpi=RENDER_DPI, colorspace=fitz.csGRAY, alpha=False)
    # pix.samples rows are padded to pix.stride bytes; crop to real width
    img = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.stride)[:, :pix.width]

    try:
        found, decoded_info, _, _ = detector.detectAndDecodeMulti(img)
    except cv2.error as e:
        logger.debug(f"OpenCV QR decode error: {str(e)}")
        return []

    if not found or decoded_info is None:
        return []
    return list(decoded_info)


def detect_qr_codes(pdf_path, validate_pdf_file=None):
    if validate_pdf_file and not validate_pdf_file(pdf_path):
        return None

    results = {
        "supported": QR_SUPPORT,
        "qr_count": 0,
        "qr_codes": [],
        "undecoded_count": 0,
        "pages_scanned": 0,
        "pages_skipped": 0,
        "errors": []
    }
    if not QR_SUPPORT:
        results["errors"].append(QR_UNAVAILABLE_MESSAGE)
        return results

    original_stats = None
    try:
        original_stats = os.stat(pdf_path)
    except Exception:
        pass

    try:
        with fitz.open(pdf_path) as doc:
            detector = cv2.QRCodeDetector()
            seen_payloads = set()

            for page_num, page in enumerate(doc):
                if page_num >= MAX_QR_PAGES:
                    results["pages_skipped"] = doc.page_count - MAX_QR_PAGES
                    break
                results["pages_scanned"] += 1
                try:
                    payloads = _decode_page(page, detector)
                except Exception as e:
                    logger.debug(f"Error scanning page {page_num + 1} for QR codes: {str(e)}")
                    if len(results["errors"]) < MAX_QR_ERRORS:
                        results["errors"].append(f"Page {page_num + 1} scan error: {str(e)}")
                    continue

                for payload in payloads:
                    if not payload:
                        # Detected QR geometry that could not be decoded
                        results["undecoded_count"] += 1
                        continue
                    payload = payload[:MAX_PAYLOAD_LENGTH]
                    if payload in seen_payloads:
                        continue
                    seen_payloads.add(payload)
                    results["qr_codes"].append({
                        "page": page_num + 1,
                        "type": "URL" if is_url_payload(payload) else "Text",
                        "payload": payload
                    })

            results["qr_count"] = len(results["qr_codes"])
    except Exception as e:
        logger.error(f"Error detecting QR codes: {str(e)}")
        results["errors"].append(f"General QR detection error: {str(e)}")
    finally:
        if original_stats:
            try:
                os.utime(pdf_path, (original_stats.st_atime, original_stats.st_mtime))
            except Exception:
                pass

    return results


def print_qr_findings(results, defanged=False, defang_url=None):
    if not results:
        print("No QR analysis results available.")
        return

    print("\n=== QR Code Analysis ===")
    if not results["supported"]:
        print(QR_UNAVAILABLE_MESSAGE)
        return

    print(f"Pages Scanned: {results['pages_scanned']}")
    if results["pages_skipped"]:
        print(f"Pages Skipped (page limit): {results['pages_skipped']}")
    print(f"QR Codes Decoded: {results['qr_count']}")
    if results["undecoded_count"]:
        print(f"QR Codes Detected but Unreadable: {results['undecoded_count']}")

    for i, qr in enumerate(results["qr_codes"], 1):
        payload = qr["payload"]
        if qr["type"] == "URL" and defanged and defang_url:
            payload = defang_url(payload)
        print(f"\n{i}. Page {qr['page']} [{qr['type']}]")
        print(f"   Payload: {payload}")

    if results["errors"]:
        print("\n--- Detection Errors ---")
        for error in results["errors"]:
            print(f"ERROR: {error}")
