import copy
import io
import os
from pathlib import Path
from datetime import datetime, timezone

import fitz

from .. import __version__
from .coverage import print_coverage
from .hash_checker import calculate_file_hashes
from .link_extractor import defang_url
from .pipeline import analyze_pdf_once
from .report_html import (BORDER, CSS, MUTED, PAGE_MARGIN, build_footer_text,
                          build_report_html, report_images)
from .risk_scorer import risk_level
from .threat_intel import selected_providers
from .urlhaus import URLhausClient
from .utils import get_confirmation
from .virustotal import VirusTotalClient

MAX_OPERATOR_NAME_LENGTH = 100

_BOTTOM_MARGIN = 58
_FOOTER_FONT_SIZE = 7.5
_BLOCK_ID = "block-%d"
# Height of the endless page the report is measured on (points)
_MEASURE_HEIGHT = 1e6


def _rgb(color):
    """'#rrggbb' -> PyMuPDF colour tuple."""
    return tuple(int(color[i:i + 2], 16) / 255 for i in (1, 3, 5))


def _story(body_html, archive, breaks=frozenset()):
    """A Story of the report with an id on every top-level block and a page
    break before each block whose index is in `breaks`. Also returns, per
    block, whether it is kept with the next one (headings, table headers and
    the lines introducing a table)."""
    story = fitz.Story(html=body_html, user_css=CSS, archive=archive)
    keeps = []
    node = story.body.first_child
    while node:
        if not node.is_text:
            index = len(keeps)
            # get_attributes(), not get_attribute_value(): PyMuPDF hangs
            # looking up a missing attribute on a node that has any attribute
            keeps.append(node.tagname in ("h2", "h3")
                         or "keep" in node.get_attributes().get("class", "").split())
            if index in breaks:
                # Tables ignore page-break-before, so break on an empty div
                marker = story.body.create_element("div")
                marker.set_attribute("style", "page-break-before: always")
                node.insert_before(marker)
            node.set_attribute("id", _BLOCK_ID % index)
        node = node.next
    return story, keeps


def _keep_breaks(body_html, archive, content):
    """Indices of the blocks to start a new page at, so that no keep-with-next
    block ends a page apart from the content it introduces (fitz.Story ignores
    page-break-after: avoid). The report is laid out once on an endless page,
    where every block position is exact, and paginated the way Story does it:
    a block that does not fit moves whole to the next page."""
    story, keeps = _story(body_html, archive)
    story.place(fitz.Rect(content.x0, content.y0, content.x1, content.y0 + _MEASURE_HEIGHT))
    ids = {_BLOCK_ID % index: index for index in range(len(keeps))}
    spans = [None] * len(keeps)

    def record(position):
        index = ids.get(position.id)
        if index is not None and spans[index] is None:
            spans[index] = (position.rect[1], position.rect[3])

    story.element_positions(record)
    # Story cannot break a table row across pages and silently drops whatever
    # overflows one; the template caps content to prevent it, so fail loudly
    # rather than emit a report with sections missing
    if any(span and span[1] - span[0] > content.height for span in spans):
        raise ValueError("report content too tall to fit on a page")

    breaks = set()
    first, index = 0, 1     # first block on the current page, block to place
    while index < len(keeps) and spans[index] and spans[first]:
        if spans[index][1] - spans[first][0] <= content.height:
            index += 1
            continue
        start = index
        while start - 1 > first and keeps[start - 1]:
            start -= 1
        if start < index:
            breaks.add(start)
        first, index = start, start + 1
    return breaks


def _render_html_to_pdf(body_html, meta, output_path):
    """Render the report HTML to a PDF with PyMuPDF's Story engine and stamp a
    page-numbered footer once the total page count is known."""
    mediabox = fitz.paper_rect("a4")
    content = fitz.Rect(PAGE_MARGIN, PAGE_MARGIN,
                        mediabox.x1 - PAGE_MARGIN, mediabox.y1 - _BOTTOM_MARGIN)
    # Images are served from memory, so the renderer never dereferences a
    # filesystem path named in the HTML
    archive = fitz.Archive()
    for name, data in report_images().items():
        archive.add((data, name))

    story, _ = _story(body_html, archive, _keep_breaks(body_html, archive, content))
    buffer = io.BytesIO()
    writer = fitz.DocumentWriter(buffer)
    more = 1
    while more:
        device = writer.begin_page(mediabox)
        more, _ = story.place(content)
        story.draw(device)
        writer.end_page()
    writer.close()

    doc = fitz.open("pdf", buffer.getvalue())
    try:
        page_count = doc.page_count
        footer_y = mediabox.y1 - 30
        for index, page in enumerate(doc, 1):
            page.draw_line(fitz.Point(PAGE_MARGIN, footer_y - 6),
                           fitz.Point(mediabox.x1 - PAGE_MARGIN, footer_y - 6),
                           color=_rgb(BORDER), width=0.6)
            left, right = build_footer_text(meta, index, page_count)
            right_x = (mediabox.x1 - PAGE_MARGIN
                       - fitz.get_text_length(right, "helv", _FOOTER_FONT_SIZE))
            for x, text in ((PAGE_MARGIN, left), (right_x, right)):
                page.insert_text(fitz.Point(x, footer_y), text,
                                 fontsize=_FOOTER_FONT_SIZE, fontname="helv",
                                 color=_rgb(MUTED))
        doc.save(str(output_path))
    finally:
        doc.close()


def _service(providers, provider):
    return next((client for client in providers if client.provider == provider), None)


# Report cell for one lookup: a summary, why it was skipped, or None when the
# service is not in use
def _reputation(client, value, file=False):
    if client is None:
        return None
    if file:
        value = value.lower()
        reason = client.skip_reason(value, client.checked_hashes, noun="File hash")
    else:
        reason = client.skip_reason(value, client.checked_urls)
    if reason:
        return {"status": "skipped", "message": reason}
    if file:
        return client.summarize_file(client.check_file(value, silent=True))
    return client.summarize_url(client.check_url(value, silent=True))


# Gather everything the HTML template needs, running each service's lookups
# (file hash first, then links, then QR URLs) against its own shared call limit.
def _collect_report_data(pdf_path, analysis_result, defang, operator_name,
                         providers=(), include_logo=True):
    vt = _service(providers, "virustotal")
    urlhaus = _service(providers, "urlhaus")

    def lookups(url):
        return {"vt": _reputation(vt, url), "urlhaus": _reputation(urlhaus, url)}

    sha256 = (analysis_result.hashes or {}).get("SHA-256")
    vt_file = _reputation(vt, sha256, file=True) if sha256 else None
    urlhaus_file = _reputation(urlhaus, sha256, file=True) if sha256 else None

    links = [dict(url=link, display=defang_url(link) if defang else link, **lookups(link))
             for link in analysis_result.links or []]

    qr = None
    if analysis_result.qr:
        qr = dict(analysis_result.qr)
        qr_codes = []
        for qr_code in qr.get('qr_codes', []):
            payload = qr_code.get('payload', '')
            is_url = qr_code.get('type') == 'URL'
            entry = dict(qr_code, display=defang_url(payload) if (is_url and defang) else payload,
                         vt=None, urlhaus=None)
            if is_url:
                entry.update(lookups(payload))
            qr_codes.append(entry)
        qr['qr_codes'] = qr_codes

    risk = copy.deepcopy(analysis_result.risk)
    intel = []
    if vt_file and vt_file.get('status') == 'ok' and vt_file.get('positives', 0):
        intel.append("VirusTotal flagged the file")
    if urlhaus_file and urlhaus_file.get('status') == 'ok':
        intel.append("URLhaus identifies a known malware payload")
    for entry in links + (qr.get('qr_codes', []) if qr else []):
        vt_url = entry.get('vt') or {}
        stats = vt_url.get('stats', {})
        if vt_url.get('status') == 'ok' and (stats.get('malicious', 0) or stats.get('suspicious', 0)):
            intel.append("VirusTotal flagged a URL")
        if (entry.get('urlhaus') or {}).get('status') == 'ok':
            intel.append("URLhaus identifies a known malware URL")
    if risk is not None and intel:
        risk['score'] = max(risk['score'], 80)
        risk['level'] = risk_level(risk['score'])
        risk['adjustments'].extend(reason + ": minimum score 80 (Critical)"
                                   for reason in dict.fromkeys(intel))
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    return {
        "meta": {
            "scanned_path": str(pdf_path),
            "version": __version__,
            "timestamp": timestamp,
            "operator": operator_name,
            "vt_enabled": vt is not None,
            "urlhaus_enabled": urlhaus is not None,
            "defang": defang,
            "include_logo": include_logo,
        },
        "risk": risk,
        "hashes": analysis_result.hashes,
        "vt_file": vt_file,
        "urlhaus_file": urlhaus_file,
        "links": links,
        "metadata": analysis_result.metadata,
        "javascript": analysis_result.javascript,
        "embedded": analysis_result.embedded,
        "structure": analysis_result.structure,
        "qr": qr,
        "errors": analysis_result.errors,
    }


# `providers` are the reputation clients chosen for this operation; bulk mode
# shares them across files so each call limit spans the whole batch.
def create_report(pdf_path, defang=False, operator_name=None, providers=(),
                  include_logo=True):
    reserved_output = None
    try:
        if operator_name and len(operator_name) > MAX_OPERATOR_NAME_LENGTH:
            operator_name = operator_name[:MAX_OPERATOR_NAME_LENGTH-3] + "..."

        input_path = Path(pdf_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input PDF file not found: {pdf_path}")

        safe_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_')
        safe_stem = ''.join(c for c in input_path.stem if c in safe_chars).rstrip()
        if not safe_stem:
            safe_stem = "pdf_report"

        output_path = input_path.parent / f"{safe_stem}_report.pdf"

        counter = 1
        original_output_path = output_path
        while True:
            try:
                fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
                reserved_output = output_path
                break
            except FileExistsError:
                output_path = original_output_path.parent / f"{safe_stem}_report_{counter}.pdf"
                counter += 1

        analysis_result = analyze_pdf_once(pdf_path)
        print_coverage(analysis_result.coverage)

        report_data = _collect_report_data(
            pdf_path, analysis_result, defang, operator_name, providers, include_logo)
        report_html = build_report_html(report_data)
        _render_html_to_pdf(report_html, report_data['meta'], output_path)

        return str(output_path)

    except Exception as e:
        if reserved_output is not None:
            try:
                reserved_output.unlink()
            except OSError:
                pass
        print(f"Error generating report: {str(e)}")
        return None

# Operator name for the report ('' to skip), or None when the user cancels
def ask_operator_name():
    try:
        return input("\nPlease type your name (enter to skip): ").strip()[:MAX_OPERATOR_NAME_LENGTH]
    except (EOFError, KeyboardInterrupt):
        print("\nOperation cancelled.")
        return None

# main function to generate the report
def main(pdf_path):
    operator_name = ask_operator_name()
    if operator_name is None:
        return

    with selected_providers("elements", VirusTotalClient(), URLhausClient()) as providers:
        defang = get_confirmation("\nWould you like to defang URLs?")
        include_logo = get_confirmation("\nWould you like to include the logo in the report?")

        print(f"\nGenerating report for {pdf_path}...")
        report_path = create_report(pdf_path, defang, operator_name, providers, include_logo)

    if report_path:
        print(f"\nReport generated successfully: {report_path}")
        print(f"\nSHA256 of the report: {calculate_file_hashes(report_path)['SHA-256']}")
    else:
        print("\nFailed to generate report.")
