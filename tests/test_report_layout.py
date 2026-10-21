import tempfile
import unittest
from pathlib import Path

import fitz

from pdfchecker.core import report_generator
from pdfchecker.core.report_html import (CELL_PAD, KEY_WIDTH, PAGE_MARGIN, SPACER_SRC,
                                         build_report_html)


def _data(**overrides):
    data = {
        "meta": {"scanned_path": "/tmp/sample.pdf", "version": "1.0", "timestamp": "2026-07-17 10:00:00",
                 "operator": None, "vt_enabled": False, "urlhaus_enabled": False, "defang": False,
                 "include_logo": True},
        "risk": None,
        "hashes": {"MD5": "a" * 32, "SHA-256": "b" * 64},
        "vt_file": None, "urlhaus_file": None,
        "links": [{"display": "https://example.test/" + "x" * 300}],
        "metadata": {"document_info": {"title": "T" * 400, "author": "line one\nline two"}},
        "javascript": None, "embedded": None, "structure": None, "qr": None, "errors": [],
    }
    data.update(overrides)
    return data


def _render(html, meta):
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "report.pdf"
        report_generator._render_html_to_pdf(html, meta, path)
        with fitz.open(path) as doc:
            return [page.get_text("dict") for page in doc], doc.page_count


def _spans(pages):
    for number, page in enumerate(pages):
        for block in page["blocks"]:
            for line in block.get("lines", []):
                for span in line["spans"]:
                    if span["text"].strip():
                        yield number, span


class ReportLayoutTests(unittest.TestCase):
    def test_columns_line_up_and_long_values_stay_inside_the_margins(self):
        data = _data()
        pages, _ = _render(build_report_html(data), data["meta"])
        right = fitz.paper_rect("a4").width - PAGE_MARGIN
        for _, span in _spans(pages):
            self.assertGreaterEqual(span["bbox"][0], PAGE_MARGIN - 0.1, span["text"])
            self.assertLessEqual(span["bbox"][2], right + 0.1, span["text"])
        value_x = {round(span["bbox"][0], 1) for _, span in _spans(pages)
                   if span["text"] in ("a" * 32, "b" * 64, "line one line two")}
        self.assertEqual(value_x, {PAGE_MARGIN + KEY_WIDTH + CELL_PAD})

    def test_heading_moves_to_the_next_page_with_its_content(self):
        filler = ('<table><tr><td><img src="%s" style="width:10pt; height:690pt;"/></td></tr></table>'
                  % SPACER_SRC)
        html = ('<html><body>%s<h2>Stranded heading</h2>'
                '<table class="row"><tr><td>First row</td></tr></table></body></html>' % filler)
        pages, count = _render(html, _data()["meta"])
        placed = {span["text"]: number for number, span in _spans(pages)}
        self.assertEqual(count, 2)
        self.assertEqual(placed["Stranded heading"], 1)
        self.assertEqual(placed["First row"], 1)

    def test_row_taller_than_a_page_fails_instead_of_dropping_content(self):
        tall = '<table><tr><td>%s</td></tr></table>' % '<br/>'.join(['line'] * 120)
        with self.assertRaisesRegex(ValueError, 'too tall'):
            _render('<html><body>%s</body></html>' % tall, _data()["meta"])


if __name__ == "__main__":
    unittest.main()
