# HTML template for the PDF report. build_report_html() turns the collected
# analysis data into an HTML document that report_generator.py renders to PDF
# with PyMuPDF's fitz.Story engine. Layout constraints: Story supports a CSS 2
# subset (no flexbox/grid), so positioning is table-based. Page geometry and
# the page-numbered footer are handled by report_generator, not by CSS.
#
# MuPDF layout quirks the template works around:
# - Table columns are sized from their content and CSS widths on cells are
#   ignored, so every cell carries a hidden spacer image that pins its column
#   to an exact width. (A separate spacer row could be left behind at a page
#   break, so the spacers live inside the content cells.)
# - Adjacent cell backgrounds leave hairline seams, so each row is its own
#   single-row table and its background and rule are painted on the table.
# - Images are measured at their natural size unless both width and height
#   are given.
# - Words wider than their cell overflow it (there is no zero-width break
#   opportunity: <wbr> is ignored and U+200B renders as a space), so long
#   tokens are split with <br/> at measured widths.
# - <font color> is ignored; colours are set with <span style>.
import functools
import html
from pathlib import Path

import fitz

from .terminal import safe_text

ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"
LOGO_PATH = ASSETS_DIR / "logo.png"
# Images referenced from the report HTML, as returned by report_images().
# report_generator serves them from an in-memory fitz.Archive, so the renderer
# never touches a filesystem path.
LOGO_SRC = "logo.png"
SPACER_SRC = "spacer.png"
BAR_FILL_SRC = "bar-fill.png"
BAR_TRACK_SRC = "bar-track.png"

# Brand red sampled from the logo; neutrals for an understated report look
ACCENT = "#c0392b"
INK = "#1a2230"
MUTED = "#5b6572"
BORDER = "#d8dde3"
LIGHT_BG = "#f3f5f7"

# Risk level -> (background, foreground). Amber keeps dark text for contrast.
LEVEL_COLORS = {
    "critical": ("#b71c1c", "#ffffff"),
    "high": ("#e65100", "#ffffff"),
    "medium": ("#f9a825", "#3b2f00"),
    "low": ("#7cb342", "#1f3300"),
    "minimal": ("#2e7d32", "#ffffff"),
}

SEVERITY_COLORS = {
    "critical": "#b71c1c",
    "high": "#e65100",
    "medium": "#c98a00",
    "low": "#558b2f",
    "info": "#607d8b",
}

MAX_REASONS_PER_CATEGORY = 12
MAX_REASON_LENGTH = 120
MAX_JS_CONTENT_LENGTH = 1200
MAX_JS_LINES = 40
MAX_VALUE_LENGTH = 600
# MuPDF cannot break a table row across pages and drops whatever overflows
# one, so the caps above keep every row (risk category, code block) well
# under a page.

# Geometry in points. The story is laid out on A4 inside PAGE_MARGIN on the
# left, right and top; report_generator uses the same content box.
PAGE_MARGIN = 46
CONTENT_WIDTH = fitz.paper_rect("a4").width - 2 * PAGE_MARGIN
CELL_PAD = 6            # horizontal padding on each side of a table cell
KEY_WIDTH = 150         # label column of key/value tables
SEVERITY_WIDTH = 64     # severity/risk column of the finding tables
INDEX_WIDTH = 28        # "#" column
BADGE_WIDTH = 104       # risk badge, and the logo stacked above it
MASTHEAD_GAP = 16       # between the title and the badge column
BAR_WIDTH = 64
BAR_HEIGHT = 5
BOX_PAD = 8             # side padding of notes, errors and code blocks

# Fonts behind the CSS classes, used to measure text: MuPDF renders the PDF
# base fonts with metric-compatible faces
TEXT_FONT = ("helv", 9)
SMALL_FONT = ("helv", 8)
MONO_FONT = ("cour", 8)
CODE_FONT = ("cour", 7.5)

CSS = """
body { font-family: Helvetica; font-size: 9pt; color: %(ink)s; margin: 0; }
h1 { font-size: 19pt; line-height: 22pt; color: %(ink)s; margin: 0 0 4pt 0; }
h2 { font-size: 12.5pt; color: %(ink)s; margin: 22pt 0 8pt 0;
     padding-bottom: 3pt; border-bottom: 1.4pt solid %(ink)s; }
h3 { font-size: 10pt; color: %(ink)s; margin: 14pt 0 6pt 0; }
p { margin: 0 0 6pt 0; line-height: 13pt; }
ul { margin: 0; padding: 0 0 0 7.5pt; }
li { margin: 0 0 1pt 0; line-height: 12pt; }
table { width: 100%%; border-collapse: collapse; border-spacing: 0; }
td, th { padding: 4pt %(pad)spt; text-align: left; vertical-align: baseline;
         line-height: 12pt; }
th { font-size: 8pt; font-weight: bold; color: #ffffff; }
.sizer { line-height: 0; font-size: 0; }
.row { border-bottom: 0.6pt solid %(border)s; }
.head { background-color: %(ink)s; border-bottom: 0.6pt solid %(ink)s; }
.alt { background-color: %(light)s; }
.end { margin-bottom: 8pt; }
.k { color: %(muted)s; }
.barcell { vertical-align: top; }
.bar { padding-top: 3pt; line-height: 0; font-size: 0; }
.masthead td { padding: 0; vertical-align: top; }
.subtitle { font-size: 10pt; color: %(muted)s; margin: 0; }
.logo { line-height: 0; font-size: 0; margin-bottom: 6pt; }
.badge td { padding: 0; text-align: center; vertical-align: top; }
.badge .score { font-size: 17pt; line-height: 19pt; padding-top: 6pt; }
.badge .max { font-size: 8.5pt; }
.badge .level { font-size: 7pt; line-height: 9pt; letter-spacing: 0.6pt;
                padding: 1pt 0 6pt 0; }
.label { margin: 10pt 0 4pt 0; }
.muted { color: %(muted)s; }
.small { font-size: 8pt; }
.mono { font-family: Courier; font-size: 8pt; }
.empty { color: %(muted)s; font-style: italic; }
.box td { padding: 6pt %(box_pad)spt; vertical-align: top; }
.note { background-color: #fdf3e7; border: 0.8pt solid #e8c9a0;
        margin: 4pt 0 8pt 0; font-size: 8.5pt; }
.errbox { background-color: #fdecea; border: 0.8pt solid #f0b8b1;
          margin: 4pt 0 8pt 0; font-size: 8.5pt; }
.codeblock { background-color: %(light)s; border: 0.6pt solid %(border)s;
             margin: 3pt 0 8pt 0; font-family: Courier; font-size: 7.5pt; }
.codeblock td { line-height: 10pt; }
""" % {"ink": INK, "muted": MUTED, "border": BORDER, "light": LIGHT_BG,
       "pad": CELL_PAD, "box_pad": BOX_PAD}


def _solid_png(color=None):
    """A 1x1 PNG of one colour ('#rrggbb'), or transparent, for stretching
    into spacers and bar segments."""
    pix = fitz.Pixmap(fitz.csRGB, fitz.IRect(0, 0, 1, 1), 1)
    rgb = tuple(int(color[i:i + 2], 16) for i in (1, 3, 5)) if color else (0, 0, 0)
    pix.set_pixel(0, 0, rgb + (255 if color else 0,))
    return pix.tobytes("png")


@functools.lru_cache(maxsize=1)
def _trimmed_logo(step=4):
    """The logo PNG cropped to its visible content, so it lines up exactly with
    the risk badge below it. Near-white or transparent pixels count as margin;
    the scan runs on a downscaled copy, so the crop is accurate to `step` px."""
    pix = fitz.Pixmap(str(LOGO_PATH))
    if pix.n - pix.alpha != 3:
        pix = fitz.Pixmap(fitz.csRGB, pix)
    small = fitz.Pixmap(pix, max(1, pix.width // step), max(1, pix.height // step))
    n, width, samples = small.n, small.width, small.samples
    hits = [i // n for i in range(0, len(samples), n)
            if min(samples[i:i + 3]) < 235 and (not small.alpha or samples[i + 3] > 16)]
    if not hits:
        return pix.tobytes("png"), pix.width, pix.height
    xs = [i % width for i in hits]
    ys = [i // width for i in hits]
    box = fitz.IRect(min(xs) * step, min(ys) * step,
                     (max(xs) + 1) * step, (max(ys) + 1) * step) & pix.irect
    crop = fitz.Pixmap(pix.colorspace, box, pix.alpha)
    crop.copy(pix, box)
    return crop.tobytes("png"), crop.width, crop.height


def report_images():
    """name -> PNG bytes for every image the report HTML references."""
    images = {SPACER_SRC: _solid_png(), BAR_FILL_SRC: _solid_png(ACCENT),
              BAR_TRACK_SRC: _solid_png(BORDER)}
    if LOGO_PATH.exists():
        images[LOGO_SRC] = _trimmed_logo()[0]
    return images


def _esc(value):
    return html.escape(str(value), quote=True)


# Blank out control characters (rendered as boxes by the PDF fonts) except
# line breaks, and cap length
def _sanitize(text, max_length=MAX_VALUE_LENGTH):
    return "" if text is None else safe_text(text, max_length, keep='\n')


def _split_word(word, width, font):
    pieces, start, used = [], 0, 0.0
    for i, char in enumerate(word):
        advance = fitz.get_text_length(char, *font)
        if used + advance > width and i > start:
            pieces.append(word[start:i])
            start, used = i, 0.0
        used += advance
    pieces.append(word[start:])
    return pieces


# Escape text for HTML, splitting any word wider than `width` points into
# lines that fit. Newlines become spaces, as in any HTML text, unless kept as
# line breaks for code. Display-only.
def _wrap(text, width, font=TEXT_FONT, newlines=False):
    text = str(text)
    if not newlines:
        text = text.replace('\n', ' ')
    lines = []
    for line in text.split('\n'):
        words = []
        for word in line.split(' '):
            if fitz.get_text_length(word, *font) > width:
                words.append('<br/>'.join(_esc(p) for p in _split_word(word, width, font)))
            else:
                words.append(_esc(word))
        lines.append(' '.join(words))
    return '<br/>'.join(lines)


# Content width of a cell in a column `width` points wide
def _inner(width):
    return width - 2 * CELL_PAD


KV_VALUE_WIDTH = _inner(CONTENT_WIDTH - KEY_WIDTH)
BOX_TEXT_WIDTH = CONTENT_WIDTH - 2 * BOX_PAD - 2   # less the border


def _fmt(value, max_length=MAX_VALUE_LENGTH, width=KV_VALUE_WIDTH, font=TEXT_FONT):
    return _wrap(_sanitize(value, max_length), width, font)


def _mono(value, width=KV_VALUE_WIDTH, max_length=MAX_VALUE_LENGTH):
    return '<span class="mono">%s</span>' % _fmt(value, max_length, width, MONO_FONT)


def _colored(color, text_html):
    return '<span style="color:%s;"><b>%s</b></span>' % (color, text_html)


def _severity_html(severity):
    color = SEVERITY_COLORS.get(str(severity).lower(), MUTED)
    return _colored(color, _esc(str(severity).upper()))


# Column widths in points; the None columns share what the fixed ones leave
def _resolve(widths):
    flexible = widths.count(None)
    rest = (CONTENT_WIDTH - sum(w for w in widths if w)) / flexible if flexible else 0
    return [w if w else rest for w in widths]


def _sizer(width):
    return ('<div class="sizer"><img src="%s" style="width:%.2fpt; height:0.1pt;'
            ' visibility:hidden;"/></div>' % (SPACER_SRC, width))


# One table row as its own single-row table, each column exactly widths[i]
# points wide. A cell is HTML, or (HTML, class). The sizer follows the
# content of a body cell so the first lines stay baseline aligned; header
# cells hold a single line of one font, so theirs can lead.
def _row_table(cells, widths, classes, tag='td', pad=CELL_PAD):
    body = []
    for cell, width in zip(cells, widths):
        content, cls = cell if isinstance(cell, tuple) else (cell, None)
        sizer = _sizer(width - 2 * pad)
        body.append('<%s%s>%s</%s>'
                    % (tag, ' class="%s"' % cls if cls else '',
                       sizer + content if tag == 'th' else content + sizer, tag))
    return '<table class="%s"><tr>%s</tr></table>' % (classes, ''.join(body))


def _kv_table(rows):
    widths = [KEY_WIDTH, CONTENT_WIDTH - KEY_WIDTH]
    return ''.join(
        _row_table([(_wrap(key, _inner(KEY_WIDTH)), 'k'), value_html], widths,
                   'row end' if i == len(rows) - 1 else 'row')
        for i, (key, value_html) in enumerate(rows))


# Header row plus zebra-striped rows; `widths` must already be resolved. The
# header is kept on the same page as the first row.
def _grid_table(headers, rows, widths):
    parts = [_row_table([_esc(h) for h in headers], widths,
                        'head keep' if rows else 'head end', tag='th')]
    for i, row in enumerate(rows):
        classes = 'row alt' if i % 2 else 'row'
        parts.append(_row_table(row, widths,
                                classes + ' end' if i == len(rows) - 1 else classes))
    return ''.join(parts)


# Shaded, bordered single-cell block (note, error, code). A table rather than
# a div: MuPDF can repaint a div's background at the top of a later page. The
# span keeps a leading <b> on the same baseline as the text after it.
def _box(classes, content_html):
    return ('<table class="box %s"><tr><td><span>%s</span></td></tr></table>'
            % (classes, content_html))


def _empty(message):
    return '<p class="empty">%s</p>' % _esc(message)


def _score_badge(risk):
    if not risk:
        return ''
    bg, fg = LEVEL_COLORS.get(str(risk.get('level', '')).lower(),
                              (MUTED, "#ffffff"))
    return (
        '<table class="badge" style="background-color:%s; color:%s;">'
        '<tr><td class="score"><b>%s</b><span class="max"> / %s</span></td></tr>'
        '<tr><td class="level"><b>%s RISK</b></td></tr>'
        '</table>'
        % (bg, fg, _esc(risk['score']), _esc(risk['max_score']),
           _esc(str(risk['level']).upper()))
    )


def _header(meta, risk):
    # Title and file line top left; the logo sits above the risk badge in a
    # fixed-width right column, both exactly BADGE_WIDTH wide.
    brand = ''
    if meta.get('include_logo', True) and LOGO_PATH.exists():
        _, width, height = _trimmed_logo()
        brand = ('<div class="logo"><img src="%s" style="width:%dpt; height:%.2fpt;"/></div>'
                 % (LOGO_SRC, BADGE_WIDTH, BADGE_WIDTH * height / width))
    brand += _score_badge(risk)
    title_width = CONTENT_WIDTH - BADGE_WIDTH - MASTHEAD_GAP
    title = ('<h1>PDF Security Analysis Report</h1>'
             '<p class="subtitle">%s &nbsp;&middot;&nbsp; %s UTC</p>'
             % (_fmt(Path(meta['scanned_path']).name, 120, title_width),
                _esc(meta['timestamp'])))
    return _row_table([title, '', brand], [title_width, MASTHEAD_GAP, BADGE_WIDTH],
                      'masthead', pad=0)


def _section_report_info(meta):
    rows = [
        ("Scanned file", _mono(meta['scanned_path'])),
        ("Report generation tool", _esc("PDFChecker %s" % meta['version'])),
        ("Report generated (UTC)", _esc(meta['timestamp'])),
    ]
    if meta.get('operator'):
        rows.append(("Operator", _fmt(meta['operator'], 120)))
    rows.append(("VirusTotal enrichment",
                 "Enabled" if meta['vt_enabled'] else "Disabled"))
    rows.append(("URLhaus (abuse.ch) enrichment",
                 "Enabled" if meta.get('urlhaus_enabled') else "Disabled"))
    rows.append(("URL defanging",
                 "Enabled" if meta['defang'] else "Disabled"))
    return _kv_table(rows)


# A filled share of a BAR_WIDTH track, drawn with stretched one-pixel images;
# its cell is top aligned and padded so the bar centres on the row's text
def _risk_bar(score, max_score):
    pct = int(round(100 * score / max_score)) if max_score else 0
    fill = BAR_WIDTH * max(0, min(100, pct)) / 100
    images = ''.join(
        '<img src="%s" style="width:%.2fpt; height:%dpt;"/>' % (src, width, BAR_HEIGHT)
        for src, width in ((BAR_FILL_SRC, fill), (BAR_TRACK_SRC, BAR_WIDTH - fill))
        if width > 0)
    return ('<div class="bar">%s</div>' % images, 'barcell')


def _section_risk(risk):
    if not risk:
        return _empty("Risk score not available.")

    parts = []
    level = str(risk.get('level', '')).lower()
    color = '#b28704' if level == 'medium' else LEVEL_COLORS.get(level, (MUTED,))[0]
    parts.append(
        '<p class="keep">Overall risk score: <b>%s / %s</b> &nbsp;&mdash;&nbsp; %s</p>'
        % (_esc(risk['score']), _esc(risk['max_score']),
           _colored(color, _esc(str(risk['level']).upper())))
    )
    for adjustment in risk.get('adjustments', []):
        parts.append(_box('note keep', '<b>Note:</b> %s'
                          % _fmt(adjustment, width=BOX_TEXT_WIDTH)))

    # Category and score together span KEY_WIDTH, so the bars start where the
    # values of the key/value tables do
    widths = _resolve([98, KEY_WIDTH - 98, BAR_WIDTH + 2 * CELL_PAD, None])
    reason_width = _inner(widths[3]) - 7.5   # less the list indent
    rows = []
    for name, category in risk['categories'].items():
        label = name.replace('_', ' ').title()
        reasons = category.get('reasons', [])
        if reasons:
            shown = reasons[:MAX_REASONS_PER_CATEGORY]
            items = ''.join('<li>%s</li>' % _fmt(r, MAX_REASON_LENGTH, reason_width, SMALL_FONT)
                            for r in shown)
            if len(reasons) > MAX_REASONS_PER_CATEGORY:
                items += ('<li class="muted">... and %d more indicator(s)</li>'
                          % (len(reasons) - MAX_REASONS_PER_CATEGORY))
            reason_html = '<ul class="small">%s</ul>' % items
        else:
            reason_html = '<span class="empty">No indicators</span>'
        rows.append([
            '<b>%s</b>' % _esc(label),
            '%s&nbsp;/&nbsp;%s' % (_esc(category['score']), _esc(category['max'])),
            _risk_bar(category['score'], category['max']),
            reason_html,
        ])
    parts.append(_grid_table(["Category", "Score", "", "Indicators"], rows, widths))
    return ''.join(parts)


# Lookup outcomes without data, per renderer: status -> note
_VT_FILE_NOTES = {
    'error': 'VirusTotal API call failed.',
    'not_found': 'File not found in the VirusTotal database. No previous analysis available.',
}
_URLHAUS_FILE_NOTES = {
    'error': 'URLhaus API call failed.',
    'invalid': 'URLhaus rejected the payload hash as invalid.',
    'not_found': ('Payload hash not found in URLhaus. '
                  'No known malware distribution record is available.'),
}
_VT_URL_NOTES = {
    'error': 'VirusTotal API call failed.',
    'pending': 'Analysis still pending at report time.',
    'not_found': 'Not found in VirusTotal.',
}
_URLHAUS_URL_NOTES = {
    'error': 'URLhaus API call failed.',
    'invalid': 'URLhaus rejected this URL as invalid.',
    'not_found': 'Not found in URLhaus.',
}


# Muted note for a lookup that returned no data (skipped, failed, unknown),
# or None when the result has data to render
def _status_note(result, notes, tag, width, skipped_prefix=''):
    if result['status'] == 'skipped':
        text = skipped_prefix + _sanitize(result['message'])
    elif result['status'] in notes:
        text = notes[result['status']]
    else:
        return None
    return '<%s class="small muted">%s</%s>' % (tag, _wrap(text, width, SMALL_FONT), tag)


def _vt_file_html(vt):
    if not vt:
        return ''
    note = _status_note(vt, _VT_FILE_NOTES, 'p', CONTENT_WIDTH, 'VirusTotal: ')
    if note:
        return note

    positives, total = vt['positives'], vt['total']
    color = SEVERITY_COLORS['high'] if positives else SEVERITY_COLORS['low']
    parts = ['<p%s>VirusTotal detection rate: %s</p>'
             % (' class="keep"' if vt.get('detections') else '', _colored(color, '%d / %d (%.1f%%)'
                        % (positives, total, (positives / total * 100) if total else 0.0)))]
    if vt.get('detections'):
        widths = _resolve([KEY_WIDTH, None])
        rows = [[_fmt(scanner, 80, _inner(widths[0])), _fmt(result, 200, _inner(widths[1]))]
                for scanner, result in vt['detections']]
        parts.append(_grid_table(["Engine", "Detection"], rows, widths))
    if vt.get('scan_date'):
        parts.append('<p class="small muted">Last scan: %s UTC</p>'
                     % _esc(vt['scan_date']))
    return ''.join(parts)


def _urlhaus_file_html(result):
    if not result:
        return ''
    note = _status_note(result, _URLHAUS_FILE_NOTES, 'p', CONTENT_WIDTH, 'URLhaus: ')
    if note:
        return note
    return _kv_table([
        ("Malware signature", _fmt(result.get('signature') or 'Unknown', 120)),
        ("File type", _fmt(result.get('file_type') or 'Unknown', 80)),
        ("File size", _fmt(result.get('file_size') or 'Unknown', 80)),
        ("First seen", _fmt(result.get('first_seen') or 'Unknown', 120)),
        ("Last seen", _fmt(result.get('last_seen') or 'Unknown', 120)),
        ("Associated malware URLs",
         _esc(result.get('url_count') or result.get('known_urls', 0))),
    ])


def _section_hashes(hashes, vt_file, vt_enabled, urlhaus_file=None,
                    urlhaus_enabled=False):
    if not hashes:
        return _empty("Hash calculation not available.")
    out = _kv_table([(hash_type, _mono(value)) for hash_type, value in hashes.items()])
    if vt_enabled:
        out += '<h3>VirusTotal File Reputation</h3>'
        out += _vt_file_html(vt_file) or _empty("No VirusTotal result.")
    if urlhaus_enabled:
        out += '<h3>URLhaus Payload Reputation</h3>'
        out += _urlhaus_file_html(urlhaus_file) or _empty("No URLhaus result.")
    return out


def _vt_url_html(vt, width):
    if not vt:
        return '<span class="empty">&mdash;</span>'
    note = _status_note(vt, _VT_URL_NOTES, 'span', width)
    if note:
        return note

    stats = vt['stats']
    flagged = stats.get('malicious', 0) + stats.get('suspicious', 0)
    color = SEVERITY_COLORS['high'] if flagged else SEVERITY_COLORS['low']
    out = ('<span class="small">%s %s</span>'
           % (_colored(color, '%d flagged' % flagged),
              _wrap('(malicious %d, suspicious %d, harmless %d, undetected %d)'
                    % (stats.get('malicious', 0), stats.get('suspicious', 0),
                       stats.get('harmless', 0), stats.get('undetected', 0)),
                    width, SMALL_FONT)))
    if vt.get('scan_date'):
        out += ('<br/><span class="small muted">Last scan: %s UTC</span>'
                % _esc(vt['scan_date']))
    return out


def _urlhaus_url_html(result, width):
    if not result:
        return '<span class="empty">&mdash;</span>'
    note = _status_note(result, _URLHAUS_URL_NOTES, 'span', width)
    if note:
        return note

    def detail(label, value, max_length):
        return _fmt('%s: %s' % (label, _sanitize(value, max_length)),
                    width=width, font=SMALL_FONT)

    status = result.get('url_status', 'unknown')
    color = SEVERITY_COLORS['high'] if status == 'online' else SEVERITY_COLORS['medium']
    details = [
        _colored(color, 'Known malware URL (%s)' % _wrap(status, width, SMALL_FONT)),
        detail('Threat', result.get('threat') or 'Unknown', 80),
    ]
    if result.get('host'):
        details.append(detail('Host', result['host'], 120))
    if result.get('tags'):
        details.append(detail('Tags', ', '.join(map(str, result['tags'])), 150))
    listed = ['%s: %s' % (name.replace('_', ' '), value)
              for name, value in result.get('blacklists', {}).items()
              if value and value != 'not listed']
    if listed:
        details.append(detail('Blacklists', ', '.join(listed), 180))
    if result.get('date_added'):
        details.append(detail('Added', result['date_added'], 120))
    if result.get('reference'):
        details.append(detail('Reference', result['reference'], 180))
    return '<br/>'.join('<span class="small">%s</span>' % item
                       for item in details)


# (header, entry key, cell renderer) for each enabled reputation service
def _reputation_columns(vt_enabled, urlhaus_enabled):
    columns = []
    if vt_enabled:
        columns.append(("VirusTotal", 'vt', _vt_url_html))
    if urlhaus_enabled:
        columns.append(("URLhaus", 'urlhaus', _urlhaus_url_html))
    return columns


# Resolved widths for a URL-bearing grid: the fixed `widths` (one None for the
# URL column) followed by one column per enabled reputation service
def _url_grid_widths(widths, columns, width_for_two, width_for_one):
    width = width_for_two if len(columns) == 2 else width_for_one
    return _resolve(widths + [width] * len(columns))


# Grid of URL-bearing entries plus one column per enabled reputation service
def _url_grid(headers, widths, rows, entries, columns):
    service_widths = widths[len(headers):]
    for row, entry in zip(rows, entries):
        row.extend(render(entry.get(key), _inner(width))
                   for (_, key, render), width in zip(columns, service_widths))
    return _grid_table(headers + [header for header, _, _ in columns], rows, widths)


def _section_links(links, vt_enabled, urlhaus_enabled=False):
    if not links:
        return _empty("No links found in the PDF.")
    columns = _reputation_columns(vt_enabled, urlhaus_enabled)
    widths = _url_grid_widths([INDEX_WIDTH, None], columns, 135, 170)
    rows = [[str(i), _mono(link['display'], _inner(widths[1]))]
            for i, link in enumerate(links, 1)]
    return ('<p class="keep">%d link(s) found in the document.</p>' % len(links)
            + _url_grid(["#", "URL"], widths, rows, links, columns))


def _section_metadata(metadata):
    if not metadata:
        return _empty("Metadata analysis not available.")
    parts = []
    for section, data in metadata.items():
        if not data or not isinstance(data, dict):
            continue
        parts.append('<h3>%s</h3>'
                     % _esc(section.replace('_', ' ').title()))
        parts.append(_kv_table(
            [(str(key), _fmt(value)) for key, value in data.items()]
        ))
    return ''.join(parts) if parts else _empty("No metadata extracted.")


def _section_javascript(js):
    if not js:
        return _empty("JavaScript analysis not available.")
    parts = [_kv_table([
        ("JavaScript detected", "Yes" if js.get('has_javascript') else "No"),
        ("JavaScript objects found", _esc(js.get('javascript_count', 0))),
    ])]

    if js.get('javascript_sources'):
        parts.append('<h3>JavaScript Sources</h3>')
        for i, source in enumerate(js['javascript_sources'], 1):
            parts.append(
                '<p class="keep"><b>%d.</b> %s &nbsp;<span class="muted">(%s)</span></p>'
                % (i, _fmt(source.get('source', 'Unknown'), 120),
                   _fmt(source.get('location', 'Unknown'), 200, CONTENT_WIDTH))
            )
            content = str(source.get('content') or '')
            if content:
                lines = content.split('\n')
                truncated = (len(content) > MAX_JS_CONTENT_LENGTH
                             or len(lines) > MAX_JS_LINES)
                code = _sanitize('\n'.join(lines[:MAX_JS_LINES]), MAX_JS_CONTENT_LENGTH)
                parts.append(_box('codeblock', '%s%s' % (
                    _wrap(code, BOX_TEXT_WIDTH, CODE_FONT, newlines=True),
                    '<br/><i>[Content truncated...]</i>' if truncated else ''
                )))

    if js.get('suspicious_patterns'):
        parts.append('<h3>Suspicious Patterns</h3>')
        widths = _resolve([SEVERITY_WIDTH, 110, None, 110])
        rows = [[_severity_html(p.get('severity', 'Unknown')),
                 _fmt(p.get('type', 'Unknown'), 120, _inner(widths[1])),
                 _mono(p.get('pattern', ''), _inner(widths[2]), 200),
                 '<span class="small">%s</span>'
                 % _fmt(p.get('location', 'Unknown'), 160, _inner(widths[3]), SMALL_FONT)]
                for p in js['suspicious_patterns']]
        parts.append(_grid_table(["Severity", "Type", "Pattern", "Location"],
                                 rows, widths))
    return ''.join(parts)


def _section_embedded(embedded):
    if not embedded:
        return _empty("Embedded file analysis not available.")
    parts = [_kv_table([
        ("Embedded files found", _esc(embedded['embedded_count'])),
        ("Hidden/orphaned streams", _esc(embedded['hidden_stream_count'])),
    ])]

    if embedded['embedded_files']:
        parts.append('<h3>Embedded Files</h3>')
        for i, entry in enumerate(embedded['embedded_files'], 1):
            rows = [
                ("Filename", _mono(entry['filename'], max_length=200)),
                ("Size", _esc("%s bytes" % entry['size'])),
                ("Risk", _severity_html(entry['risk'])),
                ("Source", _fmt(entry['source'], 200)),
            ]
            if entry.get('content_type'):
                rows.append(("Content type", _fmt(entry['content_type'], 120)))
            sha256 = entry['hashes'].get('SHA-256')
            if sha256:
                rows.append(("SHA-256", _mono(sha256)))
            if entry.get('risk_reasons'):
                rows.append(("Warnings", '<br/>'.join(
                    _fmt(reason) for reason in entry['risk_reasons'])))
            parts.append('<p class="label keep"><b>File %d</b></p>' % i)
            parts.append(_kv_table(rows))

    if embedded['hidden_streams']:
        parts.append('<h3>Hidden Streams</h3>')
        widths = _resolve([44, 70, SEVERITY_WIDTH, None])
        rows = []
        for stream in embedded['hidden_streams']:
            sha256 = stream['hashes'].get('SHA-256', '')
            rows.append([
                _esc(stream['xref']),
                _esc("%s bytes" % stream['size']),
                _severity_html(stream['risk']),
                _mono(sha256, _inner(widths[3])),
            ])
        parts.append(_grid_table(["XRef", "Size", "Risk", "SHA-256"], rows, widths))
    return ''.join(parts)


def _section_structure(structure):
    if not structure:
        return _empty("Structure analysis not available.")
    parts = ['<p%s>Anomalies detected: <b>%d</b></p>'
             % (' class="keep"' if structure['anomalies'] else '', structure['anomaly_count'])]
    if structure['anomalies']:
        widths = _resolve([SEVERITY_WIDTH, 130, 46, None])
        rows = []
        for anomaly in structure['anomalies']:
            description = _fmt(anomaly['description'], width=_inner(widths[3]))
            if anomaly.get('locations'):
                description += ('<br/><span class="small muted">%s</span>'
                                % _fmt('Locations: ' + ", ".join(anomaly['locations']),
                                       300, _inner(widths[3]), SMALL_FONT))
            rows.append([
                _severity_html(anomaly['severity']),
                _fmt(anomaly['type'], 120, _inner(widths[1])),
                _esc(anomaly.get('count', 1)),
                description,
            ])
        parts.append(_grid_table(["Severity", "Type", "Count", "Description"],
                                 rows, widths))
    return ''.join(parts)


def _section_qr(qr, vt_enabled, urlhaus_enabled=False):
    if qr and not qr.get('supported'):
        # Detection couldn't run (e.g. OpenCV missing): omit the section
        # entirely rather than printing the dependency notice in the report.
        return None
    if not qr:
        return _empty("QR analysis not available.")

    parts = [_kv_table([
        ("QR codes decoded", _esc(qr['qr_count'])),
        ("Detected but unreadable", _esc(qr.get('undecoded_count', 0))),
    ])]
    if qr['qr_codes']:
        columns = _reputation_columns(vt_enabled, urlhaus_enabled)
        widths = _url_grid_widths([INDEX_WIDTH, 40, 50, None], columns, 115, 150)
        rows = [[str(i), _esc(qr_code['page']), _esc(qr_code['type']),
                 _mono(qr_code['display'], _inner(widths[3]), 400)]
                for i, qr_code in enumerate(qr['qr_codes'], 1)]
        parts.append(_url_grid(["#", "Page", "Type", "Payload"], widths,
                               rows, qr['qr_codes'], columns))
    return ''.join(parts)


def _section_errors(errors):
    return ''.join(_box('errbox', _fmt(error, width=BOX_TEXT_WIDTH)) for error in errors)


def build_report_html(data):
    meta = data['meta']

    sections = [
        ("Report Information", _section_report_info(meta)),
        ("Risk Assessment", _section_risk(data.get('risk'))),
        ("File Integrity", _section_hashes(
            data.get('hashes'), data.get('vt_file'), meta['vt_enabled'],
            data.get('urlhaus_file'), meta.get('urlhaus_enabled', False))),
        ("Document Links", _section_links(
            data.get('links'), meta['vt_enabled'],
            meta.get('urlhaus_enabled', False))),
        ("Document Metadata", _section_metadata(data.get('metadata'))),
        ("JavaScript Analysis", _section_javascript(data.get('javascript'))),
        ("Embedded Files", _section_embedded(data.get('embedded'))),
        ("Structural Anomalies", _section_structure(data.get('structure'))),
        ("QR Codes", _section_qr(
            data.get('qr'), meta['vt_enabled'],
            meta.get('urlhaus_enabled', False))),
    ]
    if data.get('errors'):
        sections.append(("Analysis Errors", _section_errors(data['errors'])))

    # Drop sections whose builder returned None (e.g. QR detection unavailable)
    # so neither their heading nor their body appears, and numbering stays gapless.
    sections = [(title, content) for title, content in sections
                if content is not None]

    body = [_header(meta, data.get('risk'))]
    for number, (title, content) in enumerate(sections, 1):
        body.append('<h2>%d. %s</h2>' % (number, _esc(title)))
        body.append(content)

    # CSS is applied by the renderer via fitz.Story(user_css=...); the
    # page-numbered footer is drawn per page by report_generator. Every block
    # is a direct child of <body>: report_generator walks them to keep
    # headings and table headers on the page of the content they introduce.
    return ('<html><head><meta charset="utf-8"/></head><body>%s</body></html>'
            % ''.join(body))


def build_footer_text(meta, page_number, page_count):
    """Left and right footer text stamped onto every rendered page.

    fitz.Story has no page-number primitive, so the footer is drawn directly by
    report_generator once the total page count is known.
    """
    return ("Generated by PDFChecker %s · %s UTC" % (meta['version'], meta['timestamp']),
            "Page %d of %d" % (page_number, page_count))
