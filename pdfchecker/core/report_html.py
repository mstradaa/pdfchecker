# HTML template for the PDF report. build_report_html() turns the collected
# analysis data into a self-contained HTML document that report_generator.py
# renders to PDF with xhtml2pdf. Layout constraints: xhtml2pdf supports a
# CSS 2.1 subset (no flexbox/grid), so positioning is table-based.
import html
from pathlib import Path

LOGO_PATH = Path(__file__).resolve().parent.parent / "assets" / "logo.png"

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
MAX_JS_CONTENT_LENGTH = 1200
MAX_VALUE_LENGTH = 600
SOFT_BREAK_EVERY = 32

CSS = """
@page {
    size: a4 portrait;
    margin: 46pt 46pt 58pt 46pt;
    @frame footer_frame {
        -pdf-frame-content: page_footer;
        left: 46pt; width: 503pt; top: 800pt; height: 28pt;
    }
}
body { font-family: Helvetica; font-size: 9pt; color: %(ink)s; }
h1 { font-size: 19pt; color: %(ink)s; margin: 0 0 2pt 0; }
h2 { font-size: 12.5pt; color: %(ink)s; margin: 22pt 0 8pt 0;
     padding-bottom: 3pt; border-bottom: 1.4pt solid %(ink)s;
     -pdf-keep-with-next: true; }
h3 { font-size: 10pt; color: %(ink)s; margin: 12pt 0 5pt 0;
     -pdf-keep-with-next: true; }
p { margin: 0 0 6pt 0; line-height: 1.45; }
ul { margin: 2pt 0 6pt 0; }
li { margin-bottom: 2pt; line-height: 1.4; }
.subtitle { font-size: 10pt; color: %(muted)s; margin-bottom: 0; }
.muted { color: %(muted)s; }
.small { font-size: 8pt; }
.mono { font-family: Courier; font-size: 8pt; }
.empty { color: %(muted)s; font-style: italic; }
td, th { line-height: 1.4; }
.kv { width: 100%%; margin-bottom: 4pt; }
.kv td { padding: 3.5pt 6pt; border-bottom: 0.6pt solid %(border)s;
         vertical-align: top; }
.kv .k { width: 150pt; color: %(muted)s; }
.grid { width: 100%%; margin-bottom: 4pt; }
.grid th { padding: 4pt 6pt; text-align: left; font-size: 8pt;
           color: #ffffff; background-color: %(ink)s; }
.grid td { padding: 3.5pt 6pt; border-bottom: 0.6pt solid %(border)s;
           vertical-align: top; }
.rowalt td { background-color: %(light)s; }
.note { background-color: #fdf3e7; border: 0.8pt solid #e8c9a0;
        padding: 6pt 8pt; margin: 4pt 0 8pt 0; font-size: 8.5pt; }
.errbox { background-color: #fdecea; border: 0.8pt solid #f0b8b1;
          padding: 6pt 8pt; margin: 4pt 0 8pt 0; font-size: 8.5pt; }
.codeblock { background-color: %(light)s; border: 0.6pt solid %(border)s;
             padding: 6pt 8pt; margin: 3pt 0 8pt 0;
             font-family: Courier; font-size: 7.5pt; }
#page_footer { font-size: 7.5pt; color: %(muted)s;
               border-top: 0.6pt solid %(border)s; padding-top: 4pt; }
""" % {"ink": INK, "muted": MUTED, "border": BORDER,
       "light": LIGHT_BG, "accent": ACCENT}


def _esc(value):
    return html.escape(str(value), quote=True)


# Strip control characters (rendered as boxes by the PDF fonts) and cap length
def _sanitize(text, max_length=MAX_VALUE_LENGTH):
    if text is None:
        return ""
    text = str(text)
    text = ''.join(c for c in text if ord(c) >= 32 or c in '\n\t')
    text = text.replace('\t', ' ')
    if len(text) > max_length:
        text = text[:max_length - 3] + "..."
    return text


# Long unbroken tokens (URLs, hashes) overflow the page: chunk them with
# spaces so the paragraph engine can wrap. Display-only.
def _soft_break(text, every=SOFT_BREAK_EVERY):
    parts = []
    for token in str(text).split(' '):
        while len(token) > every:
            parts.append(token[:every])
            token = token[every:]
        parts.append(token)
    return ' '.join(p for p in parts if p)


def _fmt(value, max_length=MAX_VALUE_LENGTH):
    return _esc(_soft_break(_sanitize(value, max_length)))


def _severity_html(severity):
    color = SEVERITY_COLORS.get(str(severity).lower(), MUTED)
    return ('<font color="%s"><b>%s</b></font>'
            % (color, _esc(str(severity).upper())))


def _kv_table(rows):
    cells = []
    for key, value_html in rows:
        cells.append('<tr><td class="k">%s</td><td>%s</td></tr>'
                     % (_esc(key), value_html))
    return '<table class="kv">%s</table>' % ''.join(cells)


def _grid_table(headers, rows, widths=None):
    ths = []
    for i, header in enumerate(headers):
        width = ' width="%s"' % widths[i] if widths and widths[i] else ''
        ths.append('<th%s>%s</th>' % (width, _esc(header)))
    body = []
    for i, row in enumerate(rows):
        cls = ' class="rowalt"' if i % 2 else ''
        body.append('<tr%s>%s</tr>'
                    % (cls, ''.join('<td>%s</td>' % cell for cell in row)))
    return ('<table class="grid" repeat="1"><tr>%s</tr>%s</table>'
            % (''.join(ths), ''.join(body)))


def _empty(message):
    return '<p class="empty">%s</p>' % _esc(message)


def _score_badge(risk, compact=False):
    if not risk:
        return ''
    bg, fg = LEVEL_COLORS.get(str(risk.get('level', '')).lower(),
                              (MUTED, "#ffffff"))
    sizes = {
        "score": "17pt" if compact else "21pt",
        "max": "9pt" if compact else "10pt",
        "level": "7.5pt" if compact else "8.5pt",
        "toppad": "6pt 4pt 1pt 4pt" if compact else "9pt 4pt 1pt 4pt",
        "botpad": "0 4pt 6pt 4pt" if compact else "0 4pt 8pt 4pt",
    }
    return (
        '<table width="100%%" style="background-color:%(bg)s;">'
        '<tr><td align="center" style="font-size:%(score_sz)s; color:%(fg)s;'
        ' padding:%(toppad)s;"><b>%(score)s</b>'
        '<span style="font-size:%(max_sz)s;"> / %(max)s</span></td></tr>'
        '<tr><td align="center" style="font-size:%(level_sz)s; color:%(fg)s;'
        ' padding:%(botpad)s;"><b>%(level)s RISK</b></td></tr>'
        '</table>'
        % {"bg": bg, "fg": fg, "score": _esc(risk['score']),
           "max": _esc(risk['max_score']),
           "level": _esc(str(risk['level']).upper()),
           "score_sz": sizes["score"], "max_sz": sizes["max"],
           "level_sz": sizes["level"], "toppad": sizes["toppad"],
           "botpad": sizes["botpad"]}
    )


def _header(meta, risk):
    # Left column stacks logo (optional), title and file metadata, all left
    # aligned; the risk badge sits in a fixed-width right column, top aligned.
    logo_html = ''
    if meta.get('include_logo', True) and LOGO_PATH.exists():
        logo_html = ('<div style="margin-bottom:6pt;">'
                     '<img src="%s" width="112" height="40"/></div>'
                     % _esc(str(LOGO_PATH)))
    badge = _score_badge(risk, compact=True)
    badge_cell = ('<td width="140" valign="top" align="right">%s</td>' % badge
                  if badge else '<td width="140"></td>')
    return (
        '<table width="100%%"><tr>'
        '<td valign="top">'
        '%s'
        '<h1>PDF Security Analysis Report</h1>'
        '<p class="subtitle">%s &nbsp;&middot;&nbsp; %s UTC</p>'
        '</td>'
        '%s'
        '</tr></table>'
        % (logo_html,
           _fmt(Path(meta['scanned_path']).name, 120), _esc(meta['timestamp']),
           badge_cell)
    )


def _section_report_info(meta):
    rows = [
        ("Scanned file", '<span class="mono">%s</span>'
         % _fmt(meta['scanned_path'])),
        ("Report generation tool", _esc("PDFChecker %s" % meta['version'])),
        ("Report generated (UTC)", _esc(meta['timestamp'])),
    ]
    if meta.get('operator'):
        rows.append(("Operator", _fmt(meta['operator'], 120)))
    rows.append(("VirusTotal enrichment",
                 "Enabled" if meta['vt_enabled'] else "Disabled"))
    rows.append(("URL defanging",
                 "Enabled" if meta['defang'] else "Disabled"))
    return _kv_table(rows)


def _risk_bar(score, max_score):
    pct = int(round(100 * score / max_score)) if max_score else 0
    pct = max(0, min(100, pct))
    if pct == 0:
        return ('<table width="100%%"><tr>'
                '<td style="background-color:%s; padding:2.6pt 0;"></td>'
                '</tr></table>' % LIGHT_BG)
    if pct == 100:
        return ('<table width="100%%"><tr>'
                '<td style="background-color:%s; padding:2.6pt 0;"></td>'
                '</tr></table>' % ACCENT)
    return ('<table width="100%%"><tr>'
            '<td width="%d%%" style="background-color:%s; padding:2.6pt 0;"></td>'
            '<td width="%d%%" style="background-color:%s; padding:2.6pt 0;"></td>'
            '</tr></table>' % (pct, ACCENT, 100 - pct, LIGHT_BG))


def _section_risk(risk):
    if not risk:
        return _empty("Risk score not available.")

    parts = []
    bg, fg = LEVEL_COLORS.get(str(risk.get('level', '')).lower(),
                              (MUTED, "#ffffff"))
    parts.append(
        '<p>Overall risk score: <b>%s / %s</b> &nbsp;&mdash;&nbsp; '
        '<font color="%s"><b>%s</b></font></p>'
        % (_esc(risk['score']), _esc(risk['max_score']),
           bg if str(risk.get('level', '')).lower() != 'medium' else '#b28704',
           _esc(str(risk['level']).upper()))
    )
    for adjustment in risk.get('adjustments', []):
        parts.append('<div class="note"><b>Note:</b> %s</div>'
                     % _fmt(adjustment))

    rows = []
    for name, category in risk['categories'].items():
        label = name.replace('_', ' ').title()
        reasons = category.get('reasons', [])
        reason_html = ''
        if reasons:
            shown = reasons[:MAX_REASONS_PER_CATEGORY]
            items = ''.join('<li>%s</li>' % _fmt(r) for r in shown)
            if len(reasons) > MAX_REASONS_PER_CATEGORY:
                items += ('<li class="muted">... and %d more indicator(s)</li>'
                          % (len(reasons) - MAX_REASONS_PER_CATEGORY))
            reason_html = '<ul class="small">%s</ul>' % items
        else:
            reason_html = '<span class="empty">No indicators</span>'
        rows.append([
            '<b>%s</b>' % _esc(label),
            '%s&nbsp;/&nbsp;%s'
            % (_esc(category['score']), _esc(category['max'])),
            _risk_bar(category['score'], category['max']),
            reason_html,
        ])
    parts.append(_grid_table(
        ["Category", "Score", "", "Indicators"], rows,
        widths=["90", "52", "70", None]
    ))
    return ''.join(parts)


def _vt_file_html(vt):
    if not vt:
        return ''
    if vt['status'] == 'skipped':
        return '<p class="small muted">VirusTotal: %s</p>' % _fmt(vt['message'])
    if vt['status'] == 'not_found':
        return ('<p class="small muted">File not found in the VirusTotal '
                'database. No previous analysis available.</p>')

    positives, total = vt['positives'], vt['total']
    color = SEVERITY_COLORS['high'] if positives else SEVERITY_COLORS['low']
    parts = ['<p>VirusTotal detection rate: <font color="%s"><b>%d / %d '
             '(%.1f%%)</b></font></p>'
             % (color, positives, total,
                (positives / total * 100) if total else 0.0)]
    if vt.get('detections'):
        rows = [['%s' % _fmt(scanner, 80), '%s' % _fmt(result, 200)]
                for scanner, result in vt['detections']]
        parts.append(_grid_table(["Engine", "Detection"], rows,
                                 widths=["120", None]))
    if vt.get('scan_date'):
        parts.append('<p class="small muted">Last scan: %s UTC</p>'
                     % _esc(vt['scan_date']))
    return ''.join(parts)


def _section_hashes(hashes, vt_file, vt_enabled):
    if not hashes:
        return _empty("Hash calculation not available.")
    rows = [(hash_type, '<span class="mono">%s</span>' % _fmt(value))
            for hash_type, value in hashes.items()]
    out = _kv_table(rows)
    if vt_enabled:
        out += '<h3>VirusTotal File Reputation</h3>'
        out += _vt_file_html(vt_file) or _empty("No VirusTotal result.")
    return out


def _vt_url_html(vt):
    if not vt:
        return '<span class="empty">&mdash;</span>'
    if vt['status'] == 'skipped':
        return '<span class="small muted">%s</span>' % _fmt(vt['message'])
    if vt['status'] == 'error':
        return ('<span class="small muted">VirusTotal API call failed.</span>')
    if vt['status'] == 'pending':
        return ('<span class="small muted">Analysis still pending at report '
                'time.</span>')
    if vt['status'] == 'not_found':
        return '<span class="small muted">Not found in VirusTotal.</span>'

    stats = vt['stats']
    flagged = stats.get('malicious', 0) + stats.get('suspicious', 0)
    color = SEVERITY_COLORS['high'] if flagged else SEVERITY_COLORS['low']
    out = ('<span class="small"><font color="%s"><b>%d flagged</b></font> '
           '(malicious %d, suspicious %d, harmless %d, undetected %d)</span>'
           % (color, flagged, stats.get('malicious', 0),
              stats.get('suspicious', 0), stats.get('harmless', 0),
              stats.get('undetected', 0)))
    if vt.get('scan_date'):
        out += ('<br/><span class="small muted">Last scan: %s UTC</span>'
                % _esc(vt['scan_date']))
    return out


def _section_links(links, vt_enabled):
    if not links:
        return _empty("No links found in the PDF.")
    parts = ['<p>%d link(s) found in the document.</p>' % len(links)]
    if vt_enabled:
        rows = [[str(i), '<span class="mono">%s</span>' % _fmt(l['display']),
                 _vt_url_html(l.get('vt'))]
                for i, l in enumerate(links, 1)]
        parts.append(_grid_table(["#", "URL", "VirusTotal"], rows,
                                 widths=["18", None, "170"]))
    else:
        rows = [[str(i), '<span class="mono">%s</span>' % _fmt(l['display'])]
                for i, l in enumerate(links, 1)]
        parts.append(_grid_table(["#", "URL"], rows, widths=["18", None]))
    return ''.join(parts)


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
                '<p><b>%d.</b> %s &nbsp;<span class="muted">(%s)</span></p>'
                % (i, _fmt(source.get('source', 'Unknown'), 120),
                   _fmt(source.get('location', 'Unknown'), 200))
            )
            content = source.get('content', '')
            if content:
                truncated = len(str(content)) > MAX_JS_CONTENT_LENGTH
                parts.append('<div class="codeblock">%s%s</div>' % (
                    _fmt(content, MAX_JS_CONTENT_LENGTH).replace('\n', '<br/>'),
                    '<br/><i>[Content truncated...]</i>' if truncated else ''
                ))

    if js.get('suspicious_patterns'):
        parts.append('<h3>Suspicious Patterns</h3>')
        rows = [[_severity_html(p.get('severity', 'Unknown')),
                 _fmt(p.get('type', 'Unknown'), 120),
                 '<span class="mono">%s</span>' % _fmt(p.get('pattern', ''), 200),
                 '<span class="small">%s</span>'
                 % _fmt(p.get('location', 'Unknown'), 160)]
                for p in js['suspicious_patterns']]
        parts.append(_grid_table(["Severity", "Type", "Pattern", "Location"],
                                 rows, widths=["50", "110", None, "120"]))
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
                ("Filename", '<span class="mono">%s</span>'
                 % _fmt(entry['filename'], 200)),
                ("Size", _esc("%s bytes" % entry['size'])),
                ("Risk", _severity_html(entry['risk'])),
                ("Source", _fmt(entry['source'], 200)),
            ]
            if entry.get('content_type'):
                rows.append(("Content type", _fmt(entry['content_type'], 120)))
            sha256 = entry['hashes'].get('SHA-256')
            if sha256:
                rows.append(("SHA-256", '<span class="mono">%s</span>'
                             % _fmt(sha256)))
            if entry.get('risk_reasons'):
                rows.append(("Warnings", '<br/>'.join(
                    _fmt(reason) for reason in entry['risk_reasons'])))
            parts.append('<p><b>File %d</b></p>' % i)
            parts.append(_kv_table(rows))

    if embedded['hidden_streams']:
        parts.append('<h3>Hidden Streams</h3>')
        rows = []
        for stream in embedded['hidden_streams']:
            sha256 = stream['hashes'].get('SHA-256', '')
            rows.append([
                _esc(stream['xref']),
                _esc("%s bytes" % stream['size']),
                _severity_html(stream['risk']),
                '<span class="mono">%s</span>' % _fmt(sha256),
            ])
        parts.append(_grid_table(["XRef", "Size", "Risk", "SHA-256"], rows,
                                 widths=["40", "60", "50", None]))
    return ''.join(parts)


def _section_structure(structure):
    if not structure:
        return _empty("Structure analysis not available.")
    parts = ['<p>Anomalies detected: <b>%d</b></p>'
             % structure['anomaly_count']]
    if structure['anomalies']:
        rows = []
        for anomaly in structure['anomalies']:
            description = _fmt(anomaly['description'])
            if anomaly.get('locations'):
                description += ('<br/><span class="small muted">Locations: '
                                '%s</span>'
                                % _fmt(", ".join(anomaly['locations']), 300))
            rows.append([
                _severity_html(anomaly['severity']),
                _fmt(anomaly['type'], 120),
                _esc(anomaly.get('count', 1)),
                description,
            ])
        parts.append(_grid_table(["Severity", "Type", "Count", "Description"],
                                 rows, widths=["52", "120", "36", None]))
    return ''.join(parts)


def _section_qr(qr, vt_enabled, unavailable_message):
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
        headers = ["#", "Page", "Type", "Payload"]
        widths = ["18", "30", "40", None]
        if vt_enabled:
            headers.append("VirusTotal")
            widths = ["18", "30", "40", None, "150"]
        rows = []
        for i, qr_code in enumerate(qr['qr_codes'], 1):
            row = [str(i), _esc(qr_code['page']), _esc(qr_code['type']),
                   '<span class="mono">%s</span>'
                   % _fmt(qr_code['display'], 400)]
            if vt_enabled:
                row.append(_vt_url_html(qr_code.get('vt')))
            rows.append(row)
        parts.append(_grid_table(headers, rows, widths=widths))
    return ''.join(parts)


def _section_errors(errors):
    return ''.join('<div class="errbox">%s</div>' % _fmt(error)
                   for error in errors)


def build_report_html(data):
    meta = data['meta']

    sections = [
        ("Report Information", _section_report_info(meta)),
        ("Risk Assessment", _section_risk(data.get('risk'))),
        ("File Integrity", _section_hashes(
            data.get('hashes'), data.get('vt_file'), meta['vt_enabled'])),
        ("Document Links", _section_links(
            data.get('links'), meta['vt_enabled'])),
        ("Document Metadata", _section_metadata(data.get('metadata'))),
        ("JavaScript Analysis", _section_javascript(data.get('javascript'))),
        ("Embedded Files", _section_embedded(data.get('embedded'))),
        ("Structural Anomalies", _section_structure(data.get('structure'))),
        ("QR Codes", _section_qr(
            data.get('qr'), meta['vt_enabled'],
            data.get('qr_unavailable_message', ''))),
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

    # NOTE: <pdf:pagenumber> is not rendered by xhtml2pdf inside tables,
    # so the footer must stay a plain div
    footer = (
        '<div id="page_footer">Generated by PDFChecker %s &middot; %s UTC'
        ' &nbsp;&nbsp;&mdash;&nbsp;&nbsp; Page <pdf:pagenumber> of '
        '<pdf:pagecount></div>'
        % (_esc(meta['version']), _esc(meta['timestamp']))
    )

    return (
        '<html><head><meta charset="utf-8"/><style>%s</style></head>'
        '<body>%s%s</body></html>'
        % (CSS, footer, ''.join(body))
    )
