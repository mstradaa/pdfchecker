# Risk scoring: combines the findings of the individual analysis modules
# (JavaScript, structure, embedded files, links, QR codes) into a single
# weighted 0-100 score with a per-category breakdown, for fast triage.
import re

CATEGORY_WEIGHTS = {
    "javascript": 30,
    "structure": 25,
    "embedded_files": 20,
    "links": 15,
    "qr_codes": 10,
}

RISK_LEVELS = [
    (80, "Critical"),
    (55, "High"),
    (30, "Medium"),
    (10, "Low"),
    (0, "Minimal"),
]

_STRUCTURE_SEVERITY_POINTS = {
    "Critical": 12,
    "High": 8,
    "Medium": 4,
    "Low": 1,
    "Info": 0,
}

_IP_URL_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://\d{1,3}(?:\.\d{1,3}){3}')
_RISKY_SCHEME_PATTERN = re.compile(r'^(?:javascript|file|data|vbscript):', re.IGNORECASE)
_RISKY_FILE_EXT_PATTERN = re.compile(
    r'\.(?:exe|scr|js|vbs|bat|cmd|ps1|jar|apk|msi|hta|zip|rar|7z|iso)(?:$|[?#])',
    re.IGNORECASE
)
_SHORTENER_DOMAINS = frozenset([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
    'rebrand.ly', 'cutt.ly', 'rb.gy', 'shorturl.at', 't.ly', 's.id'
])


def _url_host(url):
    try:
        without_scheme = url.split('://', 1)[1] if '://' in url else url
        host = without_scheme.split('/', 1)[0].split('?', 1)[0].lower()
        return host[4:] if host.startswith('www.') else host
    except Exception:
        return ""


def _score_url(url, reasons, context=""):
    prefix = f"{context}: " if context else ""
    points = 0
    if _RISKY_SCHEME_PATTERN.match(url):
        points += 5
        reasons.append(f"{prefix}risky URL scheme ({url.split(':', 1)[0]}:)")
    if _IP_URL_PATTERN.match(url):
        points += 5
        reasons.append(f"{prefix}URL points to a raw IP address")
    host = _url_host(url)
    if host in _SHORTENER_DOMAINS:
        points += 3
        reasons.append(f"{prefix}URL uses a link shortener ({host})")
    if host.startswith('xn--') or '.xn--' in host:
        points += 4
        reasons.append(f"{prefix}punycode (potential homoglyph) domain")
    if _RISKY_FILE_EXT_PATTERN.search(url):
        points += 4
        reasons.append(f"{prefix}URL targets a risky file type")
    return points


def _score_javascript(js_findings):
    reasons = []
    if not js_findings or not js_findings.get("has_javascript"):
        return 0, reasons

    points = 8
    reasons.append(f"JavaScript present ({js_findings.get('javascript_count', 0)} object(s))")

    if any(src.get("source") == "Open Action"
           for src in js_findings.get("javascript_sources", [])):
        points += 8
        reasons.append("JavaScript runs automatically when the document opens")

    high = sum(1 for p in js_findings.get("suspicious_patterns", [])
               if p.get("severity") == "High")
    medium = sum(1 for p in js_findings.get("suspicious_patterns", [])
                 if p.get("severity") == "Medium")
    if high:
        points += min(high * 6, 18)
        reasons.append(f"{high} high-severity suspicious pattern(s)")
    if medium:
        points += min(medium * 3, 9)
        reasons.append(f"{medium} medium-severity suspicious pattern(s)")

    return points, reasons


def _score_structure(structure_findings):
    reasons = []
    if not structure_findings:
        return 0, reasons

    points = 0
    for anomaly in structure_findings.get("anomalies", []):
        severity_points = _STRUCTURE_SEVERITY_POINTS.get(anomaly.get("severity"), 0)
        if severity_points:
            # Repeated instances of the same anomaly add weight, capped at
            # double the base points so one noisy type cannot dominate
            count = max(anomaly.get("count", 1), 1)
            points += min(severity_points * count, severity_points * 2)
            reasons.append(f"[{anomaly.get('severity')}] {anomaly.get('type')} "
                           f"(x{anomaly.get('count', 1)})")
    return points, reasons


def _score_embedded(embedded_findings):
    reasons = []
    if not embedded_findings:
        return 0, reasons

    points = 0
    files = embedded_findings.get("embedded_files", [])
    if files:
        points += 5
        reasons.append(f"{len(files)} embedded file(s) present")
    for entry in files:
        if entry.get("risk") == "High":
            points += 8
            reasons.append(f"High-risk attachment: {entry.get('filename')}")
        elif entry.get("risk") == "Medium":
            points += 4
            reasons.append(f"Medium-risk attachment: {entry.get('filename')}")

    hidden = embedded_findings.get("hidden_streams", [])
    if hidden:
        points += 8
        reasons.append(f"{len(hidden)} hidden embedded stream(s) not referenced "
                       "by any file specification")
    return points, reasons


def _score_links(links):
    reasons = []
    if not links:
        return 0, reasons

    points = 0
    for link in links:
        points += _score_url(link, reasons)
    return points, reasons


def _score_qr(qr_findings):
    reasons = []
    if not qr_findings or not qr_findings.get("supported"):
        return 0, reasons

    points = 0
    urls = [qr for qr in qr_findings.get("qr_codes", []) if qr.get("type") == "URL"]
    if qr_findings.get("qr_count"):
        points += 4
        reasons.append(f"{qr_findings['qr_count']} QR code(s) found")
    if urls:
        points += 3
        reasons.append(f"{len(urls)} QR code(s) contain URLs (possible quishing)")
        for qr in urls:
            points += _score_url(qr.get("payload", ""), reasons,
                                 context=f"QR page {qr.get('page')}")
    return points, reasons


def risk_level(score):
    for threshold, level in RISK_LEVELS:
        if score >= threshold:
            return level
    return "Minimal"


def compute_risk_score(js_findings=None, structure_findings=None,
                       embedded_findings=None, links=None, qr_findings=None):
    scorers = {
        "javascript": lambda: _score_javascript(js_findings),
        "structure": lambda: _score_structure(structure_findings),
        "embedded_files": lambda: _score_embedded(embedded_findings),
        "links": lambda: _score_links(links),
        "qr_codes": lambda: _score_qr(qr_findings),
    }

    categories = {}
    total = 0
    for name, scorer in scorers.items():
        raw_points, reasons = scorer()
        weight = CATEGORY_WEIGHTS[name]
        capped = min(raw_points, weight)
        categories[name] = {
            "score": capped,
            "max": weight,
            "reasons": reasons
        }
        total += capped

    # Severity floors: a single decisive indicator (e.g. a Launch action in an
    # otherwise clean file) must not average out to a Low score
    adjustments = []
    floor = 0
    if structure_findings and any(a.get("severity") == "Critical"
                                  for a in structure_findings.get("anomalies", [])):
        floor = max(floor, 55)
        adjustments.append("Critical structural anomaly present: "
                           "minimum score raised to 55 (High)")
    if embedded_findings:
        has_high_risk_payload = (
            any(e.get("risk") == "High"
                for e in embedded_findings.get("embedded_files", []))
            or any(s.get("risk") == "High"
                   for s in embedded_findings.get("hidden_streams", []))
        )
        if has_high_risk_payload:
            floor = max(floor, 40)
            adjustments.append("High-risk embedded payload present: "
                               "minimum score raised to 40 (Medium)")

    max_score = sum(CATEGORY_WEIGHTS.values())
    total = min(max(total, floor), max_score)

    return {
        "score": total,
        "max_score": max_score,
        "level": risk_level(total),
        "categories": categories,
        "adjustments": adjustments
    }


def print_risk_assessment(assessment, max_reasons_per_category=5):
    if not assessment:
        print("No risk assessment available.")
        return

    print("\n=== Risk Assessment ===")
    print(f"Overall Risk Score: {assessment['score']}/{assessment['max_score']} "
          f"({assessment['level'].upper()})")

    for adjustment in assessment.get("adjustments", []):
        print(f"NOTE: {adjustment}")

    for name, category in assessment["categories"].items():
        label = name.replace('_', ' ').title()
        print(f"\n{label}: {category['score']}/{category['max']}")
        for reason in category["reasons"][:max_reasons_per_category]:
            print(f"   - {reason}")
        remaining = len(category["reasons"]) - max_reasons_per_category
        if remaining > 0:
            print(f"   ... and {remaining} more indicator(s)")
