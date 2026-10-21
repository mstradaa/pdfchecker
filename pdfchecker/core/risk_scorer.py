# Risk scoring: combines the findings of the individual analysis modules
# (JavaScript, structure, embedded files, links, QR codes) into a single
# weighted 0-100 score with a per-category breakdown, for fast triage.
import re
from ipaddress import ip_address

from .coverage import finding_errors, print_coverage
from .terminal import safe_text
from .url_discovery import hostname, site_host

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

_RISKY_SCHEME_PATTERN = re.compile(r'^(?:javascript|file|data|vbscript):', re.IGNORECASE)
_RISKY_FILE_EXT_PATTERN = re.compile(
    r'\.(?:exe|scr|js|vbs|bat|cmd|ps1|jar|apk|msi|hta|zip|rar|7z|iso)(?:$|[?#])',
    re.IGNORECASE
)
_SHORTENER_DOMAINS = frozenset([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
    'rebrand.ly', 'cutt.ly', 'rb.gy', 'shorturl.at', 't.ly', 's.id'
])
# Link text naming another site is a phishing hallmark, but redirect and
# tracking services cause it too, so it adds weight without a severity floor
_LINK_MISMATCH_POINTS = 10


def _url_host(url):
    # Scheme-less links ("bit.ly/x") still name a host worth scoring
    candidate = url.strip()
    host = hostname(candidate if '://' in candidate else '//' + candidate)
    return host[4:] if host.startswith('www.') else host


def _score_url(url, reasons, context=""):
    prefix = f"{context}: " if context else ""
    points = 0
    if _RISKY_SCHEME_PATTERN.match(url):
        points += 5
        reasons.append(f"{prefix}risky URL scheme ({url.split(':', 1)[0]}:)")
    host = _url_host(url)
    try:
        ip_address(host)
    except ValueError:
        pass
    else:
        points += 5
        reasons.append(f"{prefix}URL points to a raw IP address")
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
        reasons.append(f"{len(hidden)} hidden embedded stream(s) not listed "
                       "as document attachments")
    return points, reasons


def _score_links(link_findings):
    reasons = []
    if not link_findings:
        return 0, reasons

    points = 0
    for entry in link_findings.get("urls", []):
        points += _score_url(entry["url"], reasons)
        shown = sorted({site_host(label) for source in entry["sources"]
                        if source.get("mismatch")
                        for label in source.get("displayed_urls", [])} - {''})
        if shown:
            points += _LINK_MISMATCH_POINTS
            reasons.append(f"Link text shows {', '.join(shown)} but opens "
                           f"{_url_host(entry['url'])}")
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


def risk_reasons(assessment):
    """Every reason, in category order (most heavily weighted first)."""
    return [reason for category in assessment["categories"].values()
            for reason in category["reasons"]]


def ranking_key(assessment):
    """Sort key putting the riskiest results first and unscored ones last."""
    return -assessment["score"] if assessment else 1


def risk_level(score):
    for threshold, level in RISK_LEVELS:
        if score >= threshold:
            return level
    return "Minimal"


def compute_risk_score(js_findings=None, structure_findings=None,
                       embedded_findings=None, link_findings=None, qr_findings=None):
    errors = [f"{name}: {error}" for name, findings in
              [('JavaScript', js_findings), ('Structure', structure_findings),
               ('Embedded files', embedded_findings), ('Links', link_findings),
               ('QR', qr_findings)]
              for error in finding_errors(findings)]
    if errors:
        raise ValueError("Incomplete analysis: " + "; ".join(errors))
    scorers = {
        "javascript": lambda: _score_javascript(js_findings),
        "structure": lambda: _score_structure(structure_findings),
        "embedded_files": lambda: _score_embedded(embedded_findings),
        "links": lambda: _score_links(link_findings),
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

    if assessment.get('coverage'):
        print_coverage(assessment['coverage'])
    print("\n=== Risk Assessment ===")
    print(f"Overall Risk Score: {assessment['score']}/{assessment['max_score']} "
          f"({assessment['level'].upper()})")

    for adjustment in assessment.get("adjustments", []):
        print(f"NOTE: {adjustment}")

    for name, category in assessment["categories"].items():
        label = name.replace('_', ' ').title()
        print(f"\n{label}: {category['score']}/{category['max']}")
        # Reasons quote document values such as hosts and attachment names
        for reason in category["reasons"][:max_reasons_per_category]:
            print(f"   - {safe_text(reason)}")
        remaining = len(category["reasons"]) - max_reasons_per_category
        if remaining > 0:
            print(f"   ... and {remaining} more indicator(s)")
