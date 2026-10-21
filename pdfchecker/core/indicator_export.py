"""Export PDF indicators as native JSON or a STIX 2.1 bundle."""
import base64
import contextlib
import hashlib
import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

from . import bulk_processor
from .coverage import finding_errors
from .json_output import tool_info
from .pdf_access import validate_pdf
from .pipeline import run_analyses
from .url_discovery import hostname
from .utils import TRUNCATION_MARKER


SCHEMA_VERSION = 1
STIX_SPEC_VERSION = "2.1"
INDICATOR_ANALYSES = ('javascript', 'qr', 'link_findings')


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z")


def _source(**values):
    return {key: value for key, value in values.items() if value is not None}


def _normalized_domain(url):
    """Return a lower-case IDNA hostname for a URL, excluding IP addresses."""
    host = hostname(url)
    if not host or any(character.isspace() for character in host):
        return None
    try:
        ip_address(host)
    except ValueError:
        return host
    return None


def collect_pdf_indicators(pdf_path):
    """Collect link/QR URLs and JavaScript while opening the PDF only once."""
    path = str(pdf_path)
    analysis = run_analyses(path, INDICATOR_ANALYSES)
    if all(getattr(analysis, name) is None for name in INDICATOR_ANALYSES):
        # Nothing could be inspected, e.g. an unreadable or locked PDF
        raise ValueError("; ".join(analysis.errors))
    result = {"path": path, "urls": [], "javascript": [], "warnings": []}

    javascript = analysis.javascript or {}
    result["warnings"].extend(javascript.get("extraction_errors", []))
    for source in javascript.get("javascript_sources", []):
        value = source.get("full_content") or source.get("content")
        if not value:
            continue
        result["javascript"].append({
            "value": value,
            "truncated": value.endswith(TRUNCATION_MARKER),
            "source": _source(
                path=path, origin="javascript",
                source=source.get("source"),
                location=source.get("location")),
        })

    links = analysis.link_findings or {}
    result['warnings'].extend(links.get('errors', []) + links.get('limits', []))
    for entry in links.get('urls', []):
        for source in entry['sources']:
            result['urls'].append({'value': entry['url'], 'source': dict(source, path=path)})

    qr = analysis.qr or {}
    for finding in qr.get("qr_codes", []):
        if finding.get("type") != "URL" or not finding.get("payload"):
            continue
        result["urls"].append({
            "value": finding["payload"],
            "source": _source(
                path=path, origin="qr-code", page=finding.get("page")),
        })
    result["warnings"].extend(finding_errors(qr))
    return result


def _append_unique(index, value, source, **extra):
    entry = index.get(value)
    if entry is None:
        entry = {"value": value, **extra, "sources": []}
        index[value] = entry
    if source not in entry["sources"]:
        entry["sources"].append(source)


def build_json_export(target, file_results, failures=None, generated_at=None):
    """Merge per-file findings into the versioned native export schema."""
    failures = failures or []
    url_index = {}
    domain_index = {}
    javascript_index = {}
    warnings = []

    for result in file_results:
        warnings.extend(
            {"path": result["path"], "message": message}
            for message in result.get("warnings", [])
        )
        for finding in result.get("urls", []):
            value = finding["value"]
            source = finding["source"]
            _append_unique(url_index, value, source)
            domain = _normalized_domain(value)
            if domain:
                domain_source = dict(source, url=value)
                _append_unique(domain_index, domain, domain_source)
        for finding in result.get("javascript", []):
            value = finding["value"]
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
            _append_unique(
                javascript_index, value, finding["source"],
                sha256=digest, truncated=bool(finding.get("truncated")))

    indicators = {
        "urls": list(url_index.values()),
        "domains": list(domain_index.values()),
        "javascript": list(javascript_index.values()),
    }
    target_path = Path(target)
    return {
        "schema_version": SCHEMA_VERSION,
        "type": "pdfchecker-indicator-export",
        "tool": tool_info(),
        "generated_at": generated_at or _utc_now(),
        "target": str(target),
        "target_type": "directory" if target_path.is_dir() else "file",
        "summary": {
            "files_scanned": len(file_results),
            "files_failed": len(failures),
            "urls": len(indicators["urls"]),
            "domains": len(indicators["domains"]),
            "javascript": len(indicators["javascript"]),
        },
        "indicators": indicators,
        "warnings": warnings,
        "errors": failures,
    }


def _stix_escape(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _safe_stix_string(value):
    # STIX string literals only define escapes for apostrophes and backslashes.
    # Use a binary Artifact pattern for values containing raw control characters.
    return not any(ord(character) < 0x20 or ord(character) == 0x7f
                   for character in value)


def _stix_indicator(name, pattern, labels, sources, created_at, **custom):
    indicator = {
        "type": "indicator",
        "spec_version": STIX_SPEC_VERSION,
        "id": f"indicator--{uuid.uuid4()}",
        "created": created_at,
        "modified": created_at,
        "name": name,
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": STIX_SPEC_VERSION,
        "valid_from": created_at,
        "labels": labels,
        "x_pdfchecker_sources": sources,
    }
    indicator.update(custom)
    return indicator


def build_stix_export(native_export):
    """Convert a native indicator document to a self-contained STIX bundle."""
    created_at = native_export["generated_at"]
    objects = []
    for entry in native_export["indicators"]["urls"]:
        if _safe_stix_string(entry["value"]):
            pattern = f"[url:value = '{_stix_escape(entry['value'])}']"
            custom = {}
        else:
            payload = base64.b64encode(
                entry["value"].encode("utf-8")).decode("ascii")
            pattern = f"[artifact:payload_bin = b'{payload}']"
            custom = {"x_pdfchecker_observable_type": "url"}
        objects.append(_stix_indicator(
            f"PDF URL: {entry['value']}",
            pattern,
            ["pdf", "url"], entry["sources"], created_at,
            **custom,
        ))
    for entry in native_export["indicators"]["domains"]:
        objects.append(_stix_indicator(
            f"PDF domain: {entry['value']}",
            f"[domain-name:value = '{_stix_escape(entry['value'])}']",
            ["pdf", "domain"], entry["sources"], created_at,
        ))
    for entry in native_export["indicators"]["javascript"]:
        payload = base64.b64encode(entry["value"].encode("utf-8")).decode("ascii")
        objects.append(_stix_indicator(
            f"PDF JavaScript: {entry['sha256'][:12]}",
            f"[artifact:payload_bin = b'{payload}']",
            ["pdf", "javascript"], entry["sources"], created_at,
            x_pdfchecker_sha256=entry["sha256"],
            x_pdfchecker_truncated=entry["truncated"],
        ))
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def _collect_target(target):
    target_path = Path(target)
    if target_path.is_dir():
        try:
            files, skipped = bulk_processor.discover_pdfs(target)
        except OSError as exc:
            return [], [{"path": str(target), "message": str(exc)}]
        failures = [
            {"path": str(Path(target) / name), "message": reason}
            for name, reason in skipped
        ]
        if not files:
            return [], failures
        with contextlib.redirect_stdout(sys.stderr):
            results = bulk_processor._run_parallel(
                files, collect_pdf_indicators, use_processes=True)
        collected = []
        for path in files:
            ok, payload = results[path]
            if ok:
                collected.append(payload)
            else:
                failures.append({"path": path, "message": str(payload)})
        return collected, failures

    error = validate_pdf(target)
    if error:
        return [], [{"path": str(target), "message": error}]
    try:
        return [collect_pdf_indicators(target)], []
    except Exception as exc:
        return [], [{"path": str(target), "message": str(exc) or type(exc).__name__}]


def _write_atomic(output_path, text):
    destination = Path(output_path)
    if not destination.parent.exists():
        raise OSError(f"Output directory does not exist: {destination.parent}")
    if destination.exists() and destination.is_dir():
        raise OSError(f"Output path is a directory: {destination}")
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=str(destination.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(text)
            output.write("\n")
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def run_indicator_export(target, output_format="json", output_path=None):
    """CLI entry point. Return 0 on success and 1 on a hard/total failure."""
    if output_format not in ("json", "stix"):
        print(f"Unsupported indicator format: {output_format}", file=sys.stderr)
        return 1
    if output_path:
        destination = Path(output_path)
        source = Path(target)
        inputs = list(source.glob('*')) if source.is_dir() else [source]
        for candidate in inputs:
            if source.is_dir() and candidate.suffix.lower() != '.pdf':
                continue
            if (candidate.resolve() == destination.resolve() or
                    (candidate.exists() and destination.exists() and
                     os.path.samefile(candidate, destination))):
                print("Output would overwrite an input PDF", file=sys.stderr)
                return 1
    collected, failures = _collect_target(target)
    native = build_json_export(target, collected, failures)
    document = build_stix_export(native) if output_format == "stix" else native
    serialized = json.dumps(document, indent=2, ensure_ascii=False)

    try:
        if output_path:
            _write_atomic(output_path, serialized)
        else:
            print(serialized)
    except OSError as exc:
        print(f"Error writing indicator export: {exc}", file=sys.stderr)
        return 1
    if output_format == "stix":
        for failure in failures:
            print(f"Indicator export error ({failure['path']}): "
                  f"{failure['message']}", file=sys.stderr)
    return 0 if collected or not failures else 1
