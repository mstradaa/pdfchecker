"""Run several analyzers over one opened document and one parsed object map,
for full scans, reports, risk scoring and indicator export."""
from .coverage import analysis_coverage, finding_errors
from .embedded_file_detector import detect_embedded_files
from .hash_checker import calculate_file_hashes
from .javascript_detector import extract_javascript_from_pdf
from .metadata_analyzer import analyze_pdf_metadata
from .pdf_access import open_pdf, preserved_timestamps
from .qr_detector import detect_qr_codes
from .risk_scorer import compute_risk_score
from .structure_analyzer import analyze_structure
from .url_discovery import discover_urls
from .utils import build_xref_object_cache

# PDFAnalysisResult attributes in execution order (URL discovery reuses the
# JavaScript findings)
ALL_ANALYSES = ('hashes', 'metadata', 'javascript', 'structure', 'embedded', 'qr', 'link_findings')
RISK_ANALYSES = ('javascript', 'structure', 'embedded', 'qr', 'link_findings')


class PDFAnalysisResult:
    def __init__(self):
        self.hashes = None
        self.links = None
        self.link_findings = None
        self.coverage = {}
        self.metadata = None
        self.javascript = None
        self.structure = None
        self.embedded = None
        self.qr = None
        self.risk = None
        self.errors = []


def _analyze(name, path, doc, xref_cache, file_stats, result, include_data):
    if name == 'metadata':
        return analyze_pdf_metadata(path, file_stats=file_stats, doc=doc, xref_cache=xref_cache)
    if name == 'javascript':
        return extract_javascript_from_pdf(path, doc=doc, xref_cache=xref_cache)
    if name == 'structure':
        return analyze_structure(path, doc=doc, xref_cache=xref_cache)
    if name == 'embedded':
        return detect_embedded_files(path, include_data=include_data, doc=doc, xref_cache=xref_cache)
    if name == 'qr':
        return detect_qr_codes(path, doc=doc)
    return discover_urls(path, doc=doc, xref_cache=xref_cache, javascript=result.javascript)


def run_analyses(pdf_path, analyses, include_data=False):
    """Hash the file, then open it once and run `analyses` on the shared
    document. Nothing raises: every failure is listed in result.errors and the
    coverage of each requested check explains it. Timestamps are restored."""
    result = PDFAnalysisResult()
    document_analyses = [name for name in analyses if name != 'hashes']
    with preserved_timestamps(pdf_path) as file_stats:
        if 'hashes' in analyses:
            try:
                result.hashes = calculate_file_hashes(pdf_path)
            except Exception as e:
                result.errors.append(f"Hash calculation error: {str(e)}")

        try:
            doc = open_pdf(pdf_path)
        except Exception as exc:
            result.errors.append(f"PDF open failed: {exc}")
            result.coverage = analysis_coverage(result, analyses)
            for name, check in result.coverage.items():
                if name != 'hashes':
                    check['details'] = [f"PDF could not be opened: {exc}"]
            return result

        with doc:
            try:
                xref_cache = build_xref_object_cache(doc)
            except Exception:
                xref_cache = None
            # Each analysis is isolated so one failure does not lose the rest
            for name in document_analyses:
                try:
                    setattr(result, name, _analyze(name, pdf_path, doc, xref_cache,
                                                   file_stats, result, include_data))
                except Exception as e:
                    result.errors.append(f"{name} analysis error: {str(e)}")

    if 'link_findings' in analyses:
        result.links = [entry['url'] for entry in (result.link_findings or {}).get('urls', [])]
    for name in document_analyses:
        findings = getattr(result, name)
        if findings is None:
            result.errors.append(f"{name}: analysis unavailable")
        else:
            result.errors.extend(f"{name}: {error}" for error in finding_errors(findings))
    result.coverage = analysis_coverage(result, analyses)
    return result


def _score(result):
    return compute_risk_score(
        js_findings=result.javascript, structure_findings=result.structure,
        embedded_findings=result.embedded, link_findings=result.link_findings,
        qr_findings=result.qr)


def analyze_pdf_once(pdf_path, include_data=False):
    """Every analysis, for reports and full scans. The risk score is left out
    unless all of them completed, including every page of the QR scan."""
    result = run_analyses(pdf_path, ALL_ANALYSES, include_data)
    if (result.qr or {}).get('pages_skipped'):
        result.errors.append(f"QR: {result.qr['pages_skipped']} pages were not scanned")
    if not result.errors:
        result.risk = _score(result)
    return result


def analyze_pdf_for_risk(pdf_path):
    """Risk score plus the coverage of the scored checks; raises when any of
    them is incomplete rather than scoring a partial analysis."""
    result = run_analyses(pdf_path, RISK_ANALYSES)
    if result.errors:
        raise ValueError("Incomplete analysis: " + "; ".join(result.errors))
    return dict(_score(result), coverage=result.coverage)
